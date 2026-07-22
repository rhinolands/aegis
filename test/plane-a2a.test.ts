import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createServer, type Server, type IncomingMessage } from 'node:http';
import { getDb } from '../src/db/client.js';
import { loadConfig } from '../src/config.js';
import { loadPolicy, type PolicyEngine } from '../src/policy/opa.js';
import { registerAgent } from '../src/identity/registry.js';
import { putCredential } from '../src/credentials/store.js';
import { seedBudget } from '../src/guard/budget.js';
import { buildServer } from '../src/server.js';

const cfg = loadConfig(process.env);
let engine: PolicyEngine;
beforeAll(async () => { engine = await loadPolicy('dist/policy.wasm'); });

// Ephemeral peer: records every request it receives (headers + body) and
// responds 200 JSON. This is the real assertion surface for the peer-
// allowlist and destination-mediation properties — no [200,403] shrug on an
// unreachable host.
interface RecordedRequest { headers: IncomingMessage['headers']; body: unknown }

function startPeer(): Promise<{ server: Server; port: number; requests: RecordedRequest[] }> {
  const requests: RecordedRequest[] = [];
  return new Promise((resolve) => {
    const server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf8');
        let body: unknown = {};
        try { body = raw ? JSON.parse(raw) : {}; } catch { body = raw; }
        requests.push({ headers: req.headers, body });
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
      });
    });
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      resolve({ server, port, requests });
    });
  });
}

describe('POST /a2a/:peer', () => {
  let peer: Awaited<ReturnType<typeof startPeer>>;

  beforeAll(async () => { peer = await startPeer(); });
  afterAll(async () => { await new Promise((r) => peer.server.close(r)); });

  it('allows an allowlisted peer, calls the operator-registered destination, and carries x-on-behalf-of', async () => {
    const { db, sql } = getDb(cfg);
    try {
      const name = `a2a-${Date.now()}`;
      const { agent, apiKey } = await registerAgent(db, { name, tenant: 'test', allowedPeers: ['agent-b'] });
      await seedBudget(db, agent.id, 1_000_000, 1_000_000);
      // The peer destination is registered by the operator alongside the
      // credential — never supplied by the caller in the request body.
      await putCredential(db, cfg, agent.id, 'a2a:agent-b', 'unused-secret', `http://127.0.0.1:${peer.port}/inbox`);
      const app = buildServer({ cfg, db, engine });

      const before = peer.requests.length;
      const res = await app.inject({
        method: 'POST',
        url: '/a2a/agent-b',
        headers: { 'x-api-key': apiKey },
        payload: { operation: 'ping', args: { hello: 'world' } },
      });

      expect(res.statusCode).toBe(200);
      expect(peer.requests.length).toBe(before + 1);
      const received = peer.requests[peer.requests.length - 1];
      expect(received.headers['x-on-behalf-of']).toBe(name);
      expect(received.body).toEqual({ operation: 'ping', args: { hello: 'world' } });

      await app.close();
    } finally {
      await sql.end();
    }
  });

  it('denies a call to a non-allowlisted peer with 403 and makes zero peer requests', async () => {
    const { db, sql } = getDb(cfg);
    try {
      const { agent, apiKey } = await registerAgent(db, { name: `a2a-deny-${Date.now()}`, tenant: 'test', allowedPeers: ['agent-b'] });
      await seedBudget(db, agent.id, 1_000_000, 1_000_000);
      // Even though a destination IS registered for agent-c, the policy must
      // deny before execute() ever runs because agent-c is not allowlisted.
      await putCredential(db, cfg, agent.id, 'a2a:agent-c', 'unused-secret', `http://127.0.0.1:${peer.port}/inbox`);
      const app = buildServer({ cfg, db, engine });

      const before = peer.requests.length;
      const res = await app.inject({
        method: 'POST',
        url: '/a2a/agent-c',
        headers: { 'x-api-key': apiKey },
        payload: { operation: 'ping', args: {} },
      });

      expect(res.statusCode).toBe(403);
      expect(peer.requests.length).toBe(before);

      await app.close();
    } finally {
      await sql.end();
    }
  });

  it('SECURITY: ignores a caller-supplied upstreamUrl and never contacts the attacker-controlled server', async () => {
    const { db, sql } = getDb(cfg);
    let attacker: Awaited<ReturnType<typeof startPeer>> | undefined;
    try {
      attacker = await startPeer();
      const { agent, apiKey } = await registerAgent(db, { name: `a2a-exfil-${Date.now()}`, tenant: 'test', allowedPeers: ['agent-b'] });
      await seedBudget(db, agent.id, 1_000_000, 1_000_000);
      // Register the credential/destination against the LEGITIMATE peer only.
      await putCredential(db, cfg, agent.id, 'a2a:agent-b', 'unused-secret', `http://127.0.0.1:${peer.port}/inbox`);
      const app = buildServer({ cfg, db, engine });

      const beforeLegit = peer.requests.length;
      const beforeAttacker = attacker.requests.length;
      const res = await app.inject({
        method: 'POST',
        url: '/a2a/agent-b',
        headers: { 'x-api-key': apiKey },
        // Attacker-controlled agent still tries to redirect the mediated call.
        payload: { operation: 'ping', args: {}, upstreamUrl: `http://127.0.0.1:${attacker.port}/inbox` },
      });

      expect(res.statusCode).toBe(200);
      // The attacker server must receive ZERO requests — this is the whole
      // point of resolving the peer destination server-side.
      expect(attacker.requests.length).toBe(beforeAttacker);
      // The legitimate, operator-registered peer received exactly one request.
      expect(peer.requests.length).toBe(beforeLegit + 1);

      await app.close();
    } finally {
      await sql.end();
      if (attacker) await new Promise((r) => attacker!.server.close(r));
    }
  });

  it('denies an allowlisted peer with no registered destination with 403 and makes zero peer requests', async () => {
    const { db, sql } = getDb(cfg);
    try {
      const { agent, apiKey } = await registerAgent(db, { name: `a2a-notarget-${Date.now()}`, tenant: 'test', allowedPeers: ['agent-b'] });
      await seedBudget(db, agent.id, 1_000_000, 1_000_000);
      // No putCredential call at all — no registered destination for a2a:agent-b.
      const app = buildServer({ cfg, db, engine });

      const before = peer.requests.length;
      const res = await app.inject({
        method: 'POST',
        url: '/a2a/agent-b',
        headers: { 'x-api-key': apiKey },
        payload: { operation: 'ping', args: {} },
      });

      expect(res.statusCode).toBe(403);
      expect(peer.requests.length).toBe(before);

      await app.close();
    } finally {
      await sql.end();
    }
  });

  it('rejects an unauthenticated request with 403 and makes zero peer requests', async () => {
    const { db, sql } = getDb(cfg);
    try {
      const app = buildServer({ cfg, db, engine });
      const before = peer.requests.length;
      const res = await app.inject({
        method: 'POST',
        url: '/a2a/agent-b',
        payload: { operation: 'ping', args: {} },
      });
      expect(res.statusCode).toBe(403);
      expect(peer.requests.length).toBe(before);
      await app.close();
    } finally {
      await sql.end();
    }
  });
});
