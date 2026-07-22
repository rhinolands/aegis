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

// Ephemeral upstream: records every request it receives (headers + body) and
// responds 200 JSON. This is the real assertion surface for the
// credential-injection and deny-short-circuit properties — no [200,403]
// shrug on an unreachable host.
interface RecordedRequest { headers: IncomingMessage['headers']; body: unknown }

function startUpstream(): Promise<{ server: Server; port: number; requests: RecordedRequest[] }> {
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

describe('POST /mcp/:tool', () => {
  let upstream: Awaited<ReturnType<typeof startUpstream>>;

  beforeAll(async () => { upstream = await startUpstream(); });
  afterAll(async () => { await new Promise((r) => upstream.server.close(r)); });

  it('allows a whitelisted tool, calls the operator-registered upstream, and injects the scoped credential the caller never held', async () => {
    const { db, sql } = getDb(cfg);
    try {
      const { agent, apiKey } = await registerAgent(db, { name: `mcp-${Date.now()}`, tenant: 'test', allowedTools: ['echo'] });
      await seedBudget(db, agent.id, 1_000_000, 1_000_000);
      // The upstream destination is registered by the operator alongside the
      // credential — never supplied by the caller in the request body.
      await putCredential(db, cfg, agent.id, 'mcp:echo', 'backend-token-xyz', `http://127.0.0.1:${upstream.port}/tool`);
      const app = buildServer({ cfg, db, engine });

      const before = upstream.requests.length;
      const res = await app.inject({
        method: 'POST',
        url: '/mcp/echo',
        headers: { 'x-api-key': apiKey },
        payload: { operation: 'call', args: { msg: 'hi' } },
      });

      expect(res.statusCode).toBe(200);
      expect(upstream.requests.length).toBe(before + 1);
      const received = upstream.requests[upstream.requests.length - 1];
      // The gateway injected the backend secret; the caller only ever
      // presented its own api key and never possessed this value.
      expect(received.headers['authorization']).toBe('Bearer backend-token-xyz');
      expect(received.body).toEqual({ operation: 'call', args: { msg: 'hi' } });

      await app.close();
    } finally {
      await sql.end();
    }
  });

  it('SECURITY: ignores a caller-supplied upstreamUrl and never contacts the attacker-controlled server', async () => {
    const { db, sql } = getDb(cfg);
    let attacker: Awaited<ReturnType<typeof startUpstream>> | undefined;
    try {
      attacker = await startUpstream();
      const { agent, apiKey } = await registerAgent(db, { name: `mcp-exfil-${Date.now()}`, tenant: 'test', allowedTools: ['echo'] });
      await seedBudget(db, agent.id, 1_000_000, 1_000_000);
      // Register the credential against the LEGITIMATE upstream only.
      await putCredential(db, cfg, agent.id, 'mcp:echo', 'backend-token-xyz', `http://127.0.0.1:${upstream.port}/tool`);
      const app = buildServer({ cfg, db, engine });

      const beforeLegit = upstream.requests.length;
      const beforeAttacker = attacker.requests.length;
      const res = await app.inject({
        method: 'POST',
        url: '/mcp/echo',
        headers: { 'x-api-key': apiKey },
        // Attacker-controlled agent still tries to redirect the credential.
        payload: { operation: 'call', args: { msg: 'hi' }, upstreamUrl: `http://127.0.0.1:${attacker.port}/tool` },
      });

      expect(res.statusCode).toBe(200);
      // The attacker server must receive ZERO requests — this is the whole
      // point of resolving the destination server-side.
      expect(attacker.requests.length).toBe(beforeAttacker);
      // The legitimate, operator-registered upstream received exactly one
      // request, with the scoped credential attached.
      expect(upstream.requests.length).toBe(beforeLegit + 1);
      const received = upstream.requests[upstream.requests.length - 1];
      expect(received.headers['authorization']).toBe('Bearer backend-token-xyz');

      await app.close();
    } finally {
      await sql.end();
      if (attacker) await new Promise((r) => attacker!.server.close(r));
    }
  });

  it('SECURITY: does not follow a redirect from the registered upstream and makes zero requests to the redirect target', async () => {
    const { db, sql } = getDb(cfg);
    let attacker: Awaited<ReturnType<typeof startUpstream>> | undefined;
    let redirector: Server | undefined;
    try {
      attacker = await startUpstream();
      // Ephemeral "registered" upstream that always responds 302 pointing at
      // the attacker server — simulating a compromised registered upstream
      // trying to hop the mediated call (and its injected credential) to a
      // host the operator never authorized.
      const redirectorPort: number = await new Promise((resolve) => {
        const server = createServer((_req, res) => {
          res.writeHead(302, { location: `http://127.0.0.1:${attacker!.port}/tool` });
          res.end();
        });
        redirector = server;
        server.listen(0, '127.0.0.1', () => {
          const addr = server.address();
          resolve(typeof addr === 'object' && addr ? addr.port : 0);
        });
      });

      const { agent, apiKey } = await registerAgent(db, { name: `mcp-redirect-${Date.now()}`, tenant: 'test', allowedTools: ['echo'] });
      await seedBudget(db, agent.id, 1_000_000, 1_000_000);
      // Register the credential against the redirecting upstream.
      await putCredential(db, cfg, agent.id, 'mcp:echo', 'backend-token-xyz', `http://127.0.0.1:${redirectorPort}/tool`);
      const app = buildServer({ cfg, db, engine });

      const beforeAttacker = attacker.requests.length;
      const res = await app.inject({
        method: 'POST',
        url: '/mcp/echo',
        headers: { 'x-api-key': apiKey },
        payload: { operation: 'call', args: { msg: 'hi' } },
      });

      // Fail-closed: the redirect must be treated as an upstream failure, not
      // silently followed.
      expect(res.statusCode).toBe(403);
      // The attacker server must receive ZERO requests — this locks the
      // behaviour in our own code (redirect: 'manual' + explicit rejection)
      // rather than relying on undici's incidental Authorization-stripping.
      expect(attacker.requests.length).toBe(beforeAttacker);

      await app.close();
    } finally {
      await sql.end();
      if (attacker) await new Promise((r) => attacker!.server.close(r));
      if (redirector) await new Promise((r) => redirector!.close(r));
    }
  });

  it('denies an allowlisted tool with no registered credential/target with 403 and makes zero upstream requests', async () => {
    const { db, sql } = getDb(cfg);
    try {
      const { agent, apiKey } = await registerAgent(db, { name: `mcp-notarget-${Date.now()}`, tenant: 'test', allowedTools: ['echo'] });
      await seedBudget(db, agent.id, 1_000_000, 1_000_000);
      // No putCredential call at all — no registered target for mcp:echo.
      const app = buildServer({ cfg, db, engine });

      const before = upstream.requests.length;
      const res = await app.inject({
        method: 'POST',
        url: '/mcp/echo',
        headers: { 'x-api-key': apiKey },
        payload: { operation: 'call', args: {} },
      });

      expect(res.statusCode).toBe(403);
      expect(upstream.requests.length).toBe(before);

      await app.close();
    } finally {
      await sql.end();
    }
  });

  it('denies a non-whitelisted tool with 403 and makes zero upstream requests', async () => {
    const { db, sql } = getDb(cfg);
    try {
      const { agent, apiKey } = await registerAgent(db, { name: `mcp2-${Date.now()}`, tenant: 'test', allowedTools: ['echo'] });
      await seedBudget(db, agent.id, 1_000_000, 1_000_000);
      const app = buildServer({ cfg, db, engine });

      const before = upstream.requests.length;
      const res = await app.inject({
        method: 'POST',
        url: '/mcp/danger',
        headers: { 'x-api-key': apiKey },
        payload: { operation: 'call', args: {} },
      });

      expect(res.statusCode).toBe(403);
      // Deny must short-circuit BEFORE any upstream contact — this is the
      // property the brief's [200,403]-on-unreachable-host test could not prove.
      expect(upstream.requests.length).toBe(before);

      await app.close();
    } finally {
      await sql.end();
    }
  });

  it('rejects an unauthenticated request with 403 and makes zero upstream requests', async () => {
    const { db, sql } = getDb(cfg);
    try {
      const app = buildServer({ cfg, db, engine });
      const before = upstream.requests.length;
      const res = await app.inject({
        method: 'POST',
        url: '/mcp/echo',
        payload: { operation: 'call', args: {} },
      });
      expect(res.statusCode).toBe(403);
      expect(upstream.requests.length).toBe(before);
      await app.close();
    } finally {
      await sql.end();
    }
  });
});
