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

  it('allows a whitelisted tool, calls upstream, and injects the scoped credential the caller never held', async () => {
    const { db, sql } = getDb(cfg);
    try {
      const { agent, apiKey } = await registerAgent(db, { name: `mcp-${Date.now()}`, tenant: 'test', allowedTools: ['echo'] });
      await seedBudget(db, agent.id, 1_000_000, 1_000_000);
      await putCredential(db, cfg, agent.id, 'mcp:echo', 'backend-token-xyz');
      const app = buildServer({ cfg, db, engine });

      const before = upstream.requests.length;
      const res = await app.inject({
        method: 'POST',
        url: '/mcp/echo',
        headers: { 'x-api-key': apiKey },
        payload: { operation: 'call', args: { msg: 'hi' }, upstreamUrl: `http://127.0.0.1:${upstream.port}/tool` },
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
        payload: { operation: 'call', args: {}, upstreamUrl: `http://127.0.0.1:${upstream.port}/tool` },
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
        payload: { operation: 'call', args: {}, upstreamUrl: `http://127.0.0.1:${upstream.port}/tool` },
      });
      expect(res.statusCode).toBe(403);
      expect(upstream.requests.length).toBe(before);
      await app.close();
    } finally {
      await sql.end();
    }
  });
});
