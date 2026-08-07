import { describe, it, expect, beforeAll } from 'vitest';
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

// The model under test must have a MODEL_PRICES entry so metering is exercised
// rather than falling through the unpriced path.
const MODEL = 'claude-sonnet-4-6';

interface RecordedRequest {
  method: string | undefined;
  url: string | undefined;
  headers: IncomingMessage['headers'];
  raw: string;
  body: unknown;
}

interface UpstreamOptions {
  /** Status the fake Anthropic returns. Default 200. */
  status?: number;
  /** Extra response headers. */
  headers?: Record<string, string>;
  /** Exact response bytes. Overrides `usage`. */
  body?: string;
  /** Convenience: respond `{"ok":true,"usage":{...}}`. */
  usage?: Record<string, unknown>;
}

/**
 * Ephemeral upstream that records every request it receives (method, url,
 * headers, raw bytes) and answers with a caller-chosen status/body. The
 * analog in test/plane-llm.test.ts always answers 200 JSON; the status-relay
 * proofs below need 400/401/429/500 and a non-JSON body, so the harness is
 * widened here.
 */
function startUpstream(opts: UpstreamOptions = {}): Promise<{ server: Server; port: number; requests: RecordedRequest[] }> {
  const requests: RecordedRequest[] = [];
  return new Promise((resolve) => {
    const server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf8');
        let body: unknown = {};
        try { body = raw ? JSON.parse(raw) : {}; } catch { body = raw; }
        requests.push({ method: req.method, url: req.url, headers: req.headers, raw, body });
        const payload = opts.body ?? JSON.stringify({ ok: true, ...(opts.usage ? { usage: opts.usage } : {}) });
        res.writeHead(opts.status ?? 200, { 'content-type': 'application/json', ...(opts.headers ?? {}) });
        res.end(payload);
      });
    });
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      resolve({ server, port, requests });
    });
  });
}

describe('POST /v1/messages (G1 anthropic-compat raw route)', () => {
  it('relays an allowed request to the registered upstream and returns its body byte-for-byte', async () => {
    const { db, sql } = getDb(cfg);
    const upstream = await startUpstream({ usage: { input_tokens: 40, output_tokens: 60 } });
    try {
      const { agent, apiKey } = await registerAgent(db, { name: `llmraw-${Date.now()}`, tenant: 'test', allowedModels: [MODEL] });
      await seedBudget(db, agent.id, 1_000_000, 1_000_000);
      // The operator registers a bare ORIGIN — the raw route appends /v1/messages itself.
      await putCredential(db, cfg, agent.id, 'llm:anthropic', 'anthropic-key-xyz', `http://127.0.0.1:${upstream.port}`);
      const app = buildServer({ cfg, db, engine });

      const payload = { model: MODEL, max_tokens: 16, messages: [{ role: 'user', content: 'hi' }] };
      const res = await app.inject({
        method: 'POST',
        url: '/v1/messages',
        headers: { 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' },
        payload,
      });

      expect(res.statusCode).toBe(200);
      expect(res.body).toBe(JSON.stringify({ ok: true, usage: { input_tokens: 40, output_tokens: 60 } }));
      expect(upstream.requests.length).toBe(1);
      const received = upstream.requests[0];
      expect(received.url).toBe('/v1/messages');
      // The gateway swaps in the registered secret; the caller's key never travels.
      expect(received.headers['x-api-key']).toBe('anthropic-key-xyz');
      expect(received.headers['anthropic-version']).toBe('2023-06-01');
      // The body passes through with no field added, removed, or renamed.
      expect(received.body).toEqual(payload);

      await app.close();
    } finally {
      await sql.end();
      await new Promise((r) => upstream.server.close(r));
    }
  });

  it('relays an upstream 429 as 429 with its body — never collapsed into 403', async () => {
    const { db, sql } = getDb(cfg);
    const upstreamBody = JSON.stringify({ type: 'error', error: { type: 'rate_limit_error', message: 'slow down' } });
    const upstream = await startUpstream({ status: 429, body: upstreamBody });
    try {
      const { agent, apiKey } = await registerAgent(db, { name: `llmraw-429-${Date.now()}`, tenant: 'test', allowedModels: [MODEL] });
      await seedBudget(db, agent.id, 1_000_000, 1_000_000);
      await putCredential(db, cfg, agent.id, 'llm:anthropic', 'anthropic-key-xyz', `http://127.0.0.1:${upstream.port}`);
      const app = buildServer({ cfg, db, engine });

      const res = await app.inject({
        method: 'POST',
        url: '/v1/messages',
        headers: { 'x-api-key': apiKey },
        payload: { model: MODEL, max_tokens: 16, messages: [] },
      });

      // 403 here is the defect this route exists to fix: the SDK maps typed
      // errors by status alone, and 403 is not retryable.
      expect(res.statusCode).toBe(429);
      expect(res.statusCode).not.toBe(403);
      expect(res.body).toBe(upstreamBody);

      await app.close();
    } finally {
      await sql.end();
      await new Promise((r) => upstream.server.close(r));
    }
  });
});
