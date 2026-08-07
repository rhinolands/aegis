/**
 * Protocol fidelity, status relay and split-rate metering for the G1 raw
 * route (POST /v1/messages). The security surface lives in its sibling,
 * test/plane-llm-raw-security.test.ts, and is deliberately not duplicated here.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { createServer, type Server, type IncomingMessage } from 'node:http';
import { randomUUID } from 'node:crypto';
import { eq, sql as dsql } from 'drizzle-orm';
import { getDb } from '../src/db/client.js';
import { loadConfig } from '../src/config.js';
import { loadPolicy, type PolicyEngine } from '../src/policy/opa.js';
import { registerAgent } from '../src/identity/registry.js';
import { putCredential } from '../src/credentials/store.js';
import { seedBudget } from '../src/guard/budget.js';
import { buildServer } from '../src/server.js';
import { budgets, auditRecords } from '../src/db/schema.js';

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
  /** Extra/overriding response headers. */
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
      // The body passes through with no field added, removed, or renamed —
      // asserted both structurally and as raw bytes.
      expect(received.body).toEqual(payload);
      expect(received.raw).toBe(JSON.stringify(payload));

      await app.close();
    } finally {
      await sql.end();
      await new Promise((r) => upstream.server.close(r));
    }
  });

  it('forwards the beta query and the anthropic-beta header for beta.messages.parse()', async () => {
    const { db, sql } = getDb(cfg);
    const upstream = await startUpstream({ usage: { input_tokens: 10, output_tokens: 5 } });
    try {
      const { agent, apiKey } = await registerAgent(db, { name: `llmraw-beta-${Date.now()}`, tenant: 'test', allowedModels: [MODEL] });
      await seedBudget(db, agent.id, 1_000_000, 1_000_000);
      await putCredential(db, cfg, agent.id, 'llm:anthropic', 'anthropic-key-xyz', `http://127.0.0.1:${upstream.port}`);
      const app = buildServer({ cfg, db, engine });

      const res = await app.inject({
        method: 'POST',
        url: '/v1/messages?beta=true',
        headers: {
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01',
          'anthropic-beta': 'structured-outputs-2025-12-15',
        },
        payload: { model: MODEL, max_tokens: 16, messages: [] },
      });

      expect(res.statusCode).toBe(200);
      expect(upstream.requests.length).toBe(1);
      expect(upstream.requests[0].url).toBe('/v1/messages?beta=true');
      // Kill-finding K2: the SDK strips `betas` out of the body into this
      // header, so it is the only carrier of structured-output behaviour.
      expect(upstream.requests[0].headers['anthropic-beta']).toBe('structured-outputs-2025-12-15');

      await app.close();
    } finally {
      await sql.end();
      await new Promise((r) => upstream.server.close(r));
    }
  });

  it('meters input and output at their OWN rates: 12,000 in + 2,000 out on Sonnet 4.6 costs exactly 66,000 micros', async () => {
    const { db, sql } = getDb(cfg);
    const upstream = await startUpstream({ usage: { input_tokens: 12000, output_tokens: 2000 } });
    try {
      const { agent, apiKey } = await registerAgent(db, { name: `llmraw-meter-${Date.now()}`, tenant: 'test', allowedModels: [MODEL] });
      await seedBudget(db, agent.id, 1_000_000, 1_000_000);
      await putCredential(db, cfg, agent.id, 'llm:anthropic', 'anthropic-key-xyz', `http://127.0.0.1:${upstream.port}`);
      const app = buildServer({ cfg, db, engine });

      const [before] = await db.select().from(budgets).where(eq(budgets.agentId, agent.id)).limit(1);
      const res = await app.inject({
        method: 'POST',
        url: '/v1/messages',
        headers: { 'x-api-key': apiKey },
        payload: { model: MODEL, max_tokens: 16, messages: [] },
      });
      expect(res.statusCode).toBe(200);
      const [after] = await db.select().from(budgets).where(eq(budgets.agentId, agent.id)).limit(1);

      // The token meter is one number: input + output.
      expect(after.tokensUsed - before.tokensUsed).toBe(14000);
      // RESEARCH §4.4 derivation, quoted so a reviewer re-derives it in 30s:
      //   12,000 / 1000 x 3,000  =  36,000 micros of input
      //    2,000 / 1000 x 15,000 =  30,000 micros of output
      //                    total =  66,000 micros
      // A blended single-rate regression produces 42,000 and fails here; the
      // old table applied the INPUT rate to the summed tokens.
      expect(after.costUsedMicros - before.costUsedMicros).toBe(66000);
      expect(after.costUsedMicros - before.costUsedMicros).not.toBe(42000);

      await app.close();
    } finally {
      await sql.end();
      await new Promise((r) => upstream.server.close(r));
    }
  });

  it('does not inflate the meter when the upstream reports usage counts as strings', async () => {
    const { db, sql } = getDb(cfg);
    const upstream = await startUpstream({ usage: { input_tokens: '40', output_tokens: 60 } });
    try {
      const { agent, apiKey } = await registerAgent(db, { name: `llmraw-str-${Date.now()}`, tenant: 'test', allowedModels: [MODEL] });
      await seedBudget(db, agent.id, 1_000_000, 1_000_000);
      await putCredential(db, cfg, agent.id, 'llm:anthropic', 'anthropic-key-xyz', `http://127.0.0.1:${upstream.port}`);
      const app = buildServer({ cfg, db, engine });

      const [before] = await db.select().from(budgets).where(eq(budgets.agentId, agent.id)).limit(1);
      const res = await app.inject({
        method: 'POST',
        url: '/v1/messages',
        headers: { 'x-api-key': apiKey },
        payload: { model: MODEL, max_tokens: 16, messages: [] },
      });
      expect(res.statusCode).toBe(200);
      const [after] = await db.select().from(budgets).where(eq(budgets.agentId, agent.id)).limit(1);

      // With a naive `+`, "40" + 60 === "4060".
      const delta = after.tokensUsed - before.tokensUsed;
      expect(delta).toBe(100);
      expect(delta).not.toBe(4060);

      await app.close();
    } finally {
      await sql.end();
      await new Promise((r) => upstream.server.close(r));
    }
  });

  // ---- status relay: one test per row of RESEARCH §1.5's collapse table ----

  it('relays an upstream 400 as 400 with its body — never collapsed into 403', async () => {
    const { db, sql } = getDb(cfg);
    const upstreamBody = JSON.stringify({ type: 'error', error: { type: 'invalid_request_error', message: 'max_tokens required' } });
    const upstream = await startUpstream({ status: 400, body: upstreamBody });
    try {
      const { agent, apiKey } = await registerAgent(db, { name: `llmraw-400-${Date.now()}`, tenant: 'test', allowedModels: [MODEL] });
      await seedBudget(db, agent.id, 1_000_000, 1_000_000);
      await putCredential(db, cfg, agent.id, 'llm:anthropic', 'anthropic-key-xyz', `http://127.0.0.1:${upstream.port}`);
      const app = buildServer({ cfg, db, engine });

      const res = await app.inject({
        method: 'POST', url: '/v1/messages',
        headers: { 'x-api-key': apiKey },
        payload: { model: MODEL, messages: [] },
      });

      expect(res.statusCode).toBe(400);
      expect(res.statusCode).not.toBe(403);
      expect(res.body).toBe(upstreamBody);

      await app.close();
    } finally {
      await sql.end();
      await new Promise((r) => upstream.server.close(r));
    }
  });

  it('relays an upstream 401 as 401 — an operator key problem must not look like a policy deny', async () => {
    const { db, sql } = getDb(cfg);
    const upstreamBody = JSON.stringify({ type: 'error', error: { type: 'authentication_error', message: 'invalid x-api-key' } });
    const upstream = await startUpstream({ status: 401, body: upstreamBody });
    try {
      const { agent, apiKey } = await registerAgent(db, { name: `llmraw-401-${Date.now()}`, tenant: 'test', allowedModels: [MODEL] });
      await seedBudget(db, agent.id, 1_000_000, 1_000_000);
      await putCredential(db, cfg, agent.id, 'llm:anthropic', 'anthropic-key-xyz', `http://127.0.0.1:${upstream.port}`);
      const app = buildServer({ cfg, db, engine });

      const res = await app.inject({
        method: 'POST', url: '/v1/messages',
        headers: { 'x-api-key': apiKey },
        payload: { model: MODEL, messages: [] },
      });

      expect(res.statusCode).toBe(401);
      expect(res.statusCode).not.toBe(403);
      expect(res.body).toBe(upstreamBody);

      await app.close();
    } finally {
      await sql.end();
      await new Promise((r) => upstream.server.close(r));
    }
  });

  it('relays an upstream 429 as 429 with its body — never collapsed into 403', async () => {
    const { db, sql } = getDb(cfg);
    const upstreamBody = JSON.stringify({ type: 'error', error: { type: 'rate_limit_error', message: 'slow down' } });
    // retry-after is not required to survive the hop; the STATUS is what makes
    // the SDK's retry machinery fire at all (403 is not retryable).
    const upstream = await startUpstream({ status: 429, body: upstreamBody, headers: { 'retry-after': '2' } });
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

      expect(res.statusCode).toBe(429);
      expect(res.statusCode).not.toBe(403);
      expect(res.body).toBe(upstreamBody);

      await app.close();
    } finally {
      await sql.end();
      await new Promise((r) => upstream.server.close(r));
    }
  });

  it('relays an upstream 500 as 500, copies request-id, and audits the relayed failure with a marker', async () => {
    const { db, sql } = getDb(cfg);
    const upstreamBody = JSON.stringify({ type: 'error', error: { type: 'api_error', message: 'overloaded' } });
    const upstream = await startUpstream({ status: 500, body: upstreamBody, headers: { 'request-id': 'req_relay_500' } });
    try {
      const { agent, apiKey } = await registerAgent(db, { name: `llmraw-500-${Date.now()}`, tenant: 'test', allowedModels: [MODEL] });
      await seedBudget(db, agent.id, 1_000_000, 1_000_000);
      await putCredential(db, cfg, agent.id, 'llm:anthropic', 'anthropic-key-xyz', `http://127.0.0.1:${upstream.port}`);
      const app = buildServer({ cfg, db, engine });

      const correlationId = randomUUID();
      const [before] = await db.select().from(budgets).where(eq(budgets.agentId, agent.id)).limit(1);
      const res = await app.inject({
        method: 'POST', url: '/v1/messages',
        headers: { 'x-api-key': apiKey, 'x-correlation-id': correlationId },
        payload: { model: MODEL, messages: [] },
      });

      expect(res.statusCode).toBe(500);
      expect(res.statusCode).not.toBe(403);
      expect(res.body).toBe(upstreamBody);
      // The join key Phase 47's audit correlation will want.
      expect(res.headers['request-id']).toBe('req_relay_500');

      // A relayed upstream failure is still an authorized call: the record
      // stays an allow and carries a marker, and nothing is metered.
      const [record] = await db.select().from(auditRecords)
        .where(dsql`${auditRecords.whenWhere}->>'correlationId' = ${correlationId}`).limit(1);
      expect(record).toBeDefined();
      expect(record.verdict).toBe('allow');
      expect(String((record.why as { reason?: unknown }).reason)).toContain('upstream_error:upstream_500');
      const [after] = await db.select().from(budgets).where(eq(budgets.agentId, agent.id)).limit(1);
      expect(after.tokensUsed - before.tokensUsed).toBe(0);
      expect(after.costUsedMicros - before.costUsedMicros).toBe(0);

      await app.close();
    } finally {
      await sql.end();
      await new Promise((r) => upstream.server.close(r));
    }
  });

  // ---- denial envelopes ----

  it('denies a model outside the allowlist with an Anthropic-shaped envelope carrying gateway_code model_not_allowed, leaking no gateway vocabulary', async () => {
    const { db, sql } = getDb(cfg);
    const upstream = await startUpstream({ usage: { input_tokens: 1, output_tokens: 1 } });
    try {
      const { agent, apiKey } = await registerAgent(db, { name: `llmraw-deny-${Date.now()}`, tenant: 'test', allowedModels: [MODEL] });
      await seedBudget(db, agent.id, 1_000_000, 1_000_000);
      await putCredential(db, cfg, agent.id, 'llm:anthropic', 'anthropic-key-xyz', `http://127.0.0.1:${upstream.port}`);
      const app = buildServer({ cfg, db, engine });

      const correlationId = randomUUID();
      const res = await app.inject({
        method: 'POST', url: '/v1/messages',
        headers: { 'x-api-key': apiKey, 'x-correlation-id': correlationId },
        payload: { model: 'claude-opus-4-8', messages: [] },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body) as { type?: string; error?: { type?: string; gateway_code?: string } };
      expect(body.type).toBe('error');
      expect(body.error?.type).toBe('permission_error');
      expect(body.error?.gateway_code).toBe('model_not_allowed');
      // D-09: Aegis's internal vocabulary must never reach Acme. The SDK
      // stuffs the whole body into err.message, which the advisor renders.
      expect(res.body).not.toContain('deny-by-default');
      expect(res.headers['x-should-retry']).toBe('false');
      // Nothing may reach the upstream on a denial.
      expect(upstream.requests.length).toBe(0);

      const [record] = await db.select().from(auditRecords)
        .where(dsql`${auditRecords.whenWhere}->>'correlationId' = ${correlationId}`).limit(1);
      expect(record).toBeDefined();
      expect(record.verdict).toBe('deny');

      await app.close();
    } finally {
      await sql.end();
      await new Promise((r) => upstream.server.close(r));
    }
  });

  it('trips the cost budget on the SECOND call — ensureBudget is pre-flight, metering is post-flight', async () => {
    const { db, sql } = getDb(cfg);
    const upstream = await startUpstream({ usage: { input_tokens: 12000, output_tokens: 2000 } });
    try {
      const { agent, apiKey } = await registerAgent(db, { name: `llmraw-budget-${Date.now()}`, tenant: 'test', allowedModels: [MODEL] });
      // Cost cap well below the 66,000 micros one call meters.
      await seedBudget(db, agent.id, 1_000_000, 1_000);
      await putCredential(db, cfg, agent.id, 'llm:anthropic', 'anthropic-key-xyz', `http://127.0.0.1:${upstream.port}`);
      const app = buildServer({ cfg, db, engine });

      const send = () => app.inject({
        method: 'POST', url: '/v1/messages',
        headers: { 'x-api-key': apiKey },
        payload: { model: MODEL, messages: [] },
      });

      // Asserting only the denial would pass against a gateway that denies
      // everything, so call 1 MUST be proven to succeed first.
      const first = await send();
      expect(first.statusCode).toBe(200);

      const second = await send();
      expect(second.statusCode).toBe(403);
      const body = JSON.parse(second.body) as { error?: { gateway_code?: string } };
      expect(body.error?.gateway_code).toBe('budget_exhausted');
      expect(second.body).not.toContain('cost budget exceeded');
      // The refused call never reached the upstream.
      expect(upstream.requests.length).toBe(1);

      await app.close();
    } finally {
      await sql.end();
      await new Promise((r) => upstream.server.close(r));
    }
  });

  it('refuses a streaming request with 503 streaming_not_supported and makes zero upstream requests (P-06)', async () => {
    const { db, sql } = getDb(cfg);
    const upstream = await startUpstream({ usage: { input_tokens: 1, output_tokens: 1 } });
    try {
      const { agent, apiKey } = await registerAgent(db, { name: `llmraw-stream-${Date.now()}`, tenant: 'test', allowedModels: [MODEL] });
      await seedBudget(db, agent.id, 1_000_000, 1_000_000);
      await putCredential(db, cfg, agent.id, 'llm:anthropic', 'anthropic-key-xyz', `http://127.0.0.1:${upstream.port}`);
      const app = buildServer({ cfg, db, engine });

      const res = await app.inject({
        method: 'POST', url: '/v1/messages',
        headers: { 'x-api-key': apiKey },
        payload: { model: MODEL, messages: [], stream: true },
      });

      expect(res.statusCode).toBe(503);
      const body = JSON.parse(res.body) as { error?: { type?: string; gateway_code?: string } };
      expect(body.error?.type).toBe('api_error');
      expect(body.error?.gateway_code).toBe('streaming_not_supported');
      // Buffering a stream request is NOT a valid degrade — plan 45-07 (G2)
      // replaces this branch with the real passthrough.
      expect(upstream.requests.length).toBe(0);

      await app.close();
    } finally {
      await sql.end();
      await new Promise((r) => upstream.server.close(r));
    }
  });

  it('refuses with gateway_code not_provisioned when no upstream destination is registered', async () => {
    const { db, sql } = getDb(cfg);
    try {
      const { agent, apiKey } = await registerAgent(db, { name: `llmraw-noprov-${Date.now()}`, tenant: 'test', allowedModels: [MODEL] });
      await seedBudget(db, agent.id, 1_000_000, 1_000_000);
      // Deliberately NO putCredential for (agent, 'llm:anthropic').
      const app = buildServer({ cfg, db, engine });

      const res = await app.inject({
        method: 'POST', url: '/v1/messages',
        headers: { 'x-api-key': apiKey },
        payload: { model: MODEL, messages: [] },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body) as { error?: { gateway_code?: string } };
      expect(body.error?.gateway_code).toBe('not_provisioned');
      expect(res.headers['x-should-retry']).toBe('false');

      await app.close();
    } finally {
      await sql.end();
    }
  });

  it('accepts a body larger than Fastify’s 1 MiB default but under the 8 MiB route limit (P-08)', async () => {
    const { db, sql } = getDb(cfg);
    const upstream = await startUpstream({ usage: { input_tokens: 10, output_tokens: 5 } });
    try {
      const { agent, apiKey } = await registerAgent(db, { name: `llmraw-big-${Date.now()}`, tenant: 'test', allowedModels: [MODEL] });
      await seedBudget(db, agent.id, 1_000_000, 1_000_000);
      await putCredential(db, cfg, agent.id, 'llm:anthropic', 'anthropic-key-xyz', `http://127.0.0.1:${upstream.port}`);
      const app = buildServer({ cfg, db, engine });

      // Generated, never committed as a fixture. ~2 MiB of content, which is
      // the shape of Acme's assessment prompt (blueprint + cost table + ALZ
      // findings in one string).
      const big = 'x'.repeat(2 * 1024 * 1024);
      const res = await app.inject({
        method: 'POST', url: '/v1/messages',
        headers: { 'x-api-key': apiKey },
        payload: { model: MODEL, max_tokens: 16, messages: [{ role: 'user', content: big }] },
      });

      expect(res.statusCode).not.toBe(413);
      expect(res.statusCode).toBe(200);
      expect(upstream.requests.length).toBe(1);
      expect(((upstream.requests[0].body as { messages: { content: string }[] }).messages[0].content).length).toBe(big.length);

      await app.close();
    } finally {
      await sql.end();
      await new Promise((r) => upstream.server.close(r));
    }
  });

  it('relays a 2xx body that is not JSON as-is, metering zero rather than throwing', async () => {
    const { db, sql } = getDb(cfg);
    const upstream = await startUpstream({ status: 200, body: '<html>gateway sandwich</html>', headers: { 'content-type': 'text/html' } });
    try {
      const { agent, apiKey } = await registerAgent(db, { name: `llmraw-nonjson-${Date.now()}`, tenant: 'test', allowedModels: [MODEL] });
      await seedBudget(db, agent.id, 1_000_000, 1_000_000);
      await putCredential(db, cfg, agent.id, 'llm:anthropic', 'anthropic-key-xyz', `http://127.0.0.1:${upstream.port}`);
      const app = buildServer({ cfg, db, engine });

      const [before] = await db.select().from(budgets).where(eq(budgets.agentId, agent.id)).limit(1);
      const res = await app.inject({
        method: 'POST', url: '/v1/messages',
        headers: { 'x-api-key': apiKey },
        payload: { model: MODEL, messages: [] },
      });

      expect(res.statusCode).toBe(200);
      expect(res.body).toBe('<html>gateway sandwich</html>');
      const [after] = await db.select().from(budgets).where(eq(budgets.agentId, agent.id)).limit(1);
      expect(after.tokensUsed - before.tokensUsed).toBe(0);

      await app.close();
    } finally {
      await sql.end();
      await new Promise((r) => upstream.server.close(r));
    }
  });

  it('rejects a body with no usable model with 400, before any governance work', async () => {
    const { db, sql } = getDb(cfg);
    const upstream = await startUpstream();
    try {
      const { agent, apiKey } = await registerAgent(db, { name: `llmraw-badbody-${Date.now()}`, tenant: 'test', allowedModels: [MODEL] });
      await seedBudget(db, agent.id, 1_000_000, 1_000_000);
      await putCredential(db, cfg, agent.id, 'llm:anthropic', 'anthropic-key-xyz', `http://127.0.0.1:${upstream.port}`);
      const app = buildServer({ cfg, db, engine });

      const res = await app.inject({
        method: 'POST', url: '/v1/messages',
        headers: { 'x-api-key': apiKey },
        payload: { messages: [] },
      });

      expect(res.statusCode).toBe(400);
      expect(upstream.requests.length).toBe(0);

      await app.close();
    } finally {
      await sql.end();
      await new Promise((r) => upstream.server.close(r));
    }
  });

  it('rejects an unauthenticated request with 403 before any governance or upstream work', async () => {
    const { db, sql } = getDb(cfg);
    const upstream = await startUpstream();
    try {
      const app = buildServer({ cfg, db, engine });
      const res = await app.inject({
        method: 'POST', url: '/v1/messages',
        payload: { model: MODEL, messages: [] },
      });
      expect(res.statusCode).toBe(403);
      expect(JSON.parse(res.body)).toEqual({ error: 'unauthenticated' });
      expect(upstream.requests.length).toBe(0);
      await app.close();
    } finally {
      await sql.end();
      await new Promise((r) => upstream.server.close(r));
    }
  });
});
