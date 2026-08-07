/**
 * G2 — SSE passthrough on the raw route (POST /v1/messages with stream: true).
 *
 * These tests drive a REAL socket (`app.listen` + `fetch`) rather than
 * `app.inject`, for two reasons: `reply.hijack()` takes the response out of
 * Fastify's hands entirely, and a client disconnect mid-stream — the Pitfall-9
 * case where a closed tab must not yield free tokens — cannot be simulated
 * against an in-memory injection.
 *
 * Fidelity is asserted on BYTES, never on parsed events: the upstream records
 * exactly what it wrote and the test compares that Buffer with what the client
 * received.
 *
 * A streamed turn settles AFTER the response body has finished, so every test
 * waits for its audit record before tearing the pool down. That is not
 * politeness: closing the pool underneath an unfinished settle is exactly how a
 * "passing" suite hides a lost governance record.
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

/** Priced in MODEL_PRICES at 3,000 / 15,000 micros per 1K, so metering is exercised. */
const MODEL = 'claude-sonnet-4-6';

const delay = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

function frame(event: string, data: unknown): string {
  return `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
}

/** message_start carrying 12,000 input tokens — half of the 66,000-micro worked example. */
const START_12K = frame('message_start', {
  type: 'message_start',
  message: { id: 'msg_stream', type: 'message', role: 'assistant', content: [], usage: { input_tokens: 12000, output_tokens: 0 } },
});

const DELTA_2K = frame('message_delta', { type: 'message_delta', delta: { stop_reason: 'end_turn' }, usage: { output_tokens: 2000 } });
const STOP = frame('message_stop', { type: 'message_stop' });
const textDelta = (text: string): string =>
  frame('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text } });

interface RecordedRequest {
  method: string | undefined;
  url: string | undefined;
  headers: IncomingMessage['headers'];
  raw: string;
}

interface StreamUpstreamOptions {
  /** SSE frames written one `res.write()` at a time. */
  frames?: string[];
  /** Split `frames[index]` into two writes at byte `offset` — the carry-buffer exercise. */
  splitFrameAt?: { index: number; offset: number };
  /** Destroy the socket after writing this frame index (mid-stream upstream fault). */
  destroyAfterFrame?: number;
  /**
   * Grace period before that destroy. It must be long enough for the gateway to
   * have received the upstream RESPONSE HEADERS and opened the client's SSE
   * response — otherwise the destroy races the `fetch` promise itself and the
   * gateway correctly answers 502 `upstream_unreachable`, which is a different
   * code path and not the one this knob exists to exercise.
   */
  destroyDelayMs?: number;
  /** Milliseconds between frames. Large enough that a client abort lands mid-stream. */
  gapMs?: number;
  /** Non-2xx: answer buffered JSON and never open an SSE response. */
  status?: number;
  body?: string;
  headers?: Record<string, string>;
}

interface StreamUpstream {
  server: Server;
  port: number;
  requests: RecordedRequest[];
  /** Every byte the upstream actually wrote on the SSE body, in order. */
  wrote: Buffer[];
}

/**
 * Streaming variant of the `startUpstream` harness in test/plane-llm.test.ts and
 * test/plane-llm-raw.test.ts. Those always answer buffered 200 JSON; this one
 * writes SSE frames with explicit `res.write()` calls so the test controls the
 * exact chunk boundaries the gateway's tee has to cope with.
 */
function startStreamUpstream(opts: StreamUpstreamOptions = {}): Promise<StreamUpstream> {
  const requests: RecordedRequest[] = [];
  const wrote: Buffer[] = [];
  return new Promise((resolve) => {
    const server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => {
        requests.push({ method: req.method, url: req.url, headers: req.headers, raw: Buffer.concat(chunks).toString('utf8') });

        if (opts.status !== undefined && opts.status !== 200) {
          res.writeHead(opts.status, { 'content-type': 'application/json', ...(opts.headers ?? {}) });
          res.end(opts.body ?? JSON.stringify({ type: 'error', error: { type: 'rate_limit_error', message: 'slow down' } }));
          return;
        }

        res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache', ...(opts.headers ?? {}) });
        const write = (b: Buffer): void => { wrote.push(Buffer.from(b)); res.write(b); };
        void (async () => {
          const frames = opts.frames ?? [];
          for (let i = 0; i < frames.length; i++) {
            const buf = Buffer.from(frames[i], 'utf8');
            if (opts.splitFrameAt && opts.splitFrameAt.index === i) {
              write(buf.subarray(0, opts.splitFrameAt.offset));
              await delay(5);
              write(buf.subarray(opts.splitFrameAt.offset));
            } else {
              write(buf);
            }
            if (opts.destroyAfterFrame === i) {
              await delay(opts.destroyDelayMs ?? 150);
              res.socket?.destroy();
              return;
            }
            await delay(opts.gapMs ?? 2);
          }
          res.end();
        })();
      });
    });
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      resolve({ server, port, requests, wrote });
    });
  });
}

type Db = ReturnType<typeof getDb>['db'];

/** Every audit row carrying this correlation id. Length is the settle count. */
async function auditFor(db: Db, correlationId: string): Promise<{ verdict: string; why: unknown }[]> {
  return db.select().from(auditRecords)
    .where(dsql`${auditRecords.whenWhere}->>'correlationId' = ${correlationId}`) as unknown as Promise<{ verdict: string; why: unknown }[]>;
}

/** Bounded wait for the post-stream settle to reach Postgres. */
async function waitForAudit(db: Db, correlationId: string): Promise<{ verdict: string; why: unknown }[]> {
  let rows: { verdict: string; why: unknown }[] = [];
  for (let i = 0; i < 150; i++) {
    rows = await auditFor(db, correlationId);
    if (rows.length > 0) return rows;
    await delay(20);
  }
  return rows;
}

async function budgetOf(db: Db, agentId: string): Promise<{ tokensUsed: number; costUsedMicros: number }> {
  const [r] = await db.select().from(budgets).where(eq(budgets.agentId, agentId)).limit(1);
  return { tokensUsed: r.tokensUsed, costUsedMicros: r.costUsedMicros };
}

describe('POST /v1/messages with stream: true (G2 SSE passthrough)', () => {
  it('relays the SSE stream byte-for-byte with 200 and text/event-stream', async () => {
    const { db, sql } = getDb(cfg);
    const upstream = await startStreamUpstream({
      frames: [
        START_12K,
        frame('content_block_start', { type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } }),
        textDelta('thinking…'),
        textDelta(' more — 世界'),
        frame('ping', { type: 'ping' }),
        frame('some_future_event', { type: 'some_future_event' }),
        DELTA_2K,
        STOP,
      ],
    });
    const app = buildServer({ cfg, db, engine });
    try {
      const { agent, apiKey } = await registerAgent(db, { name: `rawstream-fid-${Date.now()}`, tenant: 'test', allowedModels: [MODEL] });
      await seedBudget(db, agent.id, 1_000_000, 1_000_000);
      await putCredential(db, cfg, agent.id, 'llm:anthropic', 'anthropic-key-xyz', `http://127.0.0.1:${upstream.port}`);
      const base = await app.listen({ port: 0, host: '127.0.0.1' });

      const correlationId = randomUUID();
      const res = await fetch(`${base}/v1/messages`, {
        method: 'POST',
        headers: { 'x-api-key': apiKey, 'content-type': 'application/json', 'x-correlation-id': correlationId },
        body: JSON.stringify({ model: MODEL, max_tokens: 64, stream: true, messages: [{ role: 'user', content: 'hi' }] }),
      });

      expect(res.status).toBe(200);
      expect(res.headers.get('content-type')).toContain('text/event-stream');
      expect(res.headers.get('cache-control')).toBe('no-cache');
      expect(res.headers.get('x-accel-buffering')).toBe('no');

      const received = Buffer.from(await res.arrayBuffer());
      // Bytes, not events: an unknown event name and a ping both survive.
      expect(received.equals(Buffer.concat(upstream.wrote))).toBe(true);
      expect(upstream.requests.length).toBe(1);
      expect(upstream.requests[0].headers['x-api-key']).toBe('anthropic-key-xyz');

      expect((await waitForAudit(db, correlationId)).length).toBe(1);
    } finally {
      await app.close();
      await sql.end();
      await new Promise((r) => upstream.server.close(r));
    }
  });

  it('stays byte-identical when the upstream flushes a frame across two writes, splitting it mid-line', async () => {
    const { db, sql } = getDb(cfg);
    // Cut the message_delta frame in the middle of its `data:` line — the exact
    // hazard a naive split-on-blank-line drops on the floor, taking the usage
    // figures with it.
    const splitOffset = Buffer.from(DELTA_2K, 'utf8').indexOf(Buffer.from('"output_tokens":2', 'utf8')) + 10;
    const upstream = await startStreamUpstream({
      frames: [START_12K, textDelta('a'), DELTA_2K, STOP],
      splitFrameAt: { index: 2, offset: splitOffset },
    });
    const app = buildServer({ cfg, db, engine });
    try {
      const { agent, apiKey } = await registerAgent(db, { name: `rawstream-split-${Date.now()}`, tenant: 'test', allowedModels: [MODEL] });
      await seedBudget(db, agent.id, 1_000_000, 1_000_000);
      await putCredential(db, cfg, agent.id, 'llm:anthropic', 'anthropic-key-xyz', `http://127.0.0.1:${upstream.port}`);
      const base = await app.listen({ port: 0, host: '127.0.0.1' });

      const correlationId = randomUUID();
      const before = await budgetOf(db, agent.id);
      const res = await fetch(`${base}/v1/messages`, {
        method: 'POST',
        headers: { 'x-api-key': apiKey, 'content-type': 'application/json', 'x-correlation-id': correlationId },
        body: JSON.stringify({ model: MODEL, stream: true, messages: [] }),
      });
      expect(res.status).toBe(200);
      const received = Buffer.from(await res.arrayBuffer());

      expect(splitOffset).toBeGreaterThan(10);
      expect(upstream.wrote.length).toBeGreaterThan(4);   // the split really produced an extra write
      expect(received.equals(Buffer.concat(upstream.wrote))).toBe(true);

      expect((await waitForAudit(db, correlationId)).length).toBe(1);
      const after = await budgetOf(db, agent.id);
      // The frame was reassembled, so its usage was read: 12,000 + 2,000.
      expect(after.tokensUsed - before.tokensUsed).toBe(14000);
      expect(after.costUsedMicros - before.costUsedMicros).toBe(66000);
    } finally {
      await app.close();
      await sql.end();
      await new Promise((r) => upstream.server.close(r));
    }
  });

  it('meters the stream at split rates: 12,000 in + 2,000 out on Sonnet 4.6 costs exactly 66,000 micros', async () => {
    const { db, sql } = getDb(cfg);
    const upstream = await startStreamUpstream({ frames: [START_12K, textDelta('x'), DELTA_2K, STOP] });
    const app = buildServer({ cfg, db, engine });
    try {
      const { agent, apiKey } = await registerAgent(db, { name: `rawstream-meter-${Date.now()}`, tenant: 'test', allowedModels: [MODEL] });
      await seedBudget(db, agent.id, 1_000_000, 1_000_000);
      await putCredential(db, cfg, agent.id, 'llm:anthropic', 'anthropic-key-xyz', `http://127.0.0.1:${upstream.port}`);
      const base = await app.listen({ port: 0, host: '127.0.0.1' });

      const correlationId = randomUUID();
      const before = await budgetOf(db, agent.id);
      const res = await fetch(`${base}/v1/messages`, {
        method: 'POST',
        headers: { 'x-api-key': apiKey, 'content-type': 'application/json', 'x-correlation-id': correlationId },
        body: JSON.stringify({ model: MODEL, stream: true, messages: [] }),
      });
      expect(res.status).toBe(200);
      await res.arrayBuffer();
      expect((await waitForAudit(db, correlationId)).length).toBe(1);
      const after = await budgetOf(db, agent.id);

      // Identical arithmetic to the non-streaming branch (plan 45-05):
      //   12,000 / 1000 x 3,000  = 36,000 micros of input
      //    2,000 / 1000 x 15,000 = 30,000 micros of output
      //                    total = 66,000 micros
      expect(after.tokensUsed - before.tokensUsed).toBe(14000);
      expect(after.costUsedMicros - before.costUsedMicros).toBe(66000);
      // The blended single-rate regression, which the old table produced.
      expect(after.costUsedMicros - before.costUsedMicros).not.toBe(42000);
    } finally {
      await app.close();
      await sql.end();
      await new Promise((r) => upstream.server.close(r));
    }
  });

  it('treats message_delta output_tokens as CUMULATIVE: 500, 1200, 2000 meters 2,000 — not 3,700', async () => {
    const { db, sql } = getDb(cfg);
    const upstream = await startStreamUpstream({
      frames: [
        START_12K,
        frame('message_delta', { type: 'message_delta', delta: {}, usage: { output_tokens: 500 } }),
        frame('message_delta', { type: 'message_delta', delta: {}, usage: { output_tokens: 1200 } }),
        DELTA_2K,
        STOP,
      ],
    });
    const app = buildServer({ cfg, db, engine });
    try {
      const { agent, apiKey } = await registerAgent(db, { name: `rawstream-cum-${Date.now()}`, tenant: 'test', allowedModels: [MODEL] });
      await seedBudget(db, agent.id, 1_000_000, 1_000_000);
      await putCredential(db, cfg, agent.id, 'llm:anthropic', 'anthropic-key-xyz', `http://127.0.0.1:${upstream.port}`);
      const base = await app.listen({ port: 0, host: '127.0.0.1' });

      const correlationId = randomUUID();
      const before = await budgetOf(db, agent.id);
      const res = await fetch(`${base}/v1/messages`, {
        method: 'POST',
        headers: { 'x-api-key': apiKey, 'content-type': 'application/json', 'x-correlation-id': correlationId },
        body: JSON.stringify({ model: MODEL, stream: true, messages: [] }),
      });
      expect(res.status).toBe(200);
      await res.arrayBuffer();
      expect((await waitForAudit(db, correlationId)).length).toBe(1);
      const after = await budgetOf(db, agent.id);

      const tokenDelta = after.tokensUsed - before.tokensUsed;
      // 12,000 input + 2,000 output (the LAST value), never 12,000 + 3,700.
      expect(tokenDelta).toBe(14000);
      expect(tokenDelta).not.toBe(15700);
      expect(tokenDelta - 12000).toBe(2000);
      expect(tokenDelta - 12000).not.toBe(3700);
      expect(after.costUsedMicros - before.costUsedMicros).toBe(66000);
    } finally {
      await app.close();
      await sql.end();
      await new Promise((r) => upstream.server.close(r));
    }
  });

  it('settles an upstream that dies mid-stream as ALLOW with partial usage and an error marker — never a retroactive deny', async () => {
    const { db, sql } = getDb(cfg);
    // Socket destroyed straight after message_start: input is known, output is not.
    const upstream = await startStreamUpstream({
      frames: [START_12K, textDelta('partial'), DELTA_2K, STOP],
      destroyAfterFrame: 0,
    });
    const app = buildServer({ cfg, db, engine });
    try {
      const { agent, apiKey } = await registerAgent(db, { name: `rawstream-uperr-${Date.now()}`, tenant: 'test', allowedModels: [MODEL] });
      await seedBudget(db, agent.id, 1_000_000, 1_000_000);
      await putCredential(db, cfg, agent.id, 'llm:anthropic', 'anthropic-key-xyz', `http://127.0.0.1:${upstream.port}`);
      const base = await app.listen({ port: 0, host: '127.0.0.1' });

      const correlationId = randomUUID();
      const before = await budgetOf(db, agent.id);
      const res = await fetch(`${base}/v1/messages`, {
        method: 'POST',
        headers: { 'x-api-key': apiKey, 'content-type': 'application/json', 'x-correlation-id': correlationId },
        body: JSON.stringify({ model: MODEL, stream: true, messages: [] }),
      });
      // The status was fixed the moment the first byte went out, and it stays 200.
      expect(res.status).toBe(200);
      // The client's read tears down with the upstream; that is expected.
      await res.arrayBuffer().catch(() => undefined);

      const rows = await waitForAudit(db, correlationId);
      expect(rows.length).toBe(1);
      // Bytes were already delivered, so the decision cannot be retracted.
      expect(rows[0].verdict).toBe('allow');
      expect(rows[0].verdict).not.toBe('deny');
      expect(String((rows[0].why as { reason?: unknown }).reason)).toContain('upstream_error:');

      const after = await budgetOf(db, agent.id);
      // Partial, not zero and not the full turn: input only.
      expect(after.tokensUsed - before.tokensUsed).toBe(12000);
      expect(after.costUsedMicros - before.costUsedMicros).toBe(36000);
    } finally {
      await app.close();
      await sql.end();
      await new Promise((r) => upstream.server.close(r));
    }
  });

  it('settles EXACTLY ONCE with partial usage when the client disconnects mid-stream — a closed tab is not free tokens', async () => {
    const { db, sql } = getDb(cfg);
    // Slow enough that the abort lands before the message_delta carrying output.
    const upstream = await startStreamUpstream({
      frames: [START_12K, textDelta('one'), textDelta('two'), textDelta('three'), DELTA_2K, STOP],
      gapMs: 120,
    });
    const app = buildServer({ cfg, db, engine });
    try {
      const { agent, apiKey } = await registerAgent(db, { name: `rawstream-abort-${Date.now()}`, tenant: 'test', allowedModels: [MODEL] });
      await seedBudget(db, agent.id, 1_000_000, 1_000_000);
      await putCredential(db, cfg, agent.id, 'llm:anthropic', 'anthropic-key-xyz', `http://127.0.0.1:${upstream.port}`);
      const base = await app.listen({ port: 0, host: '127.0.0.1' });

      const correlationId = randomUUID();
      const controller = new AbortController();
      const res = await fetch(`${base}/v1/messages`, {
        method: 'POST',
        headers: { 'x-api-key': apiKey, 'content-type': 'application/json', 'x-correlation-id': correlationId },
        body: JSON.stringify({ model: MODEL, stream: true, messages: [] }),
        signal: controller.signal,
      });
      expect(res.status).toBe(200);

      // Read until message_start has definitely arrived, then close the tab.
      const reader = res.body!.getReader();
      const seen: Buffer[] = [];
      for (let i = 0; i < 20; i++) {
        const { value, done } = await reader.read();
        if (done) break;
        if (value) seen.push(Buffer.from(value));
        if (Buffer.concat(seen).includes('message_start')) break;
      }
      expect(Buffer.concat(seen).includes('message_start')).toBe(true);
      controller.abort();

      const rows = await waitForAudit(db, correlationId);
      // ONE settle. A disconnect racing the pipeline rejection must not meter twice.
      expect(rows.length).toBe(1);
      expect(rows[0].verdict).toBe('allow');

      // Give any (bugged) second settle time to land before asserting the delta.
      await delay(300);
      expect((await auditFor(db, correlationId)).length).toBe(1);
      const after = await budgetOf(db, agent.id);
      // Partial usage, metered once: 12,000 input, no output seen yet.
      expect(after.tokensUsed).toBe(12000);
      expect(after.tokensUsed).not.toBe(0);
      expect(after.tokensUsed).not.toBe(24000);
      expect(after.costUsedMicros).toBe(36000);
    } finally {
      await app.close();
      await sql.end();
      await new Promise((r) => upstream.server.close(r));
    }
  });

  it('relays a pre-stream upstream 429 as 429 and never opens an SSE response', async () => {
    const { db, sql } = getDb(cfg);
    const upstreamBody = JSON.stringify({ type: 'error', error: { type: 'rate_limit_error', message: 'slow down' } });
    const upstream = await startStreamUpstream({ status: 429, body: upstreamBody });
    const app = buildServer({ cfg, db, engine });
    try {
      const { agent, apiKey } = await registerAgent(db, { name: `rawstream-429-${Date.now()}`, tenant: 'test', allowedModels: [MODEL] });
      await seedBudget(db, agent.id, 1_000_000, 1_000_000);
      await putCredential(db, cfg, agent.id, 'llm:anthropic', 'anthropic-key-xyz', `http://127.0.0.1:${upstream.port}`);
      const base = await app.listen({ port: 0, host: '127.0.0.1' });

      const correlationId = randomUUID();
      const res = await fetch(`${base}/v1/messages`, {
        method: 'POST',
        headers: { 'x-api-key': apiKey, 'content-type': 'application/json', 'x-correlation-id': correlationId },
        body: JSON.stringify({ model: MODEL, stream: true, messages: [] }),
      });

      // The SDK's retry machinery only fires on the real status; 403 would kill it.
      expect(res.status).toBe(429);
      expect(res.status).not.toBe(403);
      expect(await res.text()).toBe(upstreamBody);
      // No half-opened stream: had the gateway written SSE headers first, the
      // status could never have been 429 and finalMessage() would have thrown
      // "request ended without sending any chunks".
      expect(res.headers.get('content-type')).not.toContain('text/event-stream');
      expect(res.headers.get('x-accel-buffering')).toBeNull();

      const rows = await waitForAudit(db, correlationId);
      expect(rows.length).toBe(1);
      expect(rows[0].verdict).toBe('allow');
      expect(String((rows[0].why as { reason?: unknown }).reason)).toContain('upstream_error:upstream_429');
    } finally {
      await app.close();
      await sql.end();
      await new Promise((r) => upstream.server.close(r));
    }
  });

  it('does not inflate the meter when a streamed usage field arrives as the string "40"', async () => {
    const { db, sql } = getDb(cfg);
    const upstream = await startStreamUpstream({
      frames: [
        frame('message_start', { type: 'message_start', message: { usage: { input_tokens: '40' } } }),
        textDelta('y'),
        frame('message_delta', { type: 'message_delta', delta: { stop_reason: 'end_turn' }, usage: { output_tokens: '40' } }),
        STOP,
      ],
    });
    const app = buildServer({ cfg, db, engine });
    try {
      const { agent, apiKey } = await registerAgent(db, { name: `rawstream-str-${Date.now()}`, tenant: 'test', allowedModels: [MODEL] });
      await seedBudget(db, agent.id, 1_000_000, 1_000_000);
      await putCredential(db, cfg, agent.id, 'llm:anthropic', 'anthropic-key-xyz', `http://127.0.0.1:${upstream.port}`);
      const base = await app.listen({ port: 0, host: '127.0.0.1' });

      const correlationId = randomUUID();
      const before = await budgetOf(db, agent.id);
      const res = await fetch(`${base}/v1/messages`, {
        method: 'POST',
        headers: { 'x-api-key': apiKey, 'content-type': 'application/json', 'x-correlation-id': correlationId },
        body: JSON.stringify({ model: MODEL, stream: true, messages: [] }),
      });
      expect(res.status).toBe(200);
      await res.arrayBuffer();
      expect((await waitForAudit(db, correlationId)).length).toBe(1);
      const after = await budgetOf(db, agent.id);

      const tokenDelta = after.tokensUsed - before.tokensUsed;
      expect(tokenDelta).toBe(80);
      // With a naive `+` this is the string '4040'.
      expect(tokenDelta).not.toBe(4040);
      // 40/1000 x 3,000 = 120 input micros; 40/1000 x 15,000 = 600 output micros.
      expect(after.costUsedMicros - before.costUsedMicros).toBe(720);
    } finally {
      await app.close();
      await sql.end();
      await new Promise((r) => upstream.server.close(r));
    }
  });
});
