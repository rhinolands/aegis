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
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { createServer, type Server, type IncomingMessage } from 'node:http';
import { eq } from 'drizzle-orm';
import { getDb } from '../src/db/client.js';
import { loadConfig } from '../src/config.js';
import { loadPolicy, type PolicyEngine } from '../src/policy/opa.js';
import { registerAgent } from '../src/identity/registry.js';
import { putCredential } from '../src/credentials/store.js';
import { seedBudget } from '../src/guard/budget.js';
import { buildServer } from '../src/server.js';
import { budgets } from '../src/db/schema.js';

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
  /** Destroy the socket immediately after writing this frame index (mid-stream upstream fault). */
  destroyAfterFrame?: number;
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
            if (opts.destroyAfterFrame === i) { res.socket?.destroy(); return; }
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

describe('POST /v1/messages with stream: true (G2 SSE passthrough)', () => {
  it('relays the SSE stream byte-for-byte with 200 and text/event-stream', async () => {
    const { db, sql } = getDb(cfg);
    const upstream = await startStreamUpstream({
      frames: [
        START_12K,
        frame('content_block_start', { type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } }),
        frame('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'thinking…' } }),
        frame('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: ' more' } }),
        frame('ping', { type: 'ping' }),
        frame('message_delta', { type: 'message_delta', delta: { stop_reason: 'end_turn' }, usage: { output_tokens: 2000 } }),
        frame('message_stop', { type: 'message_stop' }),
      ],
    });
    const app = buildServer({ cfg, db, engine });
    try {
      const { agent, apiKey } = await registerAgent(db, { name: `rawstream-fid-${Date.now()}`, tenant: 'test', allowedModels: [MODEL] });
      await seedBudget(db, agent.id, 1_000_000, 1_000_000);
      await putCredential(db, cfg, agent.id, 'llm:anthropic', 'anthropic-key-xyz', `http://127.0.0.1:${upstream.port}`);
      const base = await app.listen({ port: 0, host: '127.0.0.1' });

      const res = await fetch(`${base}/v1/messages`, {
        method: 'POST',
        headers: { 'x-api-key': apiKey, 'content-type': 'application/json' },
        body: JSON.stringify({ model: MODEL, max_tokens: 64, stream: true, messages: [{ role: 'user', content: 'hi' }] }),
      });

      expect(res.status).toBe(200);
      expect(res.headers.get('content-type')).toContain('text/event-stream');
      expect(res.headers.get('cache-control')).toBe('no-cache');
      expect(res.headers.get('x-accel-buffering')).toBe('no');

      const received = Buffer.from(await res.arrayBuffer());
      expect(received.equals(Buffer.concat(upstream.wrote))).toBe(true);
      expect(upstream.requests.length).toBe(1);
      expect(upstream.requests[0].headers['x-api-key']).toBe('anthropic-key-xyz');
    } finally {
      await app.close();
      await sql.end();
      await new Promise((r) => upstream.server.close(r));
    }
  });

  it('meters the stream at split rates: 12,000 in + 2,000 out on Sonnet 4.6 costs exactly 66,000 micros', async () => {
    const { db, sql } = getDb(cfg);
    const upstream = await startStreamUpstream({
      frames: [
        START_12K,
        frame('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'x' } }),
        frame('message_delta', { type: 'message_delta', delta: { stop_reason: 'end_turn' }, usage: { output_tokens: 2000 } }),
        frame('message_stop', { type: 'message_stop' }),
      ],
    });
    const app = buildServer({ cfg, db, engine });
    try {
      const { agent, apiKey } = await registerAgent(db, { name: `rawstream-meter-${Date.now()}`, tenant: 'test', allowedModels: [MODEL] });
      await seedBudget(db, agent.id, 1_000_000, 1_000_000);
      await putCredential(db, cfg, agent.id, 'llm:anthropic', 'anthropic-key-xyz', `http://127.0.0.1:${upstream.port}`);
      const base = await app.listen({ port: 0, host: '127.0.0.1' });

      const [before] = await db.select().from(budgets).where(eq(budgets.agentId, agent.id)).limit(1);
      const res = await fetch(`${base}/v1/messages`, {
        method: 'POST',
        headers: { 'x-api-key': apiKey, 'content-type': 'application/json' },
        body: JSON.stringify({ model: MODEL, stream: true, messages: [] }),
      });
      expect(res.status).toBe(200);
      await res.arrayBuffer();

      const after = await waitForBudgetChange(db, agent.id, before.tokensUsed);
      // Identical arithmetic to the non-streaming branch (plan 45-05):
      //   12,000 / 1000 x 3,000  = 36,000 micros of input
      //    2,000 / 1000 x 15,000 = 30,000 micros of output
      //                    total = 66,000 micros
      expect(after.tokensUsed - before.tokensUsed).toBe(14000);
      expect(after.costUsedMicros - before.costUsedMicros).toBe(66000);
      expect(after.costUsedMicros - before.costUsedMicros).not.toBe(42000);
    } finally {
      await app.close();
      await sql.end();
      await new Promise((r) => upstream.server.close(r));
    }
  });
});

/**
 * The settle runs after the response socket has already finished, so the test
 * must wait for the DB write rather than assume it landed. Bounded, and it
 * returns the row either way so the assertion — not the helper — decides.
 */
async function waitForBudgetChange(
  db: ReturnType<typeof getDb>['db'],
  agentId: string,
  baselineTokens: number,
): Promise<{ tokensUsed: number; costUsedMicros: number }> {
  let row = { tokensUsed: baselineTokens, costUsedMicros: 0 };
  for (let i = 0; i < 100; i++) {
    const [r] = await db.select().from(budgets).where(eq(budgets.agentId, agentId)).limit(1);
    row = { tokensUsed: r.tokensUsed, costUsedMicros: r.costUsedMicros };
    if (r.tokensUsed !== baselineTokens) return row;
    await delay(20);
  }
  return row;
}
