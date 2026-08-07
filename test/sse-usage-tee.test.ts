/**
 * Unit proofs for the SSE usage tee (G2, plan 45-07).
 *
 * The primary contract is BYTE FIDELITY: whatever the upstream writes reaches
 * the client unchanged. Usage accumulation is a side effect of watching a copy
 * go by, and it must never be able to alter, delay or drop a byte. Every
 * fidelity assertion below therefore compares real Buffers with
 * `Buffer.concat(...).equals(...)`, not parsed events.
 */
import { describe, it, expect } from 'vitest';
import { makeUsageTee, type StreamUsage } from '../src/streaming/sse-usage-tee.js';

/** One well-formed SSE frame, exactly as Anthropic writes them. */
function frame(event: string, data: unknown): string {
  return `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
}

/**
 * Feed an exact chunk sequence through the tee.
 *
 * Chunks are written one at a time with `tee.write(...)` rather than piped from
 * a Readable, because a Readable's internal buffer is free to coalesce chunks —
 * which would silently defeat the whole point of the split tests below.
 */
async function run(chunks: Buffer[]): Promise<{ out: Buffer; usage: StreamUsage }> {
  let usage: StreamUsage = { input: 0, output: 0, cacheWrite: 0, cacheRead: 0 };
  const tee = makeUsageTee((u) => { usage = u; });
  const out: Buffer[] = [];
  tee.on('data', (c: Buffer) => out.push(Buffer.from(c)));
  const done = new Promise<void>((resolve, reject) => {
    tee.on('end', () => resolve());
    tee.on('error', reject);
  });
  for (const c of chunks) tee.write(c);
  tee.end();
  await done;
  return { out: Buffer.concat(out), usage };
}

const MESSAGE_START = frame('message_start', {
  type: 'message_start',
  message: { id: 'msg_1', type: 'message', role: 'assistant', content: [], usage: { input_tokens: 12000, output_tokens: 1 } },
});

describe('makeUsageTee', () => {
  it('passes bytes through byte-identically, including ping frames and comment lines', async () => {
    const sse =
      MESSAGE_START +
      ': this is an SSE comment the parser must ignore\n\n' +
      frame('ping', { type: 'ping' }) +
      frame('content_block_start', { type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } }) +
      frame('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'hello' } }) +
      frame('message_delta', { type: 'message_delta', delta: { stop_reason: 'end_turn' }, usage: { output_tokens: 2000 } }) +
      frame('message_stop', { type: 'message_stop' });
    const input = Buffer.from(sse, 'utf8');

    const { out } = await run([input]);

    expect(out.equals(input)).toBe(true);
    expect(out.length).toBe(input.length);
  });

  it('reads input from message_start and output from the LAST message_delta, never their sum', async () => {
    const sse =
      MESSAGE_START +
      frame('message_delta', { type: 'message_delta', delta: {}, usage: { output_tokens: 500 } }) +
      frame('message_delta', { type: 'message_delta', delta: {}, usage: { output_tokens: 1200 } }) +
      frame('message_delta', { type: 'message_delta', delta: { stop_reason: 'end_turn' }, usage: { output_tokens: 2000 } }) +
      frame('message_stop', { type: 'message_stop' });

    const { usage } = await run([Buffer.from(sse, 'utf8')]);

    // message_delta.usage.output_tokens is CUMULATIVE: the SDK's own accumulator
    // OVERWRITES it (lib/MessageStream.js:454). Adding would give 3700.
    expect(usage.output).toBe(2000);
    expect(usage.output).not.toBe(3700);
    expect(usage.input).toBe(12000);
  });

  it('captures cache fields from message_start when present', async () => {
    const sse = frame('message_start', {
      type: 'message_start',
      message: { usage: { input_tokens: 100, cache_creation_input_tokens: 7, cache_read_input_tokens: 9 } },
    }) + frame('message_stop', { type: 'message_stop' });

    const { usage } = await run([Buffer.from(sse, 'utf8')]);

    expect(usage.input).toBe(100);
    expect(usage.cacheWrite).toBe(7);
    expect(usage.cacheRead).toBe(9);
  });

  it('defaults cache fields to 0 when the upstream omits them', async () => {
    const { usage } = await run([Buffer.from(MESSAGE_START, 'utf8')]);

    expect(usage.cacheWrite).toBe(0);
    expect(usage.cacheRead).toBe(0);
  });

  it('reassembles a frame split across two chunks mid-line, with identical bytes AND identical usage', async () => {
    const sse =
      MESSAGE_START +
      frame('message_delta', { type: 'message_delta', delta: { stop_reason: 'end_turn' }, usage: { output_tokens: 2000 } }) +
      frame('message_stop', { type: 'message_stop' });
    const input = Buffer.from(sse, 'utf8');

    // Split in the middle of the message_delta `data:` line — the exact hazard a
    // naive `chunk.toString().split('\n\n')` drops on the floor.
    const at = input.indexOf(Buffer.from('"output_tokens":2', 'utf8')) + 10;
    expect(at).toBeGreaterThan(0);

    const whole = await run([input]);
    const split = await run([input.subarray(0, at), input.subarray(at)]);

    expect(whole.out.equals(input)).toBe(true);
    expect(split.out.equals(input)).toBe(true);
    expect(split.usage).toEqual(whole.usage);
    expect(split.usage.output).toBe(2000);
  });

  it('survives a chunk boundary inside a multi-byte UTF-8 sequence', async () => {
    const sse =
      MESSAGE_START +
      frame('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'héllo — 世界' } }) +
      frame('message_delta', { type: 'message_delta', delta: { stop_reason: 'end_turn' }, usage: { output_tokens: 2000 } }) +
      frame('message_stop', { type: 'message_stop' });
    const input = Buffer.from(sse, 'utf8');

    // '世' is three bytes (E4 B8 96); cut after the first of them.
    const at = input.indexOf(Buffer.from('世', 'utf8')) + 1;
    expect(at).toBeGreaterThan(0);

    const whole = await run([input]);
    const split = await run([input.subarray(0, at), input.subarray(at)]);

    expect(split.out.equals(input)).toBe(true);
    expect(split.usage).toEqual(whole.usage);
    expect(split.usage.output).toBe(2000);
    expect(split.usage.input).toBe(12000);
  });

  it('coerces a string output_tokens to a number instead of string-concatenating it', async () => {
    const sse =
      frame('message_start', { type: 'message_start', message: { usage: { input_tokens: '40' } } }) +
      frame('message_delta', { type: 'message_delta', delta: {}, usage: { output_tokens: '40' } }) +
      frame('message_stop', { type: 'message_stop' });

    const { usage } = await run([Buffer.from(sse, 'utf8')]);

    expect(usage.output).toBe(40);
    expect(usage.input).toBe(40);
    expect(usage.input + usage.output).toBe(80);
    // With a naive `+` on the raw values this would be the string '4040'.
    expect(usage.input + usage.output).not.toBe('4040');
  });

  it('applies the same clamp as src/pricing/models.ts — a negative or absurd count can never move usage backwards', async () => {
    // CR-04, tee half. The two n() helpers are deliberately duplicated in
    // lockstep; this is the test that they have not drifted. A message_delta
    // OVERWRITES output (it is cumulative), so an unclamped -1000 does not just
    // fail to add — it replaces a real 2000 with a negative, and llm-raw.ts
    // hands `usage.input + usage.output` straight to meterUsage().
    const sse =
      MESSAGE_START +
      frame('message_delta', { type: 'message_delta', delta: {}, usage: { output_tokens: 2000 } }) +
      frame('message_delta', { type: 'message_delta', delta: { stop_reason: 'end_turn' }, usage: { output_tokens: -1000 } }) +
      frame('message_stop', { type: 'message_stop' });
    const input = Buffer.from(sse, 'utf8');

    const { out, usage } = await run([input]);

    // Byte fidelity is untouched by the clamp: the hostile frame still reaches
    // the client exactly as it arrived.
    expect(out.equals(input)).toBe(true);
    expect(usage.output).not.toBe(-1000);
    expect(usage.output).toBeGreaterThanOrEqual(0);
    expect(usage.input + usage.output).toBeGreaterThanOrEqual(0);
  });

  it('floors a fractional count and zeroes an absurd magnitude in every usage field', async () => {
    const sse =
      frame('message_start', {
        type: 'message_start',
        message: { usage: { input_tokens: 100.9, cache_creation_input_tokens: '1e308', cache_read_input_tokens: -7 } },
      }) +
      frame('message_delta', { type: 'message_delta', delta: {}, usage: { output_tokens: Infinity } }) +
      frame('message_stop', { type: 'message_stop' });

    const { usage } = await run([Buffer.from(sse, 'utf8')]);

    expect(usage.input).toBe(100);
    expect(usage.output).toBe(0);
    expect(usage.cacheWrite).toBe(0);
    expect(usage.cacheRead).toBe(0);
  });

  it('ignores a malformed data payload without throwing and without stopping the passthrough', async () => {
    const sse =
      MESSAGE_START +
      'event: message_delta\ndata: {this is not json\n\n' +
      frame('message_delta', { type: 'message_delta', delta: { stop_reason: 'end_turn' }, usage: { output_tokens: 2000 } }) +
      frame('message_stop', { type: 'message_stop' });
    const input = Buffer.from(sse, 'utf8');

    const { out, usage } = await run([input]);

    expect(out.equals(input)).toBe(true);
    expect(usage.output).toBe(2000);
    expect(usage.input).toBe(12000);
  });

  it('relays an event name it has never seen untouched and ignores it for usage', async () => {
    const sse =
      MESSAGE_START +
      frame('some_future_anthropic_event', { type: 'some_future_anthropic_event', usage: { output_tokens: 999999 } }) +
      frame('message_delta', { type: 'message_delta', delta: {}, usage: { output_tokens: 2000 } });
    const input = Buffer.from(sse, 'utf8');

    const { out, usage } = await run([input]);

    expect(out.equals(input)).toBe(true);
    expect(usage.output).toBe(2000);
    expect(usage.output).not.toBe(999999);
  });

  it('dispatches a final frame that arrives without a trailing blank line (flush path)', async () => {
    // A stream that dies right after the last data line still has to yield its
    // usage — Pitfall 9: an abnormal ending must not mean zero metering.
    const sse = MESSAGE_START + 'event: message_delta\ndata: {"type":"message_delta","usage":{"output_tokens":2000}}';
    const input = Buffer.from(sse, 'utf8');

    const { out, usage } = await run([input]);

    expect(out.equals(input)).toBe(true);
    expect(usage.output).toBe(2000);
  });
});
