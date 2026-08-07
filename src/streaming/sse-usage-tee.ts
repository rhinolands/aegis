import { Transform, type TransformCallback } from 'node:stream';

// ---------------------------------------------------------------------------
// G2 — the SSE usage tee.
//
// WHY A Transform AND NOT THE WEB-STREAMS `tee` OPERATION.
// The web Streams spec requires the `tee` operation to buffer chunks for
// whichever branch reads slower: both branches see every chunk, so the
// implementation has to hold anything the lagging branch has not consumed. If
// the usage-parsing branch is not drained in exact lockstep with the branch
// feeding the client socket, that buffer grows without limit for the length of
// the stream — an unbounded-memory denial of service on a long advisor turn
// (45-RESEARCH.md Pitfall 8). An IN-LINE Transform has no second branch at all:
// it passes the chunk through untouched and inspects a copy on the way, so the
// natural backpressure chain from the client socket back to the upstream body
// is preserved end to end and nothing is ever buffered on its account.
//
// BYTE FIDELITY IS THE PRIMARY CONTRACT.
// This module NEVER re-serializes an event. It pushes the original chunk first
// and parses afterwards, so a malformed frame, an unknown event name, a `ping`,
// or an event type Anthropic adds next month all reach the client exactly as
// they arrived. Usage accumulation is a side effect of watching bytes go by and
// must never be able to alter, delay or drop one.
//
// NO VENDOR SDK DEPENDENCY.
// The incremental line decoding below is modelled on the official Anthropic
// TypeScript SDK's `internal/decoders/line.js` and the usage rules on its
// `lib/MessageStream.js:434-472` accumulator — both READ, neither imported.
// Aegis is a vendor-neutral gateway and must not take a dependency on any one
// model vendor's client library to speak its wire format.
// ---------------------------------------------------------------------------

/**
 * Token usage accumulated from an in-flight Anthropic SSE stream.
 *
 * `cacheWrite` / `cacheRead` are read even though Acme sends no `cache_control`
 * today (verified by negative grep over packages/advisor), so they will be 0.
 * They are captured anyway because costing cached tokens at the wrong rate
 * later is a silent-money bug, and the fields are free to add now.
 */
export interface StreamUsage {
  input: number;
  output: number;
  cacheWrite: number;
  cacheRead: number;
}

// Coerce every usage field through Number(...) || 0 before arithmetic. Carried
// verbatim in intent from src/pricing/models.ts: an upstream is untrusted
// input, and if it returns a field as a string (usage.output_tokens: "40")
// naive `+` does string concatenation instead of addition ("40" + 60 ===
// "4060"), silently inflating the metered token count by orders of magnitude.
// Number(x) || 0 also turns NaN/undefined/null/non-numeric strings into 0
// rather than propagating garbage into the meter.
const n = (v: unknown): number => Number(v) || 0;

/**
 * A pass-through `Transform` that relays every byte untouched while
 * accumulating Anthropic SSE usage from a copy.
 *
 * `onUsage` is invoked with a SNAPSHOT every time a usage-bearing frame is
 * seen, so the caller always holds the latest figures even if the stream ends
 * abnormally. That is what makes settle-on-client-disconnect meter partial
 * usage instead of zero (45-RESEARCH.md Pitfall 9).
 */
export function makeUsageTee(onUsage: (usage: StreamUsage) => void): Transform {
  const usage: StreamUsage = { input: 0, output: 0, cacheWrite: 0, cacheRead: 0 };

  // A streaming TextDecoder: decode(chunk, { stream: true }) holds back the
  // bytes of an incomplete multi-byte sequence and prepends them to the next
  // call, so a TCP chunk boundary landing in the middle of a UTF-8 character
  // cannot corrupt the parse.
  const decoder = new TextDecoder('utf-8');
  // Carry buffer for a partial trailing LINE (the decoder handles partial
  // CHARACTERS; this handles partial lines).
  let carry = '';
  let eventName = '';
  let dataParts: string[] = [];

  /**
   * Usage rules, mirroring the SDK's own accumulator exactly:
   *   message_start -> usage.input_tokens (+ the two cache counters)
   *   message_delta -> usage.output_tokens, which is CUMULATIVE and therefore
   *                    OVERWRITES rather than accumulates. Three deltas
   *                    reporting 500, 1200 and 2000 mean the turn produced
   *                    2000 output tokens, not 3700. input_tokens and the cache
   *                    counters are also overwritten when the delta carries
   *                    them, which it sometimes does.
   * Every other event name — content_block_*, message_stop, ping, error, and
   * anything Anthropic adds later — is relayed and ignored here.
   */
  const accumulate = (type: string, data: unknown): void => {
    const d = data as Record<string, unknown> | null | undefined;
    if (type === 'message_start') {
      const message = d?.message as { usage?: Record<string, unknown> } | undefined;
      const u = message?.usage ?? {};
      usage.input = n(u.input_tokens);
      usage.cacheWrite = n(u.cache_creation_input_tokens);
      usage.cacheRead = n(u.cache_read_input_tokens);
      onUsage({ ...usage });
      return;
    }
    if (type === 'message_delta') {
      const u = (d?.usage as Record<string, unknown> | undefined) ?? {};
      if (u.output_tokens != null) usage.output = n(u.output_tokens);
      if (u.input_tokens != null) usage.input = n(u.input_tokens);
      if (u.cache_creation_input_tokens != null) usage.cacheWrite = n(u.cache_creation_input_tokens);
      if (u.cache_read_input_tokens != null) usage.cacheRead = n(u.cache_read_input_tokens);
      onUsage({ ...usage });
    }
  };

  /** A blank line terminates a frame. Parse it, or drop it if it is not JSON. */
  const dispatch = (): void => {
    const name = eventName;
    const payload = dataParts;
    eventName = '';
    dataParts = [];
    if (payload.length === 0) return;

    let parsed: unknown;
    try {
      parsed = JSON.parse(payload.join('\n'));
    } catch {
      // A malformed `data:` payload is ignored for usage purposes and must
      // NEVER throw: the bytes have already been relayed, and a parse failure
      // here would tear down a healthy client stream over a cosmetic fault.
      return;
    }
    // Anthropic sets both the `event:` field and a `type` inside the payload;
    // prefer the field, fall back to the payload so a frame that omits the
    // field is still understood.
    const inner = (parsed as { type?: unknown } | null | undefined)?.type;
    const type = name.length > 0 ? name : typeof inner === 'string' ? inner : '';
    accumulate(type, parsed);
  };

  const handleLine = (raw: string): void => {
    const line = raw.endsWith('\r') ? raw.slice(0, -1) : raw;
    if (line === '') { dispatch(); return; }
    if (line.startsWith(':')) return;             // SSE comment
    const colon = line.indexOf(':');
    const field = colon === -1 ? line : line.slice(0, colon);
    let value = colon === -1 ? '' : line.slice(colon + 1);
    if (value.startsWith(' ')) value = value.slice(1);
    if (field === 'event') eventName = value;
    else if (field === 'data') dataParts.push(value);
  };

  const feed = (text: string): void => {
    carry += text;
    let idx = carry.indexOf('\n');
    while (idx !== -1) {
      const line = carry.slice(0, idx);
      carry = carry.slice(idx + 1);
      handleLine(line);
      idx = carry.indexOf('\n');
    }
  };

  return new Transform({
    transform(chunk: Buffer, _encoding: BufferEncoding, callback: TransformCallback): void {
      // Push FIRST. Byte fidelity outranks metering: if the parser below ever
      // misbehaves it must not be able to hold up, reorder or lose a byte.
      this.push(chunk);
      try {
        feed(decoder.decode(chunk, { stream: true }));
      } catch {
        // Defence in depth. Parsing is best-effort; the relay is not.
      }
      callback();
    },

    flush(callback: TransformCallback): void {
      try {
        feed(decoder.decode());
        if (carry.length > 0) {
          const last = carry;
          carry = '';
          handleLine(last);
        }
        // A stream that ends without its terminating blank line still yields
        // the frame it was in the middle of — an abnormal ending must not mean
        // zero metering.
        dispatch();
      } catch {
        // As above: never fail the relay over a parse fault.
      }
      callback();
    },
  });
}
