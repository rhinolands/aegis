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
 * `cacheWrite` / `cacheRead` are BILLED CLASSES, not diagnostics. Anthropic's
 * `usage.input_tokens` EXCLUDES both of them, so a turn whose prompt carried
 * `cache_control` reports a tiny input count for a very large real spend.
 * src/pricing/models.ts prices all four classes at their own verified rates.
 *
 * The justification these fields used to carry — "Acme sends no cache_control
 * today, verified by negative grep over packages/advisor" — was retired by
 * CR-02, and it is worth saying why so it is not reinstated. It described the
 * wrong trust boundary. planes/llm-raw.ts is a PASSTHROUGH: it forwards
 * `req.rawLlmBody` verbatim and validates nothing but `model`, and the
 * allowlist keys on `request.model` rather than on body shape. Any
 * authenticated caller — including the non-Acme consumers a vendor-neutral
 * gateway exists to serve — can put `cache_control` in its own body today. What
 * Acme's own client happens to send constrains nothing.
 */
export interface StreamUsage {
  input: number;
  output: number;
  cacheWrite: number;
  cacheRead: number;
  // The ONE-HOUR cache write, a distinct billed class from the 5-minute
  // `cacheWrite` (2x base input vs 1.25x). Anthropic reports the per-TTL split
  // in `usage.cache_creation.{ephemeral_5m,ephemeral_1h}_input_tokens`; the flat
  // top-level `cache_creation_input_tokens` is their sum. Kept separate here so
  // the settle site can price it at its own rate (DEBT-05) rather than folding a
  // 1h write into the 5m rate and under-metering it 1.6x.
  cacheWrite1h: number;
}

// Coerce every usage field before arithmetic. Carried verbatim in intent from
// src/pricing/models.ts: an upstream is untrusted input, and if it returns a
// field as a string (usage.output_tokens: "40") naive `+` does string
// concatenation instead of addition ("40" + 60 === "4060"), silently inflating
// the metered token count by orders of magnitude. Number(x) turns
// NaN/undefined/null/non-numeric strings into NaN, which the guard below maps
// to 0 rather than propagating garbage into the meter.
//
// The upstream is OPERATOR-REGISTERED. That is an argument about who it is, not
// about what it sends, and this coercion exists precisely because a registered
// upstream is still not trusted to be WELL-FORMED. The previous coercion —
// `Number(v)` with an or-zero fallback — closed the string hazard above and
// left three others open (CR-04):
//
//   NEGATIVE — the one that matters, and it bites harder here than in the
//     pricing module because message_delta usage is CUMULATIVE and therefore
//     OVERWRITES: a frame reporting output_tokens: -1000 does not merely fail
//     to add, it REPLACES a real accumulated 2000. planes/llm-raw.ts settles
//     with `tokens: usage.input + usage.output` and meterUsage() then moves
//     budgets.cost_used_micros DOWN, permanently disarming that agent's cost
//     cap while it keeps answering "yes" to real spend.
//   FRACTIONAL — a fraction reaches Math.round((n / 1000) * rate) downstream
//     and produces micros never derived from a whole token.
//   ABSURD MAGNITUDE — Number('1e308') is FINITE, so a finite-only check still
//     admits it. Past Number.MAX_SAFE_INTEGER exact-integer arithmetic stops
//     holding.
//
// So: finite, strictly positive, safely representable, floored toward zero. The
// clamp may only ever move a reported count TOWARD zero, never away from it.
// An out-of-range value becomes 0 rather than being clamped up to the bound —
// metering a garbage field at MAX_SAFE_INTEGER would exhaust an honest agent's
// budget on one malformed response, turning an upstream fault into a customer
// outage. See src/pricing/models.ts for the full reasoning.
//
// DELIBERATELY DUPLICATED, NOT SHARED: this is a byte-identical copy of the
// helper in src/pricing/models.ts. This module is a pure byte-relay and must
// not take a dependency on the pricing module to stay that way. The two are
// meant to be diff-able; keep them identical, and change both or neither.
const n = (v: unknown): number => {
  const x = Number(v);
  if (!Number.isFinite(x) || x <= 0 || x > Number.MAX_SAFE_INTEGER) return 0;
  return Math.floor(x);
};

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
  const usage: StreamUsage = { input: 0, output: 0, cacheWrite: 0, cacheRead: 0, cacheWrite1h: 0 };

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
   *   message_start -> usage.input_tokens (+ the cache counters: 5m write, 1h
   *                    write and read; the 5m/1h split comes from the
   *                    cache_creation breakdown when present, else the flat
   *                    cache_creation_input_tokens is a 5m write — DEBT-05)
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
      const cc = u.cache_creation as Record<string, unknown> | null | undefined;
      usage.input = n(u.input_tokens);
      // Prefer the per-TTL breakdown: ephemeral_5m -> cacheWrite (1.25x),
      // ephemeral_1h -> cacheWrite1h (2x). When no breakdown is present the flat
      // count is the only signal and is metered as a 5m write — byte-identical to
      // the pre-DEBT-05 behaviour for upstreams that do not emit the split.
      usage.cacheWrite = cc ? n(cc.ephemeral_5m_input_tokens) : n(u.cache_creation_input_tokens);
      usage.cacheWrite1h = cc ? n(cc.ephemeral_1h_input_tokens) : 0;
      usage.cacheRead = n(u.cache_read_input_tokens);
      onUsage({ ...usage });
      return;
    }
    if (type === 'message_delta') {
      const u = (d?.usage as Record<string, unknown> | undefined) ?? {};
      const cc = u.cache_creation as Record<string, unknown> | null | undefined;
      if (u.output_tokens != null) usage.output = n(u.output_tokens);
      if (u.input_tokens != null) usage.input = n(u.input_tokens);
      // Breakdown wins when present; otherwise the flat field still overwrites
      // cacheWrite as a 5m write (the delta's cumulative-overwrite semantics).
      if (cc && cc.ephemeral_5m_input_tokens != null) usage.cacheWrite = n(cc.ephemeral_5m_input_tokens);
      else if (u.cache_creation_input_tokens != null) usage.cacheWrite = n(u.cache_creation_input_tokens);
      if (cc && cc.ephemeral_1h_input_tokens != null) usage.cacheWrite1h = n(cc.ephemeral_1h_input_tokens);
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
