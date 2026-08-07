/**
 * Per-model token pricing for the LLM meter.
 *
 * This module replaces the `COST_MICROS_PER_1K` table that used to live in
 * `src/planes/llm.ts`. That table stored ONE rate per model and applied it to
 * `input + output` summed. No single blended number can be correct when a
 * vendor prices output at 5x input, which both models below do — metering the
 * sum at the input rate under-meters a typical 12K-in/2K-out assessment by 36%,
 * and an output-heavy 1K-in/4K-out turn by 4.2x. A cost cap that trips at the
 * wrong spend is worse than one that never trips, because it looks correct.
 */

/** Two rates, never one. `inputMicrosPer1K` and `outputMicrosPer1K` are both micros per 1,000 tokens. */
export interface ModelPrice {
  inputMicrosPer1K: number;
  outputMicrosPer1K: number;
}

// [VERIFIED 2026-08-07 — primary source: Anthropic official pricing docs,
//  https://platform.claude.com/docs/en/about-claude/pricing (model-pricing
//  table, fetched 2026-08-07)]
//
//    Claude Haiku 4.5   $1 / MTok input   $5  / MTok output
//    Claude Sonnet 4.6  $3 / MTok input   $15 / MTok output
//
//  Derivation, shown inline so a reviewer can re-derive it in 30 seconds
//  (1 micro = $0.000001):
//
//    micros_per_1K = dollars_per_MTok x 1000
//
//      check: $3 / 1,000,000 tokens
//           = $0.000003 / token
//           = 3 micros / token
//           = 3,000 micros / 1,000 tokens        <- matches the x1000 rule
//
//  Meter-unit sanity check (this repo shipped a x730 unit bug once): the
//  arithmetic in priceMicros() below divides the token count by 1000 before
//  multiplying, so these figures MUST be per-1K. A per-MTok figure dropped in
//  unchanged would under-meter by 1000x; a per-token figure would over-meter
//  by 1000x.
//
// [VERIFIED 2026-08-07 — independent second source: the OpenRouter public
//  model API (https://openrouter.ai/api/v1/models) reports
//  anthropic/claude-sonnet-4.6 at 0.000003 / 0.000015 USD per token and
//  anthropic/claude-haiku-4.5 at 0.000001 / 0.000005 USD per token — i.e.
//  $3/$15 and $1/$5 per MTok, agreeing with the primary source. Both sources'
//  batch rows (Sonnet $1.50/$7.50, Haiku $0.50/$2.50) are exactly 50% of the
//  standard rows, an internal consistency check on both readings.]
//
//  RE-VERIFY OBLIGATION: before any figure derived from this table is shown to
//  a user, put on an invoice, or used to justify a budget cap to an operator,
//  re-check both sources and update the date above. Anthropic has repriced
//  models before (Claude Sonnet 5 is on introductory pricing through
//  2026-08-31 and steps up on 2026-09-01). No naked numbers.
//
//  DELETED, DO NOT RESTORE FROM GIT HISTORY: the previous table's two rows,
//  'claude-sonnet-5': 3000 and 'claude-opus-4-8': 15000. They were
//  self-declared [UNVERIFIED] placeholders, they are not models Acme sends,
//  and they are wrong in this shape as well as the old one (against the same
//  primary source, Sonnet 5 is $2/$10 introductory then $3/$15, and Opus 4.8
//  is $5/$25 — neither is a single flat rate). Re-adding an unverified row
//  here re-creates the exact hazard this comment block exists to close.
//
//  EXACT-MATCH HAZARD: the lookup below is exact-string. 'claude-sonnet-4-6'
//  is an alias-style id while 'claude-haiku-4-5-20251001' is date-pinned;
//  Anthropic prices by model family, so a future dated Sonnet variant
//  (e.g. 'claude-sonnet-4-6-20260301') shares this price but would NOT match
//  this key and would fall through to `priced: false`. The structural guard
//  for that is plan 45-02's `scripts/update-agent.ts`, which refuses to put a
//  model into an agent's allowlist unless it has a MODEL_PRICES entry.
export const MODEL_PRICES: Record<string, ModelPrice> = {
  'claude-haiku-4-5-20251001': { inputMicrosPer1K: 1000, outputMicrosPer1K: 5000 },
  'claude-sonnet-4-6': { inputMicrosPer1K: 3000, outputMicrosPer1K: 15000 },
};

// Coerce every usage field before arithmetic. An upstream is untrusted input:
// if it returns a field as a string (e.g. usage.input_tokens: "40"), naive `+`
// does string concatenation instead of addition ("40" + 60 === "4060"),
// silently inflating the metered token count (and therefore costMicros) by
// orders of magnitude. Number(x) also turns NaN/undefined/null/non-numeric
// strings into NaN, which the guard below maps to 0 rather than propagating
// garbage into the meter.
//
// The upstream is OPERATOR-REGISTERED. That is an argument about who it is, not
// about what it sends, and this coercion exists precisely because a registered
// upstream is still not trusted to be WELL-FORMED. The previous coercion —
// `Number(v)` with an or-zero fallback — closed the string hazard above and
// left three others open (CR-04):
//
//   NEGATIVE — the one that matters. Number(-500000) || 0 === -500000, and so
//     does the string form. A negative count CREDITS the meter: priceMicros()
//     returns a negative costMicros, governSettle() hands it to
//     meterUsage(db, agentId, tokens, costMicros), and budgets.cost_used_micros
//     goes DOWN. One response reporting output_tokens: -1e9 on Sonnet credits
//     15,000,000,000 micros and permanently disarms that agent's cost cap,
//     which then keeps answering "yes" while real money is spent. A meter that
//     can run backwards is worse than no meter, because it looks correct.
//   FRACTIONAL — 12000.7 flows into Math.round((input / 1000) * rate) and
//     produces micros that were never derived from a whole token.
//   ABSURD MAGNITUDE — Number('1e308') is FINITE, so a finite-only check still
//     admits it. Past Number.MAX_SAFE_INTEGER the exact-integer arithmetic this
//     meter is built on stops holding.
//
// So: finite, strictly positive, safely representable, floored toward zero.
// The clamp may only ever move a reported count TOWARD zero, never away from
// it — that is the single property that makes the meter monotonic.
//
// Why an out-of-range value becomes 0 and is not clamped UP to the bound: a
// value we have decided is not a real token count should not be allowed to
// pick a number for us. Metering a garbage field as MAX_SAFE_INTEGER would
// instantly and permanently exhaust an honest agent's budget on one malformed
// response — turning an upstream fault into a customer outage. Zero loses the
// metering for that one response, which is the same disposition this helper
// already takes for undefined/null/NaN. Plausibility bounds (a real turn is
// nowhere near 2^53 tokens) belong to the budget cap, not to a type coercion;
// the bound here is about representability only.
//
// DELIBERATELY DUPLICATED, NOT SHARED: src/streaming/sse-usage-tee.ts carries a
// byte-identical copy of this function. The tee is a pure byte-relay module and
// must not take a dependency on the pricing module to stay that way. The two
// are meant to be diff-able; keep them identical, and change both or neither.
const n = (v: unknown): number => {
  const x = Number(v);
  if (!Number.isFinite(x) || x <= 0 || x > Number.MAX_SAFE_INTEGER) return 0;
  return Math.floor(x);
};

/**
 * Widened form of the old `extractTokens`, which returned ONE summed number
 * and so made split-rate pricing impossible at the call site.
 *
 * Anthropic style reads `usage.input_tokens` / `usage.output_tokens`.
 * OpenAI style reads `usage.prompt_tokens` / `usage.completion_tokens`, and
 * falls back to `usage.total_tokens` as `input` with `output` 0 — preserving
 * the envelope plane's pre-split behaviour for openai-style upstreams rather
 * than silently metering them at zero.
 */
export function extractUsage(
  style: 'anthropic' | 'openai',
  body: unknown,
): { input: number; output: number } {
  const u = (body as { usage?: Record<string, unknown> } | null | undefined)?.usage;
  if (!u) return { input: 0, output: 0 };
  if (style === 'anthropic') return { input: n(u.input_tokens), output: n(u.output_tokens) };
  if (u.total_tokens != null) return { input: n(u.total_tokens), output: 0 };
  return { input: n(u.prompt_tokens), output: n(u.completion_tokens) };
}

/**
 * Cost of a call, in micros, from its input and output token counts.
 *
 * `priced` is what replaces the old `?? 0` fallthrough. A model that is
 * allowlisted but absent from MODEL_PRICES used to meter $0 forever with no
 * signal at all, which makes a budget cap vacuous. This function still returns
 * 0 in that case — throwing would turn a pricing-table gap into a user-visible
 * refusal, a worse failure than an audited zero — but it says so, and the
 * caller is responsible for making it loud.
 */
export function priceMicros(
  model: string,
  input: number,
  output: number,
): { costMicros: number; priced: boolean } {
  const price = MODEL_PRICES[model];
  if (!price) return { costMicros: 0, priced: false };
  // Clamp HERE too, not only in extractUsage. This function is public and its
  // arguments arrive from call sites that did their own accumulation (the
  // streaming settle in planes/llm-raw.ts sums tee-accumulated fields), so it
  // cannot assume its inputs already went through n(). Clamping at the
  // arithmetic itself is what makes "costMicros is never negative" a property
  // of this function rather than a property of its callers' discipline.
  const i = n(input);
  const o = n(output);
  // Each side is rounded INDEPENDENTLY and then summed — deliberately, not as
  // a rounding of the sum. The two are not the same number in general, and the
  // per-side form is what the worked example in test/pricing.test.ts pins.
  const costMicros =
    Math.round((i / 1000) * price.inputMicrosPer1K) +
    Math.round((o / 1000) * price.outputMicrosPer1K);
  return { costMicros, priced: true };
}
