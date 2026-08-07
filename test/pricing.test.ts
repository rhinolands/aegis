import { describe, it, expect } from 'vitest';
import { MODEL_PRICES, extractUsage, priceMicros } from '../src/pricing/models.js';

// Split-rate arithmetic proof. The single blended rate this module replaces
// could not express "output costs 5x input", so a cost cap built on it tripped
// at the wrong spend while LOOKING correct. Every number asserted below is
// re-derivable from the [VERIFIED] figures in src/pricing/models.ts:
//
//   micros_per_1K = dollars_per_MTok x 1000
//   Sonnet 4.6  $3/$15 per MTok  ->  3000 / 15000 micros per 1K
//   Haiku 4.5   $1/$5  per MTok  ->  1000 /  5000 micros per 1K
//
// These are pure-function tests: no DB, no network, no server.

describe('priceMicros — split input/output rates', () => {
  it('reproduces the worked example: 12,000 in + 2,000 out on Sonnet 4.6 costs 66,000 micros (NOT the blended 42,000)', () => {
    const { costMicros, priced } = priceMicros('claude-sonnet-4-6', 12_000, 2_000);
    // 12000/1000 * 3000 = 36000 ; 2000/1000 * 15000 = 30000 ; total 66000.
    expect(costMicros).toBe(66_000);
    expect(priced).toBe(true);
    // The two regressions this test exists to catch: metering the sum at the
    // input rate (14 * 3000 = 42000, -36%) or at the output rate
    // (14 * 15000 = 210000, +218%).
    expect(costMicros).not.toBe(42_000);
    expect(costMicros).not.toBe(210_000);
  });

  it('prices an output-heavy Haiku 4.5 turn (1,000 in + 4,000 out) at 21,000 micros', () => {
    // 1000/1000 * 1000 = 1000 ; 4000/1000 * 5000 = 20000 ; total 21000.
    expect(priceMicros('claude-haiku-4-5-20251001', 1_000, 4_000)).toEqual({
      costMicros: 21_000,
      priced: true,
    });
  });

  it('reports an unpriced model instead of silently costing zero', () => {
    // claude-sonnet-5 was one of the two deleted [UNVERIFIED] placeholder rows.
    // The caller (planes/llm.ts) is responsible for making `priced: false` loud.
    expect(priceMicros('claude-sonnet-5', 1_000, 1_000)).toEqual({
      costMicros: 0,
      priced: false,
    });
  });
});

describe('extractUsage — untrusted upstream coercion', () => {
  it('coerces a string usage field to a number instead of string-concatenating it', () => {
    // Naive `+` would produce "40" + 60 === "4060", inflating the meter ~40x.
    expect(extractUsage('anthropic', { usage: { input_tokens: '40', output_tokens: 60 } })).toEqual({
      input: 40,
      output: 60,
    });
  });

  it('returns zeros for a body with no usage block and for a null body', () => {
    expect(extractUsage('anthropic', {})).toEqual({ input: 0, output: 0 });
    expect(extractUsage('anthropic', null)).toEqual({ input: 0, output: 0 });
  });

  it('reads openai-style prompt/completion token fields', () => {
    expect(extractUsage('openai', { usage: { prompt_tokens: 10, completion_tokens: 20 } })).toEqual({
      input: 10,
      output: 20,
    });
  });

  it('preserves the pre-existing openai total_tokens fallback as input with zero output', () => {
    // The envelope plane metered `total_tokens` before the split; losing it
    // would silently under-meter every openai-style call to zero.
    expect(extractUsage('openai', { usage: { total_tokens: 30 } })).toEqual({ input: 30, output: 0 });
  });
});

// ---------------------------------------------------------------------------
// CR-04. The coercion above this line was written for ONE hazard — a string
// usage field being `+`-concatenated instead of added. `Number(v) || 0` closes
// that hazard and no other. These cases are the three it left open, and the
// direction that matters is CREDIT: a meter that can move backwards is worse
// than no meter, because `ensureBudget` keeps saying yes while real money is
// spent. Every assertion below FAILS against `Number(v) || 0`.
// ---------------------------------------------------------------------------
describe('the usage clamp — an upstream can never credit or overflow the meter', () => {
  it('never lets a negative output count subtract from the input term', () => {
    // Number(-1_000_000) || 0 === -1_000_000. Unclamped this is
    // 3000 + Math.round(-1000 * 15000) = -14,997,000 micros, and meterUsage()
    // subtracts it from cost_used_micros — one response permanently disarming
    // the agent's cost cap.
    expect(priceMicros('claude-sonnet-4-6', 1_000, -1_000_000).costMicros).toBe(3_000);
    // Nothing an upstream reports can make a priced call cost less than nothing.
    expect(priceMicros('claude-sonnet-4-6', -5, -5).costMicros).toBe(0);
    expect(priceMicros('claude-haiku-4-5-20251001', -1e9, 1_000).costMicros).toBe(5_000);
  });

  it('zeroes a negative token count and a non-numeric string in extractUsage', () => {
    const u = extractUsage('anthropic', { usage: { input_tokens: -5, output_tokens: 'NaN' } });
    expect(u.input).toBe(0);
    expect(u.output).toBe(0);
    // The openai style reads different field names and must carry the same rule.
    expect(extractUsage('openai', { usage: { prompt_tokens: -1, completion_tokens: -2 } }).input).toBe(0);
    expect(extractUsage('openai', { usage: { total_tokens: -30 } }).input).toBe(0);
  });

  it('floors a fractional count rather than rounding it or passing it through', () => {
    // A fraction flows into Math.round((input/1000) * rate) and yields micros
    // that were never derived from a whole token. Floor, not round: the clamp
    // may only ever move a count toward zero, never away from it.
    const u = extractUsage('anthropic', { usage: { input_tokens: 12_000.7, output_tokens: 0 } });
    expect(u.input).toBe(12_000);
    expect(u.input).not.toBe(12_001);
    expect(Number.isInteger(u.input)).toBe(true);
    // 0.7 of a token is not a token.
    expect(extractUsage('anthropic', { usage: { input_tokens: 0.7 } }).input).toBe(0);
  });

  it('zeroes Infinity and an absurd finite magnitude instead of metering a huge number', () => {
    // Number('1e308') is FINITE, so a finite-only check still lets it through —
    // and 1e308 is far past Number.MAX_SAFE_INTEGER, where the integer
    // arithmetic this meter depends on stops being exact.
    expect(extractUsage('anthropic', { usage: { input_tokens: Infinity } }).input).toBe(0);
    expect(extractUsage('anthropic', { usage: { input_tokens: '1e308' } }).input).toBe(0);
    expect(extractUsage('anthropic', { usage: { output_tokens: -Infinity } }).output).toBe(0);
    expect(priceMicros('claude-sonnet-4-6', Number.MAX_VALUE, 0).costMicros).toBe(0);
  });

  it('still coerces a plain numeric string — the clamp does not regress the hazard it extends', () => {
    // The original reason n() exists. If this breaks, the fix traded one
    // silent-money bug for another.
    const u = extractUsage('anthropic', { usage: { input_tokens: '40', output_tokens: '60' } });
    expect(u.input).toBe(40);
    expect(u.output).toBe(60);
    expect(priceMicros('claude-sonnet-4-6', 12_000, 2_000).costMicros).toBe(66_000);
  });
});

describe('MODEL_PRICES — table shape invariants', () => {
  it('contains exactly the two model ids Acme sends, and nothing else', () => {
    // A placeholder row reappearing (claude-sonnet-5 / claude-opus-4-8, both
    // [UNVERIFIED] and both wrong in this shape too) fails here.
    expect(Object.keys(MODEL_PRICES).sort()).toEqual([
      'claude-haiku-4-5-20251001',
      'claude-sonnet-4-6',
    ]);
  });

  it('prices output above input for every entry — the property the old single-rate table could not express', () => {
    for (const [model, price] of Object.entries(MODEL_PRICES)) {
      expect(price.outputMicrosPer1K, `${model} output rate`).toBeGreaterThan(price.inputMicrosPer1K);
    }
  });

  it('carries the verified per-MTok figures in the units the meter expects (micros per 1K tokens)', () => {
    // Meter-unit sanity check (the x730 discipline): a per-MTok figure dropped
    // in unchanged would under-meter 1000x; a per-token figure over-meter 1000x.
    expect(MODEL_PRICES['claude-sonnet-4-6']).toEqual({ inputMicrosPer1K: 3_000, outputMicrosPer1K: 15_000 });
    expect(MODEL_PRICES['claude-haiku-4-5-20251001']).toEqual({ inputMicrosPer1K: 1_000, outputMicrosPer1K: 5_000 });
  });
});
