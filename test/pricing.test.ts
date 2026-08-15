import { describe, it, expect } from 'vitest';
import { MODEL_PRICES, extractUsage, priceMicros, type ModelPrice } from '../src/pricing/models.js';

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
      cacheWrite: 0,
      cacheRead: 0,
    });
  });

  it('returns zeros for a body with no usage block and for a null body', () => {
    expect(extractUsage('anthropic', {})).toEqual({ input: 0, output: 0, cacheWrite: 0, cacheRead: 0 });
    expect(extractUsage('anthropic', null)).toEqual({ input: 0, output: 0, cacheWrite: 0, cacheRead: 0 });
  });

  it('reads openai-style prompt/completion token fields', () => {
    expect(extractUsage('openai', { usage: { prompt_tokens: 10, completion_tokens: 20 } })).toEqual({
      input: 10,
      output: 20,
      cacheWrite: 0,
      cacheRead: 0,
    });
  });

  it('preserves the pre-existing openai total_tokens fallback as input with zero output', () => {
    // The envelope plane metered `total_tokens` before the split; losing it
    // would silently under-meter every openai-style call to zero.
    expect(extractUsage('openai', { usage: { total_tokens: 30 } })).toEqual({
      input: 30,
      output: 0,
      cacheWrite: 0,
      cacheRead: 0,
    });
  });
});

// ---------------------------------------------------------------------------
// CR-02. Anthropic's usage.input_tokens EXCLUDES both cache classes, so a
// prompt sent with cache_control reports ~20 input tokens for a 200,000-token
// prompt the operator is really billed for. The tee already COLLECTED the two
// cache counters and the pricing module then threw them away, which is the
// same silently-zero failure mode `priced: false` exists to prevent — but with
// no signal and no log line.
//
// This is reachable today, not hypothetically: planes/llm-raw.ts forwards
// req.rawLlmBody verbatim and validates only `model`, and the allowlist keys on
// request.model rather than on body shape. Any authenticated agent can send
// cache_control.
//
// Rates below are re-derivable from the [VERIFIED] block in src/pricing/models.ts:
//   Sonnet 4.6  input 3000 -> cache write (5m) 1.25x = 3750, cache read 0.10x = 300
//   Haiku 4.5   input 1000 -> cache write (5m) 1.25x = 1250, cache read 0.10x = 100
// ---------------------------------------------------------------------------
describe('priceMicros — all four billed token classes', () => {
  it('prices a worked four-class example on Sonnet 4.6 at 831,000 micros', () => {
    // 12,000 in      -> 12000/1000 * 3000  =  36,000
    //  2,000 out     ->  2000/1000 * 15000 =  30,000
    // 200,000 write  -> 200000/1000 * 3750 = 750,000
    //  50,000 read   -> 50000/1000 * 300   =  15,000
    //                                total = 831,000
    const { costMicros, priced } = priceMicros('claude-sonnet-4-6', 12_000, 2_000, 200_000, 50_000);
    expect(costMicros).toBe(831_000);
    expect(priced).toBe(true);
    // The regression this exists to catch: dropping the two cache terms, which
    // is what the code did before and which under-meters this turn by 92%.
    expect(costMicros).not.toBe(66_000);
  });

  it('does not price either cache class at the base input rate', () => {
    // A copy-paste of inputMicrosPer1K into either new field fails here.
    const base = priceMicros('claude-sonnet-4-6', 100_000, 0).costMicros;
    const write = priceMicros('claude-sonnet-4-6', 0, 0, 100_000, 0).costMicros;
    const read = priceMicros('claude-sonnet-4-6', 0, 0, 0, 100_000).costMicros;
    // Cache WRITE is more expensive than plain input (1.25x); cache READ is far
    // cheaper (0.10x). Both must differ from base, in opposite directions.
    expect(write).toBeGreaterThan(base);
    expect(read).toBeLessThan(base);
    expect(write).not.toBe(base);
    expect(read).not.toBe(base);
  });

  it('is backward compatible — a three-argument call behaves exactly as before', () => {
    // planes/llm.ts and planes/llm-raw.ts still call the three-arg form; 45-13
    // rewires them. Until then the cache parameters must default to 0.
    expect(priceMicros('claude-sonnet-4-6', 12_000, 2_000)).toEqual(
      priceMicros('claude-sonnet-4-6', 12_000, 2_000, 0, 0),
    );
    expect(priceMicros('claude-sonnet-4-6', 12_000, 2_000).costMicros).toBe(66_000);
  });

  it('reads both cache counters from an anthropic non-streaming body', () => {
    const u = extractUsage('anthropic', {
      usage: {
        input_tokens: 20,
        output_tokens: 5,
        cache_creation_input_tokens: 200_000,
        cache_read_input_tokens: 1_234,
      },
    });
    expect(u.cacheWrite).toBe(200_000);
    expect(u.cacheRead).toBe(1_234);
    // Absent fields are 0, not undefined — the sum at the settle site must stay
    // a number.
    const bare = extractUsage('anthropic', { usage: { input_tokens: 1 } });
    expect(bare.cacheWrite).toBe(0);
    expect(bare.cacheRead).toBe(0);
  });

  it('prices the CR-02 cached-prompt scenario far above what input_tokens alone reports', () => {
    // The exact exploit: a 200K-token prompt with cache_control reports ~20
    // input tokens. Asserted as a LOWER BOUND so this test does not re-pin the
    // rate — the [VERIFIED] block in the source is the only place a rate lives.
    const u = extractUsage('anthropic', {
      usage: { input_tokens: 20, output_tokens: 0, cache_creation_input_tokens: 200_000 },
    });
    const cached = priceMicros('claude-sonnet-4-6', u.input, u.output, u.cacheWrite, u.cacheRead).costMicros;
    const blindToCache = priceMicros('claude-sonnet-4-6', u.input, u.output).costMicros;

    expect(blindToCache).toBeLessThan(100); // ~60 micros: what the meter used to see
    expect(cached).toBeGreaterThan(500_000); // real spend is ~$0.75 = ~750,000 micros
    expect(cached / Math.max(blindToCache, 1)).toBeGreaterThan(1_000);
  });

  it('keeps the priced:false signal across all four classes for an unpriced model', () => {
    expect(priceMicros('claude-sonnet-5', 1_000, 1_000, 1_000, 1_000)).toEqual({
      costMicros: 0,
      priced: false,
    });
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

describe('the 1-hour cache-write class — DEBT-05', () => {
  it('meters a 1-hour cache write at 2x input, not the 5-minute 1.25x (RED against the pre-fix meter)', () => {
    // Anthropic bills a 1-hour cache write at 2x base input, a 5-minute write at
    // 1.25x. A 200,000-token 1h write on Sonnet is 200000/1000 * 6000 =
    // 1,200,000 micros. The PRE-FIX meter had no 1h class: the same tokens flowed
    // through the 5-minute rate at 200000/1000 * 3750 = 750,000 — a 1.6x
    // under-meter. If a future edit mis-prices the 1h class at 1.25x this returns
    // 750,000 and this assertion goes RED, which is the D-11 mutation ritual.
    const { costMicros, priced } = priceMicros('claude-sonnet-4-6', 0, 0, 0, 0, 200_000);
    expect(priced).toBe(true);
    expect(costMicros).toBe(1_200_000);
    expect(costMicros).not.toBe(750_000);
  });

  it('holds on Haiku too — 1h write is input * 2 (2000/1K), not the 5m 1250/1K', () => {
    // Haiku input 1000 -> 1h write 2000. 100,000 tokens = 100 * 2000 = 200,000
    // micros; the pre-fix 5m path would have returned 100 * 1250 = 125,000.
    const { costMicros } = priceMicros('claude-haiku-4-5-20251001', 0, 0, 0, 0, 100_000);
    expect(costMicros).toBe(200_000);
    expect(costMicros).not.toBe(125_000);
  });

  it('splits the anthropic cache_creation breakdown into 5m and 1h classes', () => {
    // When the per-TTL breakdown object is present, ephemeral_5m -> cacheWrite
    // (5m) and ephemeral_1h -> cacheWrite1h. The flat top-level count is their
    // sum and is NOT double-counted.
    const u = extractUsage('anthropic', {
      usage: {
        cache_creation: { ephemeral_5m_input_tokens: 0, ephemeral_1h_input_tokens: 200_000 },
        cache_creation_input_tokens: 200_000,
      },
    });
    expect(u.cacheWrite).toBe(0);
    expect(u.cacheWrite1h).toBe(200_000);
  });

  it('routes a mixed 5m/1h breakdown to both classes independently', () => {
    const u = extractUsage('anthropic', {
      usage: {
        cache_creation: { ephemeral_5m_input_tokens: 30_000, ephemeral_1h_input_tokens: 70_000 },
        cache_creation_input_tokens: 100_000,
      },
    });
    expect(u.cacheWrite).toBe(30_000);
    expect(u.cacheWrite1h).toBe(70_000);
    // And the two classes price at their own rates when summed through priceMicros.
    const { costMicros } = priceMicros('claude-sonnet-4-6', 0, 0, u.cacheWrite, 0, u.cacheWrite1h);
    // 30 * 3750 (5m) + 70 * 6000 (1h) = 112,500 + 420,000 = 532,500
    expect(costMicros).toBe(532_500);
  });

  it('falls back to the flat cache_creation_input_tokens as a 5m write when no breakdown is present', () => {
    // Byte-identical to the pre-fix behaviour for upstreams that do not emit the
    // per-TTL split: the flat field is metered as a 5-minute write, cacheWrite1h 0.
    const u = extractUsage('anthropic', { usage: { cache_creation_input_tokens: 200_000 } });
    expect(u.cacheWrite).toBe(200_000);
    expect(u.cacheWrite1h).toBe(0);
  });

  it('coerces a negative or absurd 1h count to 0 — the clamp covers the new arg too', () => {
    expect(priceMicros('claude-sonnet-4-6', 0, 0, 0, 0, -1_000_000).costMicros).toBe(0);
    expect(priceMicros('claude-sonnet-4-6', 0, 0, 0, 0, Number.MAX_VALUE).costMicros).toBe(0);
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
    expect(MODEL_PRICES['claude-sonnet-4-6']).toEqual({
      inputMicrosPer1K: 3_000,
      outputMicrosPer1K: 15_000,
      cacheWriteMicrosPer1K: 3_750,
      cacheWrite1hMicrosPer1K: 6_000,
      cacheReadMicrosPer1K: 300,
    });
    expect(MODEL_PRICES['claude-haiku-4-5-20251001']).toEqual({
      inputMicrosPer1K: 1_000,
      outputMicrosPer1K: 5_000,
      cacheWriteMicrosPer1K: 1_250,
      cacheWrite1hMicrosPer1K: 2_000,
      cacheReadMicrosPer1K: 100,
    });
  });

  it('holds the published cache multipliers as a ratio on every row, not just on one', () => {
    // Anthropic publishes cache pricing as a MULTIPLIER of the base input rate
    // (5-minute write 1.25x, 1-hour write 2x, read 0.1x), so the relationship —
    // not just the absolute figure — is the thing to pin. A future model row
    // added with a hand-typed cache rate that does not hold the ratio fails here.
    for (const [model, price] of Object.entries(MODEL_PRICES)) {
      expect(price.cacheWriteMicrosPer1K, `${model} cache write 5m`).toBe(price.inputMicrosPer1K * 1.25);
      expect(price.cacheWrite1hMicrosPer1K, `${model} cache write 1h`).toBe(price.inputMicrosPer1K * 2);
      expect(price.cacheReadMicrosPer1K, `${model} cache read`).toBe(price.inputMicrosPer1K * 0.1);
    }
  });

  it('is frozen at the table AND the row level, so no importer can zero a rate at runtime', () => {
    // WR-10. `const` binds the reference, not the contents. An importer running
    // MODEL_PRICES['claude-sonnet-4-6'].outputMicrosPer1K = 0 would silently
    // zero the cost side of every subsequent meter, and the shape tests above —
    // which read the object at test time — would never observe it.
    expect(Object.isFrozen(MODEL_PRICES)).toBe(true);
    for (const [model, price] of Object.entries(MODEL_PRICES)) {
      expect(Object.isFrozen(price), `${model} row`).toBe(true);
    }

    // Test files are ESM and therefore strict mode: a write to a frozen
    // property throws rather than failing silently.
    const row = MODEL_PRICES['claude-sonnet-4-6'] as ModelPrice;
    expect(() => {
      (row as { outputMicrosPer1K: number }).outputMicrosPer1K = 0;
    }).toThrow(TypeError);
    expect(MODEL_PRICES['claude-sonnet-4-6'].outputMicrosPer1K).toBe(15_000);

    // Adding a row at runtime is refused the same way.
    expect(() => {
      (MODEL_PRICES as Record<string, ModelPrice>)['claude-opus-4-8'] = {
        inputMicrosPer1K: 0,
        outputMicrosPer1K: 0,
        cacheWriteMicrosPer1K: 0,
        cacheWrite1hMicrosPer1K: 0,
        cacheReadMicrosPer1K: 0,
      };
    }).toThrow(TypeError);
    expect(Object.keys(MODEL_PRICES)).toHaveLength(2);
  });
});
