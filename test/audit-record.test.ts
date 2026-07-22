import { describe, it, expect } from 'vitest';
import { canonical, argsDigest } from '../src/audit/record.js';

describe('canonical', () => {
  it('is stable regardless of key order', () => {
    const a = canonical({ b: 2, a: 1, nested: { y: 1, x: 2 } });
    const b = canonical({ a: 1, nested: { x: 2, y: 1 }, b: 2 });
    expect(a).toBe(b);
  });
  it('argsDigest is deterministic and never echoes raw args', () => {
    const d1 = argsDigest({ path: '/etc/hosts', mode: 'r' });
    const d2 = argsDigest({ mode: 'r', path: '/etc/hosts' });
    expect(d1).toBe(d2);
    expect(d1).toMatch(/^[0-9a-f]{64}$/);
    expect(d1).not.toContain('/etc/hosts');
  });

  // Regression pin: this exact string must never change for a plain, already-serializable
  // input. The audit hash chain (audit/chain.ts) hashes canonical() output directly, so
  // any future change to the serializer that alters this string invalidates every
  // previously-written audit record's hash. If this test ever needs to change, that is a
  // breaking change to the hash chain and must be treated as such, not a routine update.
  it('canonical output for a plain object is pinned (hash-chain stability regression guard)', () => {
    const out = canonical({ b: 2, a: 1, nested: { y: 1, x: 2 } });
    expect(out).toBe('{"a":1,"b":2,"nested":{"x":2,"y":1}}');
  });

  it('does not throw on a BigInt value, and is deterministic', () => {
    const out1 = canonical({ amount: 10n });
    const out2 = canonical({ amount: 10n });
    expect(() => canonical({ amount: 10n })).not.toThrow();
    expect(out1).toBe(out2);
    expect(out1).toBe('{"amount":{"$type":"bigint","value":"10"}}');
  });

  it('argsDigest with a BigInt value does not throw, is deterministic, and is a stable 64-hex digest', () => {
    let d1 = '';
    let d2 = '';
    expect(() => { d1 = argsDigest({ amount: 10n }); }).not.toThrow();
    expect(() => { d2 = argsDigest({ amount: 10n }); }).not.toThrow();
    expect(d1).toBe(d2);
    expect(d1).toMatch(/^[0-9a-f]{64}$/);
  });

  it('does not throw on a circular object, and is deterministic', () => {
    const obj: Record<string, unknown> = { a: 1 };
    obj.self = obj;
    let out1 = '';
    let out2 = '';
    expect(() => { out1 = canonical(obj); }).not.toThrow();
    expect(() => { out2 = canonical(obj); }).not.toThrow();
    expect(out1).toBe(out2);
    expect(out1).toBe('{"a":1,"self":"[Circular]"}');
  });

  it('argsDigest with a circular object does not throw and is deterministic', () => {
    const obj: Record<string, unknown> = { a: 1 };
    obj.self = obj;
    let d1 = '';
    let d2 = '';
    expect(() => { d1 = argsDigest(obj); }).not.toThrow();
    expect(() => { d2 = argsDigest(obj); }).not.toThrow();
    expect(d1).toBe(d2);
    expect(d1).toMatch(/^[0-9a-f]{64}$/);
  });

  // Fix round 3: intrinsic totality hazards — throwing accessors, hostile proxies,
  // and unbounded depth. Each of these must not throw, and must be deterministic
  // across two independent calls (not merely "didn't throw once").

  it('does not throw on an object with a throwing getter, and is deterministic', () => {
    const obj = {
      a: 1,
      get boom(): number {
        throw new Error('getter blew up');
      },
    };
    let out1 = '';
    let out2 = '';
    let d1 = '';
    let d2 = '';
    expect(() => { out1 = canonical(obj); }).not.toThrow();
    expect(() => { out2 = canonical(obj); }).not.toThrow();
    expect(() => { d1 = argsDigest(obj); }).not.toThrow();
    expect(() => { d2 = argsDigest(obj); }).not.toThrow();
    expect(out1).toBe(out2);
    expect(d1).toBe(d2);
    expect(out1).toBe('{"a":1,"boom":{"$type":"unserializable"}}');
  });

  it('does not throw on a Proxy with a throwing get trap, and is deterministic', () => {
    const proxy = new Proxy(
      { a: 1, b: 2 },
      {
        get(): never {
          throw new Error('get trap blew up');
        },
      },
    );
    let out1 = '';
    let out2 = '';
    let d1 = '';
    let d2 = '';
    expect(() => { out1 = canonical(proxy); }).not.toThrow();
    expect(() => { out2 = canonical(proxy); }).not.toThrow();
    expect(() => { d1 = argsDigest(proxy); }).not.toThrow();
    expect(() => { d2 = argsDigest(proxy); }).not.toThrow();
    expect(out1).toBe(out2);
    expect(d1).toBe(d2);
    // ownKeys is untrapped here so keys enumerate fine; every value read throws,
    // so each key gets its own unserializable marker.
    expect(out1).toBe('{"a":{"$type":"unserializable"},"b":{"$type":"unserializable"}}');
  });

  it('does not throw on a Proxy with a throwing ownKeys trap, and is deterministic', () => {
    const proxy = new Proxy(
      { a: 1, b: 2 },
      {
        ownKeys(): never {
          throw new Error('ownKeys trap blew up');
        },
      },
    );
    let out1 = '';
    let out2 = '';
    let d1 = '';
    let d2 = '';
    expect(() => { out1 = canonical(proxy); }).not.toThrow();
    expect(() => { out2 = canonical(proxy); }).not.toThrow();
    expect(() => { d1 = argsDigest(proxy); }).not.toThrow();
    expect(() => { d2 = argsDigest(proxy); }).not.toThrow();
    expect(out1).toBe(out2);
    expect(d1).toBe(d2);
    expect(out1).toBe('{"$type":"unserializable"}');
  });

  it('does not throw (no RangeError) on a ~200k-deep nested object, and is deterministic', () => {
    const DEPTH = 200_000;
    let deep: Record<string, unknown> = { leaf: true };
    for (let i = 0; i < DEPTH; i++) {
      deep = { next: deep };
    }
    let out1 = '';
    let out2 = '';
    let d1 = '';
    let d2 = '';
    expect(() => { out1 = canonical(deep); }).not.toThrow();
    expect(() => { out2 = canonical(deep); }).not.toThrow();
    expect(() => { d1 = argsDigest(deep); }).not.toThrow();
    expect(() => { d2 = argsDigest(deep); }).not.toThrow();
    expect(out1).toBe(out2);
    expect(d1).toBe(d2);
    expect(d1).toMatch(/^[0-9a-f]{64}$/);
  });
});
