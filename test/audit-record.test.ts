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
});
