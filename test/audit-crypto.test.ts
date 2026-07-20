import { describe, it, expect } from 'vitest';
import { encryptPayload, decryptPayload } from '../src/audit/crypto.js';
import { randomBytes } from 'node:crypto';

describe('crypto-shred payload', () => {
  it('round-trips with the subject key', () => {
    const key = randomBytes(32);
    const ct = encryptPayload(key, JSON.stringify({ path: '/etc/hosts' }));
    expect(ct).not.toContain('/etc/hosts');
    expect(decryptPayload(key, ct)).toBe(JSON.stringify({ path: '/etc/hosts' }));
  });
  it('fails to decrypt with a different key (shred simulation)', () => {
    const ct = encryptPayload(randomBytes(32), 'secret');
    expect(() => decryptPayload(randomBytes(32), ct)).toThrow();
  });
});
