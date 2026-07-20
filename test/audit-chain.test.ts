import { describe, it, expect } from 'vitest';
import { computeHash, GENESIS_HASH } from '../src/audit/chain.js';
import type { AuditRecord } from '../src/audit/record.js';

const rec: AuditRecord = {
  id: '11111111-1111-1111-1111-111111111111', ts: '2026-07-20T00:00:00.000Z', tenant: 't',
  plane: 'mcp', who: { agentId: 'a', identity: { agent: 'a', onBehalfOf: [] } },
  what: { target: 'mcp:fs', operation: 'read', argsDigest: 'x'.repeat(64) },
  whenWhere: { origin: 'test', correlationId: 'c1' }, why: { reason: 'unit' },
  verdict: 'allow', policyVersion: 'v1', subjectKeyId: null,
};

describe('hash chain', () => {
  it('is deterministic', () => {
    expect(computeHash(GENESIS_HASH, rec)).toBe(computeHash(GENESIS_HASH, rec));
  });
  it('changes when any field changes', () => {
    const h1 = computeHash(GENESIS_HASH, rec);
    const h2 = computeHash(GENESIS_HASH, { ...rec, verdict: 'deny' });
    expect(h1).not.toBe(h2);
  });
  it('changes when prevHash changes', () => {
    expect(computeHash(GENESIS_HASH, rec)).not.toBe(computeHash('deadbeef', rec));
  });
});
