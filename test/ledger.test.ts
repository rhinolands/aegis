import { describe, it, expect } from 'vitest';
import { formatRow, HEADER, type LedgerRow } from '../scripts/ledger.js';

// Pure-function tests for the operator ledger's row->line rendering: no DB, no
// network, no server. They prove the read is LEGIBLE for both an allow and a
// deny (deny reasons are the operator's primary signal) and that the encrypted
// payload can never leak through the formatter — even when handed a row that
// carries a ciphertext value alongside the metadata.

const ALLOW_ROW: LedgerRow = {
  seq: 27,
  ts: new Date('2026-08-15T10:00:00.000Z'),
  tenant: 'acme',
  plane: 'mcp',
  verdict: 'allow',
  who: { agentId: 'acme-advisor', identity: { agent: 'acme-advisor', onBehalfOf: [] } },
  what: { target: 'mcp:acme.advisor.lookup_rule', operation: 'invoke', argsDigest: 'abc123' },
  whenWhere: { origin: 'acme', correlationId: '5a96cc44-0000-0000-0000-000000000001' },
  why: { reason: 'tool-allowlisted' },
};

const DENY_ROW: LedgerRow = {
  seq: 32,
  ts: new Date('2026-08-15T10:00:05.000Z'),
  tenant: 'acme',
  plane: 'mcp',
  verdict: 'deny',
  who: { agentId: 'acme-advisor', identity: { agent: 'acme-advisor', onBehalfOf: [] } },
  what: { target: 'mcp:acme.admin.delete_tenant', operation: 'invoke', argsDigest: 'def456' },
  whenWhere: { origin: 'acme', correlationId: '5a96cc44-0000-0000-0000-000000000001' },
  why: { reason: 'deny-by-default' },
};

describe('formatRow — legible allow + deny rendering', () => {
  it('renders an ALLOW row with agent, target, operation, verdict and reason', () => {
    const line = formatRow(ALLOW_ROW);
    expect(line).toContain('acme-advisor');
    expect(line).toContain('mcp:acme.advisor.lookup_rule');
    expect(line).toContain('invoke');
    expect(line).toContain('allow');
    expect(line).toContain('tool-allowlisted');
    // correlation id is present so the line can be eyeball-joined with Acme's side
    expect(line).toContain('5a96cc44-0000-0000-0000-000000000001');
    // pipe-joined, one physical line
    expect(line.split('|')).toHaveLength(HEADER.split('|').length);
    expect(line).not.toContain('\n');
  });

  it('renders a DENY row surfacing the deny reason (the operator signal)', () => {
    const line = formatRow(DENY_ROW);
    expect(line).toContain('deny');
    expect(line).toContain('deny-by-default');
    expect(line).toContain('mcp:acme.admin.delete_tenant');
  });
});

describe('formatRow — the encrypted payload never leaks', () => {
  it('emits NONE of the ciphertext bytes even when the row carries one', () => {
    const secret = 'ENCRYPTED-PAYLOAD-DO-NOT-LEAK-9f8e7d6c5b4a';
    // A hostile/loose row shape carrying an extra ciphertext field alongside the
    // legitimate metadata. formatRow must project metadata ONLY.
    const rowWithCiphertext = {
      ...ALLOW_ROW,
      payloadCiphertext: secret,
    } as LedgerRow & { payloadCiphertext: string };

    const line = formatRow(rowWithCiphertext);
    expect(line).not.toContain(secret);
    expect(line).not.toContain('ENCRYPTED-PAYLOAD');
    // sanity: it still rendered the legible metadata
    expect(line).toContain('tool-allowlisted');
  });
});
