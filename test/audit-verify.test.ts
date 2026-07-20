import { describe, it, expect } from 'vitest';
import { getDb } from '../src/db/client.js';
import { loadConfig } from '../src/config.js';
import { appendAudit } from '../src/audit/writer.js';
import { verifyChain } from '../src/audit/verify.js';
import type { AuditRecord } from '../src/audit/record.js';

const cfg = loadConfig(process.env);
const mk = (): AuditRecord => ({
  id: crypto.randomUUID(), ts: new Date().toISOString(), tenant: 'verify', plane: 'llm',
  who: { agentId: 'a', identity: { agent: 'a', onBehalfOf: [] } },
  what: { target: 'llm:anthropic', operation: 'complete', argsDigest: 'b'.repeat(64) },
  whenWhere: { origin: 't', correlationId: crypto.randomUUID() },
  why: { reason: 'unit' }, verdict: 'allow', policyVersion: 'v1', subjectKeyId: null,
});

describe('verifyChain', () => {
  it('passes on an untampered chain', async () => {
    const { db, sql } = getDb(cfg);
    await appendAudit(db, cfg, mk()); await appendAudit(db, cfg, mk());
    const res = await verifyChain(db);
    expect(res.ok).toBe(true);
    expect(res.checked).toBeGreaterThan(0);
    await sql.end();
  });

  it('detects a tampered row', async () => {
    const { db, sql } = getDb(cfg);
    const { seq } = await appendAudit(db, cfg, mk());
    // Simulate raw tamper (disable trigger, edit, re-enable) — an attacker with owner DB creds.
    // Wrapped in one transaction: DDL is transactional, so the disabled-trigger state is
    // never committed/visible to other sessions until this transaction re-enables the
    // trigger and commits — not lock-based reader blocking.
    await sql.begin(async (tx) => {
      await tx`alter table audit_records disable trigger trg_audit_no_mutate`;
      await tx`update audit_records set verdict='deny' where seq=${seq}`;
      await tx`alter table audit_records enable trigger trg_audit_no_mutate`;
    });
    const res = await verifyChain(db);
    expect(res.ok).toBe(false);
    expect(res.reason).toContain('hash mismatch');
    await sql.end();
  });
});
