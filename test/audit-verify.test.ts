import { describe, it, expect } from 'vitest';
import { sql as dsql } from 'drizzle-orm';
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
    await appendAudit(db, cfg, mk());
    // Simulate raw tamper (disable trigger, edit, re-enable) — an attacker with owner DB creds.
    // Wrapped in one transaction: ALTER TABLE ... TRIGGER takes an ACCESS EXCLUSIVE lock,
    // so concurrent test files (vitest runs files in parallel) block on this table rather
    // than observing a window where the trigger is disabled.
    await sql.begin(async (tx) => {
      await tx`alter table audit_records disable trigger trg_audit_no_mutate`;
      await tx`update audit_records set verdict='deny' where seq=(select max(seq) from audit_records)`;
      await tx`alter table audit_records enable trigger trg_audit_no_mutate`;
    });
    const res = await verifyChain(db);
    expect(res.ok).toBe(false);
    expect(res.reason).toContain('hash mismatch');
    await sql.end();
  });
});
