import { describe, it, expect } from 'vitest';
import { getDb } from '../src/db/client.js';
import { loadConfig } from '../src/config.js';
import { appendAudit } from '../src/audit/writer.js';
import { auditRecords } from '../src/db/schema.js';
import { eq } from 'drizzle-orm';
import type { AuditRecord } from '../src/audit/record.js';

const cfg = loadConfig(process.env);
function mk(verdict: 'allow' | 'deny'): AuditRecord {
  return {
    id: crypto.randomUUID(), ts: new Date().toISOString(), tenant: 'test', plane: 'mcp',
    who: { agentId: 'a', identity: { agent: 'a', onBehalfOf: [] } },
    what: { target: 'mcp:fs', operation: 'read', argsDigest: 'a'.repeat(64) },
    whenWhere: { origin: 'test', correlationId: crypto.randomUUID() },
    why: { reason: 'unit' }, verdict, policyVersion: 'v1', subjectKeyId: null,
  };
}

describe('appendAudit', () => {
  it('appends allow + deny and links prev/curr hashes', async () => {
    const { db, sql } = getDb(cfg);
    const r1 = await appendAudit(db, cfg, mk('allow'));
    const r2 = await appendAudit(db, cfg, mk('deny'));
    const [row2] = await db.select().from(auditRecords).where(eq(auditRecords.seq, r2.seq)).limit(1);
    expect(row2.prevHash).toBe(r1.hash);
    expect(row2.verdict).toBe('deny'); // denies logged same as allows
    await sql.end();
  });
  it('DB blocks UPDATE and DELETE on audit_records', async () => {
    const { sql } = getDb(cfg);
    await expect(sql`update audit_records set verdict='allow' where verdict='deny'`).rejects.toThrow();
    await expect(sql`delete from audit_records`).rejects.toThrow();
    await sql.end();
  });
  // Regression: TRUNCATE fires no row-level trigger, so the UPDATE/DELETE trigger above
  // never saw it. The test connection is the table owner, so only a statement-level
  // BEFORE TRUNCATE trigger can be what raises here.
  it('DB blocks TRUNCATE on audit_records and chain_head, and the rows survive', async () => {
    const { db, sql } = getDb(cfg);
    await appendAudit(db, cfg, mk('allow'));
    const count = async () => {
      const [a] = await sql`select count(*)::int as n from audit_records`;
      const [h] = await sql`select count(*)::int as n from chain_head`;
      return { audit: a.n as number, head: h.n as number };
    };
    const before = await count();
    await expect(sql`truncate audit_records`).rejects.toThrow(/audit_records is append-only \(TRUNCATE\)/);
    await expect(sql`truncate chain_head`).rejects.toThrow(/chain_head is append-only \(TRUNCATE\)/);
    await expect(sql`truncate audit_records, chain_head`).rejects.toThrow(/append-only \(TRUNCATE\)/);
    await expect(sql`truncate audit_records cascade`).rejects.toThrow(/append-only \(TRUNCATE\)/);
    expect(before.audit).toBeGreaterThan(0);
    expect(await count()).toEqual(before);
    await sql.end();
  });
});
