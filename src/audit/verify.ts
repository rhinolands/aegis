import { asc } from 'drizzle-orm';
import type { DrizzleDb } from '../db/client.js';
import { auditRecords } from '../db/schema.js';
import { computeHash, GENESIS_HASH } from './chain.js';
import type { AuditRecord } from './record.js';

export async function verifyChain(
  db: DrizzleDb,
): Promise<{ ok: boolean; checked: number; brokenAtSeq?: number; reason?: string }> {
  const rows = await db.select().from(auditRecords).orderBy(asc(auditRecords.seq));
  let prevHash = GENESIS_HASH;
  let checked = 0;
  for (const row of rows) {
    if (row.prevHash !== prevHash) {
      return { ok: false, checked, brokenAtSeq: row.seq, reason: 'prevHash mismatch (row deleted or reordered)' };
    }
    const rec: AuditRecord = {
      id: row.id, ts: row.ts.toISOString(), tenant: row.tenant, plane: row.plane as AuditRecord['plane'],
      who: row.who as AuditRecord['who'], what: row.what as AuditRecord['what'],
      whenWhere: row.whenWhere as AuditRecord['whenWhere'], why: row.why as AuditRecord['why'],
      verdict: row.verdict as AuditRecord['verdict'], policyVersion: row.policyVersion,
      subjectKeyId: row.subjectKeyId,
    };
    const expected = computeHash(prevHash, rec);
    if (expected !== row.hash) {
      return { ok: false, checked, brokenAtSeq: row.seq, reason: 'hash mismatch (row edited)' };
    }
    prevHash = row.hash;
    checked++;
  }
  return { ok: true, checked };
}
