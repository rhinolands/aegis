import { eq } from 'drizzle-orm';
import type { DrizzleDb } from '../db/client.js';
import type { Config } from '../config.js';
import { auditRecords, chainHead } from '../db/schema.js';
import type { AuditRecord } from './record.js';
import { computeHash, GENESIS_HASH } from './chain.js';
import { getOrCreateSubjectKey, encryptPayload } from './crypto.js';

export async function appendAudit(
  db: DrizzleDb, cfg: Config, rec: AuditRecord, payload?: unknown,
): Promise<{ seq: number; hash: string }> {
  let payloadCiphertext: string | null = null;
  if (payload !== undefined && rec.subjectKeyId) {
    const key = await getOrCreateSubjectKey(db, cfg, rec.subjectKeyId);
    payloadCiphertext = encryptPayload(key, JSON.stringify(payload));
  }

  return db.transaction(async (tx) => {
    // Serialize head advance: lock the single head row FOR UPDATE.
    const [head] = await tx.select().from(chainHead).where(eq(chainHead.id, 'head')).for('update').limit(1);
    const prevHash = head?.hash ?? GENESIS_HASH;
    const hash = computeHash(prevHash, rec);

    const [inserted] = await tx.insert(auditRecords).values({
      id: rec.id, ts: new Date(rec.ts), tenant: rec.tenant, plane: rec.plane,
      subjectKeyId: rec.subjectKeyId, who: rec.who, what: rec.what, whenWhere: rec.whenWhere,
      why: rec.why, verdict: rec.verdict, policyVersion: rec.policyVersion,
      payloadCiphertext, prevHash, hash,
    }).returning({ seq: auditRecords.seq });

    if (head) {
      await tx.update(chainHead).set({ seq: inserted.seq, hash }).where(eq(chainHead.id, 'head'));
    } else {
      await tx.insert(chainHead).values({ id: 'head', seq: inserted.seq, hash });
    }
    return { seq: inserted.seq, hash };
  });
}
