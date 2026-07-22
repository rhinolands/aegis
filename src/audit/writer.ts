import { eq } from 'drizzle-orm';
import type { DrizzleDb } from '../db/client.js';
import type { Config } from '../config.js';
import { auditRecords, chainHead } from '../db/schema.js';
import { canonical, type AuditRecord } from './record.js';
import { computeHash, GENESIS_HASH } from './chain.js';
import { getOrCreateSubjectKey, encryptPayload } from './crypto.js';

export async function appendAudit(
  db: DrizzleDb, cfg: Config, rec: AuditRecord, payload?: unknown,
): Promise<{ seq: number; hash: string }> {
  let payloadCiphertext: string | null = null;
  if (payload !== undefined && rec.subjectKeyId) {
    const key = await getOrCreateSubjectKey(db, cfg, rec.subjectKeyId);
    // Use canonical() (total serializer, see audit/record.ts), not a raw JSON.stringify:
    // `payload` here is ctx.args, the same caller-supplied raw tool arguments that made
    // argsDigest() unsafe before this fix round. A bare JSON.stringify(payload) has the
    // identical BigInt/circular throw hazard, just one level deeper — inside the very
    // appendAudit() call that govern.ts's allow/deny paths depend on never throwing.
    payloadCiphertext = encryptPayload(key, canonical(payload));
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
