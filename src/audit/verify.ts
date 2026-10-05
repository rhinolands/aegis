import { asc, eq } from 'drizzle-orm';
import type { DrizzleDb } from '../db/client.js';
import { auditRecords, chainHead } from '../db/schema.js';
import { computeHash, GENESIS_HASH } from './chain.js';
import type { AuditRecord } from './record.js';

export interface VerifyResult {
  ok: boolean; checked: number; brokenAtSeq?: number; reason?: string;
  anchoredSeq?: number; // set when an export anchor was checked: the exported chain head seq
}

// What an export recorded about the chain at export time (see audit/export.ts,
// readExportAnchor): the chain head, plus seq and hash of every exported row.
export interface ExportAnchor {
  chainHead: { seq: number; hash: string } | null;
  rows: Array<{ seq: number; hash: string }>;
}

export async function verifyChain(db: DrizzleDb, anchor?: ExportAnchor): Promise<VerifyResult> {
  // Rows and head are read in ONE repeatable-read snapshot. Read separately, an
  // append that commits between the two reads would look like a tail mismatch.
  const { rows, head } = await db.transaction(
    async (tx) => {
      const rows = await tx.select().from(auditRecords).orderBy(asc(auditRecords.seq));
      const [head] = await tx.select().from(chainHead).where(eq(chainHead.id, 'head')).limit(1);
      return { rows, head };
    },
    { isolationLevel: 'repeatable read', accessMode: 'read only' },
  );

  const live = verifyLive(rows, head);
  if (!live.ok || !anchor) return live;
  return verifyAgainstExport(rows, anchor, live.checked);
}

type Row = typeof auditRecords.$inferSelect;
type Head = typeof chainHead.$inferSelect;

// The in-database check: every hash link, then the tail against chain_head.
function verifyLive(rows: Row[], head: Head | undefined): VerifyResult {
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

  // Tail check. Replaying the links above cannot see rows removed from the END of
  // the chain: every remaining link is still intact, and an emptied table has no
  // links to break. chain_head is advanced in the same transaction as every append
  // (audit/writer.ts), so the last row must be exactly the recorded head.
  const last = rows.at(-1);
  if (!last) {
    if (!head) return { ok: true, checked }; // never written: no rows, no head
    return {
      ok: false, checked, brokenAtSeq: head.seq,
      reason: `chain truncated: chain_head seq ${head.seq}, audit_records is empty`,
    };
  }
  if (!head) {
    return { ok: false, checked, brokenAtSeq: last.seq, reason: `chain_head missing: last row ${last.seq} has no recorded head` };
  }
  if (head.seq > last.seq) {
    return { ok: false, checked, brokenAtSeq: head.seq, reason: `tail truncated: chain_head seq ${head.seq}, last row ${last.seq}` };
  }
  if (head.seq < last.seq) {
    return { ok: false, checked, brokenAtSeq: last.seq, reason: `chain_head stale: chain_head seq ${head.seq}, last row ${last.seq}` };
  }
  if (head.hash !== last.hash) {
    return { ok: false, checked, brokenAtSeq: last.seq, reason: `chain_head hash mismatch at seq ${last.seq}` };
  }
  return { ok: true, checked };
}

// The external check. verifyLive() cannot see a rewrite that stays self-consistent:
// the hash is unkeyed and chain_head sits in the same database, so an owner can
// delete the tail and move the head, empty both tables, or edit a row and recompute
// every later hash. An export taken before the rewrite still holds the original
// seq/hash pairs. Every exported row and the exported chain head must be present in
// the live chain with the same hash. verifyLive() has already proven the live links
// from genesis to the live head, so a live chain that contains the exported head
// extends it.
function verifyAgainstExport(rows: Row[], anchor: ExportAnchor, checked: number): VerifyResult {
  const liveHash = new Map(rows.map((r) => [r.seq, r.hash]));
  const compare = (seq: number, hash: string, what: string): VerifyResult | undefined => {
    const found = liveHash.get(seq);
    if (found === undefined) {
      return { ok: false, checked, brokenAtSeq: seq, reason: `export mismatch: ${what} seq ${seq} is missing from the live chain` };
    }
    if (found !== hash) {
      return { ok: false, checked, brokenAtSeq: seq, reason: `export mismatch: hash differs at ${what} seq ${seq}` };
    }
    return undefined;
  };
  for (const exported of anchor.rows) {
    const broken = compare(exported.seq, exported.hash, 'exported');
    if (broken) return broken;
  }
  if (!anchor.chainHead) return { ok: true, checked };
  return compare(anchor.chainHead.seq, anchor.chainHead.hash, 'exported chain head')
    ?? { ok: true, checked, anchoredSeq: anchor.chainHead.seq };
}
