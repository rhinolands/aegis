import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import postgres, { type Sql, type TransactionSql } from 'postgres';
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

// Every test here tampers with (or depends on the exact shape of) the single global
// chain, so each one starts from an empty chain and the file leaves an empty chain
// behind. Without this, a tampered row left by one test breaks verifyChain() for every
// later test file and for the next local run.
// max: 1 because the script carries its own BEGIN/COMMIT, which postgres.js only allows
// on a single-connection client.
async function resetChain(): Promise<void> {
  const sql = postgres(cfg.databaseUrl, { max: 1 });
  await sql.file('scripts/reset-dev-chain.sql');
  await sql.end();
}

// Simulate an attacker holding owner DB credentials: disable the append-only triggers,
// mutate, re-enable. One transaction: DDL is transactional, so the disabled-trigger
// state is never committed/visible to other sessions.
async function asOwner(sql: Sql, mutate: (tx: TransactionSql) => Promise<unknown>): Promise<void> {
  await sql.begin(async (tx) => {
    await tx`alter table audit_records disable trigger user`;
    await tx`alter table chain_head disable trigger user`;
    await mutate(tx);
    await tx`alter table audit_records enable trigger user`;
    await tx`alter table chain_head enable trigger user`;
  });
}

describe('verifyChain', () => {
  beforeEach(resetChain);
  afterAll(resetChain);

  it('passes on an untampered chain', async () => {
    const { db, sql } = getDb(cfg);
    await appendAudit(db, cfg, mk()); await appendAudit(db, cfg, mk());
    const res = await verifyChain(db);
    expect(res).toEqual({ ok: true, checked: 2 });
    await sql.end();
  });

  it('passes on a chain that has never been written (no rows, no head)', async () => {
    const { db, sql } = getDb(cfg);
    expect(await verifyChain(db)).toEqual({ ok: true, checked: 0 });
    await sql.end();
  });

  it('detects a tampered row', async () => {
    const { db, sql } = getDb(cfg);
    const { seq } = await appendAudit(db, cfg, mk());
    await asOwner(sql, (tx) => tx`update audit_records set verdict='deny' where seq=${seq}`);
    const res = await verifyChain(db);
    expect(res.ok).toBe(false);
    expect(res.reason).toContain('hash mismatch');
    await sql.end();
  });

  it('detects a deleted mid-chain row', async () => {
    const { db, sql } = getDb(cfg);
    await appendAudit(db, cfg, mk());
    const { seq: middle } = await appendAudit(db, cfg, mk());
    const { seq: last } = await appendAudit(db, cfg, mk());
    await asOwner(sql, (tx) => tx`delete from audit_records where seq=${middle}`);
    const res = await verifyChain(db);
    expect(res.ok).toBe(false);
    expect(res.brokenAtSeq).toBe(last);
    expect(res.reason).toContain('prevHash mismatch');
    await sql.end();
  });

  // Regression: deleting the LAST row leaves every remaining link intact, so a replay
  // that never looks at chain_head reports ok:true. The head still names the deleted seq.
  it('detects a deleted last row (tail truncation) by comparing against chain_head', async () => {
    const { db, sql } = getDb(cfg);
    await appendAudit(db, cfg, mk());
    const { seq: kept } = await appendAudit(db, cfg, mk());
    const { seq: deleted } = await appendAudit(db, cfg, mk());
    await asOwner(sql, (tx) => tx`delete from audit_records where seq=${deleted}`);
    const res = await verifyChain(db);
    expect(res.ok).toBe(false);
    expect(res.checked).toBe(2);
    expect(res.brokenAtSeq).toBe(deleted);
    expect(res.reason).toBe(`tail truncated: chain_head seq ${deleted}, last row ${kept}`);
    await sql.end();
  });

  // Regression: an emptied audit table used to verify as { ok: true, checked: 0 }.
  it('detects a fully truncated audit table when chain_head still holds a head', async () => {
    const { db, sql } = getDb(cfg);
    await appendAudit(db, cfg, mk());
    const { seq: head } = await appendAudit(db, cfg, mk());
    await asOwner(sql, (tx) => tx`truncate audit_records`);
    const res = await verifyChain(db);
    expect(res.ok).toBe(false);
    expect(res.checked).toBe(0);
    expect(res.brokenAtSeq).toBe(head);
    expect(res.reason).toBe(`chain truncated: chain_head seq ${head}, audit_records is empty`);
    await sql.end();
  });

  it('detects a removed chain_head while audit rows exist', async () => {
    const { db, sql } = getDb(cfg);
    await appendAudit(db, cfg, mk());
    const { seq: last } = await appendAudit(db, cfg, mk());
    await asOwner(sql, (tx) => tx`delete from chain_head`);
    const res = await verifyChain(db);
    expect(res.ok).toBe(false);
    expect(res.brokenAtSeq).toBe(last);
    expect(res.reason).toBe(`chain_head missing: last row ${last} has no recorded head`);
    await sql.end();
  });

  it('detects a chain_head that points behind the last row', async () => {
    const { db, sql } = getDb(cfg);
    const first = await appendAudit(db, cfg, mk());
    const { seq: last } = await appendAudit(db, cfg, mk());
    await asOwner(sql, (tx) => tx`update chain_head set seq=${first.seq}, hash=${first.hash}`);
    const res = await verifyChain(db);
    expect(res.ok).toBe(false);
    expect(res.brokenAtSeq).toBe(last);
    expect(res.reason).toBe(`chain_head stale: chain_head seq ${first.seq}, last row ${last}`);
    await sql.end();
  });

  it('detects a chain_head whose hash does not match the last row', async () => {
    const { db, sql } = getDb(cfg);
    const { seq: last } = await appendAudit(db, cfg, mk());
    await asOwner(sql, (tx) => tx`update chain_head set hash=${'f'.repeat(64)}`);
    const res = await verifyChain(db);
    expect(res.ok).toBe(false);
    expect(res.brokenAtSeq).toBe(last);
    expect(res.reason).toBe(`chain_head hash mismatch at seq ${last}`);
    await sql.end();
  });
});
