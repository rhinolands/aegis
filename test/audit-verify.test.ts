import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import { getDb } from '../src/db/client.js';
import { loadConfig } from '../src/config.js';
import { appendAudit } from '../src/audit/writer.js';
import { verifyChain } from '../src/audit/verify.js';
import { buildDayExport, readExportAnchor } from '../src/audit/export.js';
import { computeHash } from '../src/audit/chain.js';
import { mkdtemp, writeFile, appendFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, basename } from 'node:path';
import type { DrizzleDb } from '../src/db/client.js';
import { runVerify } from '../scripts/verify.js';
import type { AuditRecord } from '../src/audit/record.js';
import { resetChain as resetChainFor, asOwner } from './helpers/chain.js';

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
const resetChain = () => resetChainFor(cfg);

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

// The in-database check cannot see a rewrite that stays self-consistent: the hash is
// unkeyed and chain_head lives next to the rows. Each test below first shows the
// rewrite PASSING plain verifyChain() (the documented limit), then shows it caught
// once the chain is compared against an export taken before the rewrite.
describe('verifyChain against an exported manifest', () => {
  beforeEach(resetChain);
  afterAll(resetChain);

  // What an auditor holds: today's export, downloaded to a local directory.
  async function exportToDir(db: DrizzleDb): Promise<{ manifestPath: string; segmentPath: string; dir: string }> {
    const { segKey, segment, manifestKey, manifest } = await buildDayExport(db, new Date().toISOString().slice(0, 10));
    const dir = await mkdtemp(join(tmpdir(), 'aegis-export-'));
    const manifestPath = join(dir, basename(manifestKey));
    const segmentPath = join(dir, basename(segKey));
    await writeFile(segmentPath, segment);
    await writeFile(manifestPath, JSON.stringify(manifest, null, 2));
    return { manifestPath, segmentPath, dir };
  }

  it('passes when the live chain matches the export, and still passes once the chain grows past it', async () => {
    const { db, sql } = getDb(cfg);
    await appendAudit(db, cfg, mk());
    const { seq: exportedHead } = await appendAudit(db, cfg, mk());
    const { manifestPath, dir } = await exportToDir(db);
    const anchor = await readExportAnchor(manifestPath);
    expect(anchor.rows).toHaveLength(2);
    expect(await verifyChain(db, anchor)).toEqual({ ok: true, checked: 2, anchoredSeq: exportedHead });
    await appendAudit(db, cfg, mk());
    expect(await verifyChain(db, anchor)).toEqual({ ok: true, checked: 3, anchoredSeq: exportedHead });
    await rm(dir, { recursive: true });
    await sql.end();
  });

  it('catches an owner who deletes the tail AND rewrites chain_head to match', async () => {
    const { db, sql } = getDb(cfg);
    const kept = await appendAudit(db, cfg, mk());
    const { seq: deleted } = await appendAudit(db, cfg, mk());
    const { manifestPath, dir } = await exportToDir(db);
    await asOwner(sql, async (tx) => {
      await tx`delete from audit_records where seq=${deleted}`;
      await tx`update chain_head set seq=${kept.seq}, hash=${kept.hash}`;
    });
    expect(await verifyChain(db)).toEqual({ ok: true, checked: 1 }); // the in-database limit
    const res = await verifyChain(db, await readExportAnchor(manifestPath));
    expect(res.ok).toBe(false);
    expect(res.brokenAtSeq).toBe(deleted);
    expect(res.reason).toBe(`export mismatch: exported seq ${deleted} is missing from the live chain`);
    await rm(dir, { recursive: true });
    await sql.end();
  });

  it('catches an owner who empties both audit_records and chain_head', async () => {
    const { db, sql } = getDb(cfg);
    const { seq: first } = await appendAudit(db, cfg, mk());
    await appendAudit(db, cfg, mk());
    const { manifestPath, dir } = await exportToDir(db);
    await asOwner(sql, (tx) => tx`truncate audit_records, chain_head`);
    expect(await verifyChain(db)).toEqual({ ok: true, checked: 0 }); // the in-database limit
    const res = await verifyChain(db, await readExportAnchor(manifestPath));
    expect(res.ok).toBe(false);
    expect(res.brokenAtSeq).toBe(first);
    expect(res.reason).toBe(`export mismatch: exported seq ${first} is missing from the live chain`);
    await rm(dir, { recursive: true });
    await sql.end();
  });

  it('catches an owner who edits a row and recomputes its hash and chain_head', async () => {
    const { db, sql } = getDb(cfg);
    const first = await appendAudit(db, cfg, mk());
    const rec = mk();
    const { seq: edited } = await appendAudit(db, cfg, rec);
    const { manifestPath, dir } = await exportToDir(db);
    const forged = computeHash(first.hash, { ...rec, verdict: 'deny' });
    await asOwner(sql, async (tx) => {
      await tx`update audit_records set verdict='deny', hash=${forged} where seq=${edited}`;
      await tx`update chain_head set hash=${forged}`;
    });
    expect(await verifyChain(db)).toEqual({ ok: true, checked: 2 }); // the in-database limit
    const res = await verifyChain(db, await readExportAnchor(manifestPath));
    expect(res.ok).toBe(false);
    expect(res.brokenAtSeq).toBe(edited);
    expect(res.reason).toBe(`export mismatch: hash differs at exported seq ${edited}`);
    await rm(dir, { recursive: true });
    await sql.end();
  });

  it('checks the exported chain head even when it lies outside the exported rows', async () => {
    const { db, sql } = getDb(cfg);
    const { seq: head, hash } = await appendAudit(db, cfg, mk());
    const elsewhere = { chainHead: { seq: head, hash: 'f'.repeat(64) }, rows: [] };
    const res = await verifyChain(db, elsewhere);
    expect(res.ok).toBe(false);
    expect(res.reason).toBe(`export mismatch: hash differs at exported chain head seq ${head}`);
    expect(await verifyChain(db, { chainHead: { seq: head + 1, hash }, rows: [] })).toMatchObject({
      ok: false, reason: `export mismatch: exported chain head seq ${head + 1} is missing from the live chain`,
    });
    await sql.end();
  });

  it('CLI: --manifest feeds the export into verification and drives the exit code', async () => {
    const { db, sql } = getDb(cfg);
    const kept = await appendAudit(db, cfg, mk());
    const { seq: deleted } = await appendAudit(db, cfg, mk());
    const { manifestPath, dir } = await exportToDir(db);
    expect(await runVerify(db, ['--manifest', manifestPath])).toEqual({
      exitCode: 0, output: JSON.stringify({ ok: true, checked: 2, anchoredSeq: deleted }),
    });
    await asOwner(sql, async (tx) => {
      await tx`delete from audit_records where seq=${deleted}`;
      await tx`update chain_head set seq=${kept.seq}, hash=${kept.hash}`;
    });
    expect((await runVerify(db, [])).exitCode).toBe(0); // the in-database limit
    const res = await runVerify(db, ['--manifest', manifestPath]);
    expect(res.exitCode).toBe(1);
    expect(JSON.parse(res.output).reason).toContain('export mismatch');
    // Usage and unusable-export errors are exit 2, never a pass.
    expect((await runVerify(db, ['--manifest'])).exitCode).toBe(2);
    expect((await runVerify(db, ['--nope'])).exitCode).toBe(2);
    expect((await runVerify(db, ['--manifest', join(dir, 'absent.json')])).exitCode).toBe(2);
    await rm(dir, { recursive: true });
    await sql.end();
  });

  it('refuses an export whose segment was altered or removed after export', async () => {
    const { db, sql } = getDb(cfg);
    await appendAudit(db, cfg, mk());
    const { manifestPath, segmentPath, dir } = await exportToDir(db);
    await appendFile(segmentPath, '{"seq":999999,"hash":"x"}\n');
    await expect(readExportAnchor(manifestPath)).rejects.toThrow(/sha256 mismatch/);
    await rm(segmentPath);
    await expect(readExportAnchor(manifestPath)).rejects.toThrow(/segment not found/);
    await rm(dir, { recursive: true });
    await sql.end();
  });
});
