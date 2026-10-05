import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { basename, dirname, join } from 'node:path';
import { and, gte, lt, asc, eq } from 'drizzle-orm';
import { PutObjectCommand, S3Client } from '@aws-sdk/client-s3';
import type { DrizzleDb } from '../db/client.js';
import type { Config } from '../config.js';
import { auditRecords, chainHead } from '../db/schema.js';
import type { ExportAnchor } from './verify.js';

// Boring-on-purpose export format: plain JSONL segments + a sha256 manifest.
// Auditors reach for `grep`/`jq`, not a bespoke reader — see spec intent in
// task-16-brief.md. The manifest lets someone verify offline (no DB access)
// that a segment wasn't altered after export: recompute sha256 of the bytes
// they downloaded and compare to the recorded value.

export function serializeSegment(rows: Array<Record<string, unknown>>): string {
  if (rows.length === 0) return '';
  return rows.map((r) => JSON.stringify(r)).join('\n') + '\n';
}

export function segmentSha256(segment: string): string {
  return createHash('sha256').update(segment).digest('hex');
}

export function makeS3(cfg: Config): S3Client {
  return new S3Client({
    endpoint: cfg.s3.endpoint || undefined,
    region: cfg.s3.region,
    forcePathStyle: true, // path-style addressing, required by self-hosted S3-compatible stores
    credentials: { accessKeyId: cfg.s3.accessKey, secretAccessKey: cfg.s3.secretKey },
  });
}

export interface ExportManifest {
  day: string;
  recordCount: number;
  segments: Array<{ key: string; sha256: string }>;
  chainHead: { seq: number; hash: string } | null;
  exportedFormat: 'jsonl';
}

export interface DayExport { segKey: string; segment: string; manifestKey: string; manifest: ExportManifest }

// Build the segment and manifest for all audit_records with ts in [day, day+1).
// dayIso = 'YYYY-MM-DD'. Rows are ordered by seq so the segment is deterministic
// and therefore its sha256 is stable across re-exports of the same day. No I/O
// beyond the database read: exportDay() uploads the result, an operator can also
// write it to disk.
export async function buildDayExport(db: DrizzleDb, dayIso: string): Promise<DayExport> {
  const start = new Date(`${dayIso}T00:00:00.000Z`);
  const end = new Date(start.getTime() + 24 * 3600 * 1000);

  // One snapshot, so the recorded chain head can never be older than the rows
  // in the segment it is exported with.
  const { rows, head } = await db.transaction(
    async (tx) => {
      const rows = await tx
        .select()
        .from(auditRecords)
        .where(and(gte(auditRecords.ts, start), lt(auditRecords.ts, end)))
        .orderBy(asc(auditRecords.seq));
      const [head] = await tx.select().from(chainHead).where(eq(chainHead.id, 'head')).limit(1);
      return { rows, head };
    },
    { isolationLevel: 'repeatable read', accessMode: 'read only' },
  );

  const segment = serializeSegment(rows as unknown as Array<Record<string, unknown>>);
  const segKey = `audit/${dayIso}/segment-000.jsonl`;
  const manifest: ExportManifest = {
    day: dayIso,
    recordCount: rows.length,
    segments: [{ key: segKey, sha256: segmentSha256(segment) }],
    chainHead: head ? { seq: head.seq, hash: head.hash } : null,
    exportedFormat: 'jsonl',
  };
  return { segKey, segment, manifestKey: `audit/${dayIso}/manifest.json`, manifest };
}

// Export one day to S3-compatible storage.
export async function exportDay(
  db: DrizzleDb,
  cfg: Config,
  dayIso: string,
  s3: S3Client = makeS3(cfg),
): Promise<{ objects: string[]; manifestKey: string; recordCount: number }> {
  const { segKey, segment, manifestKey, manifest } = await buildDayExport(db, dayIso);
  await s3.send(new PutObjectCommand({ Bucket: cfg.s3.bucket, Key: segKey, Body: segment }));
  await s3.send(
    new PutObjectCommand({
      Bucket: cfg.s3.bucket,
      Key: manifestKey,
      Body: JSON.stringify(manifest, null, 2),
    }),
  );

  return { objects: [segKey], manifestKey, recordCount: manifest.recordCount };
}

// Read a downloaded export back as an anchor for verifyChain(). Offline: no S3
// call, only local files. Each segment the manifest lists must sit next to the
// manifest file under its base name (the layout of a downloaded audit/<day>/
// prefix), and its bytes must still match the sha256 the manifest recorded.
// Throws if a segment is missing or was altered after export: an export that
// does not verify against its own manifest is not usable as an anchor.
export async function readExportAnchor(manifestPath: string): Promise<ExportAnchor> {
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8')) as ExportManifest;
  const rows: ExportAnchor['rows'] = [];
  for (const seg of manifest.segments) {
    const segPath = join(dirname(manifestPath), basename(seg.key));
    let body: string;
    try {
      body = await readFile(segPath, 'utf8');
    } catch {
      throw new Error(`export segment not found next to the manifest: ${segPath}`);
    }
    if (segmentSha256(body) !== seg.sha256) {
      throw new Error(`export segment sha256 mismatch (altered after export): ${segPath}`);
    }
    for (const line of body.split('\n')) {
      if (line.length === 0) continue;
      const r = JSON.parse(line) as { seq: number; hash: string };
      rows.push({ seq: Number(r.seq), hash: r.hash });
    }
  }
  if (rows.length !== manifest.recordCount) {
    throw new Error(`export recordCount mismatch: manifest says ${manifest.recordCount}, segments hold ${rows.length}`);
  }
  return { chainHead: manifest.chainHead, rows };
}
