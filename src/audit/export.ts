import { createHash } from 'node:crypto';
import { and, gte, lt, asc, eq } from 'drizzle-orm';
import { PutObjectCommand, S3Client } from '@aws-sdk/client-s3';
import type { DrizzleDb } from '../db/client.js';
import type { Config } from '../config.js';
import { auditRecords, chainHead } from '../db/schema.js';

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
    forcePathStyle: true, // required for MinIO and other S3-compatible stores
    credentials: { accessKeyId: cfg.s3.accessKey, secretAccessKey: cfg.s3.secretKey },
  });
}

// Export all audit_records with ts in [day, day+1) to S3-compatible storage.
// dayIso = 'YYYY-MM-DD'. Rows are ordered by seq so the segment is deterministic
// and therefore its sha256 is stable across re-exports of the same day.
export async function exportDay(
  db: DrizzleDb,
  cfg: Config,
  dayIso: string,
  s3: S3Client = makeS3(cfg),
): Promise<{ objects: string[]; manifestKey: string; recordCount: number }> {
  const start = new Date(`${dayIso}T00:00:00.000Z`);
  const end = new Date(start.getTime() + 24 * 3600 * 1000);

  const rows = await db
    .select()
    .from(auditRecords)
    .where(and(gte(auditRecords.ts, start), lt(auditRecords.ts, end)))
    .orderBy(asc(auditRecords.seq));

  const segment = serializeSegment(rows as unknown as Array<Record<string, unknown>>);
  const segKey = `audit/${dayIso}/segment-000.jsonl`;
  await s3.send(new PutObjectCommand({ Bucket: cfg.s3.bucket, Key: segKey, Body: segment }));

  const [head] = await db.select().from(chainHead).where(eq(chainHead.id, 'head')).limit(1);
  const manifest = {
    day: dayIso,
    recordCount: rows.length,
    segments: [{ key: segKey, sha256: segmentSha256(segment) }],
    chainHead: head ? { seq: head.seq, hash: head.hash } : null,
    exportedFormat: 'jsonl',
  };
  const manifestKey = `audit/${dayIso}/manifest.json`;
  await s3.send(
    new PutObjectCommand({
      Bucket: cfg.s3.bucket,
      Key: manifestKey,
      Body: JSON.stringify(manifest, null, 2),
    }),
  );

  return { objects: [segKey], manifestKey, recordCount: rows.length };
}
