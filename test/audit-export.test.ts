import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import {
  S3Client,
  CreateBucketCommand,
  GetObjectCommand,
  HeadBucketCommand,
} from '@aws-sdk/client-s3';
import { serializeSegment, segmentSha256, makeS3, exportDay } from '../src/audit/export.js';
import { getDb } from '../src/db/client.js';
import { loadConfig } from '../src/config.js';
import { appendAudit } from '../src/audit/writer.js';
import { chainHead } from '../src/db/schema.js';
import { eq } from 'drizzle-orm';
import type { AuditRecord } from '../src/audit/record.js';

const rows = [
  { seq: 1, id: 'a', verdict: 'allow', hash: 'h1' },
  { seq: 2, id: 'b', verdict: 'deny', hash: 'h2' },
];

describe('export serialization', () => {
  it('emits one JSON object per line (JSONL)', () => {
    const s = serializeSegment(rows as any);
    const lines = s.trimEnd().split('\n');
    expect(lines).toHaveLength(2);
    expect(JSON.parse(lines[1]).verdict).toBe('deny');
  });

  it('ends with a trailing newline', () => {
    const s = serializeSegment(rows as any);
    expect(s.endsWith('\n')).toBe(true);
  });

  it('sha256 is stable for identical content', () => {
    expect(segmentSha256(serializeSegment(rows as any))).toBe(segmentSha256(serializeSegment(rows as any)));
  });

  it('sha256 differs when content changes', () => {
    const changed = [...rows, { seq: 3, id: 'c', verdict: 'allow', hash: 'h3' }];
    expect(segmentSha256(serializeSegment(rows as any))).not.toBe(segmentSha256(serializeSegment(changed as any)));
  });
});

// --- Integration: real MinIO round-trip -----------------------------------
// Guarded to SKIP cleanly if MinIO is unreachable, but genuinely exercises
// exportDay -> S3 PutObject -> read-back -> sha256 verification when it is.
describe('exportDay against MinIO', () => {
  const cfg = loadConfig(process.env);
  let minioUp = true;
  let s3: S3Client;

  beforeAll(async () => {
    s3 = makeS3(cfg);
    try {
      await s3.send(new HeadBucketCommand({ Bucket: cfg.s3.bucket }));
    } catch (err: any) {
      // Bucket missing is fine — we create it. Connection refused etc means MinIO is down.
      if (err?.name === 'NotFound' || err?.$metadata?.httpStatusCode === 404) {
        try {
          await s3.send(new CreateBucketCommand({ Bucket: cfg.s3.bucket }));
        } catch (createErr) {
          minioUp = false;
        }
      } else if (err?.Code === 'NoSuchBucket') {
        await s3.send(new CreateBucketCommand({ Bucket: cfg.s3.bucket }));
      } else {
        minioUp = false;
      }
    }
  }, 15_000);

  it('exports today\'s audit records and the objects verify byte-for-byte in MinIO', async () => {
    if (!minioUp) {
      console.warn('[audit-export] MinIO unreachable at', cfg.s3.endpoint, '- skipping integration test');
      return;
    }

    const { db, sql } = getDb(cfg);
    try {
      function mk(verdict: 'allow' | 'deny'): AuditRecord {
        return {
          id: crypto.randomUUID(), ts: new Date().toISOString(), tenant: 'test', plane: 'mcp',
          who: { agentId: 'a', identity: { agent: 'a', onBehalfOf: [] } },
          what: { target: 'mcp:fs', operation: 'read', argsDigest: 'a'.repeat(64) },
          whenWhere: { origin: 'test', correlationId: crypto.randomUUID() },
          why: { reason: 'export-integration-test' }, verdict, policyVersion: 'v1', subjectKeyId: null,
        };
      }

      await appendAudit(db, cfg, mk('allow'));
      await appendAudit(db, cfg, mk('deny'));

      const dayIso = new Date().toISOString().slice(0, 10);
      const result = await exportDay(db, cfg, dayIso, s3);

      expect(result.recordCount).toBeGreaterThanOrEqual(2);
      expect(result.objects).toHaveLength(1);

      // Read the segment back from MinIO and confirm the line count matches recordCount.
      const segObj = await s3.send(new GetObjectCommand({ Bucket: cfg.s3.bucket, Key: result.objects[0] }));
      const segmentBody = await segObj.Body!.transformToString();
      const lineCount = segmentBody.trimEnd().split('\n').length;
      expect(lineCount).toBe(result.recordCount);

      // Read the manifest back and confirm the recorded sha256 equals the sha256 of the
      // segment actually stored (offline-verifiable tamper check).
      const manifestObj = await s3.send(new GetObjectCommand({ Bucket: cfg.s3.bucket, Key: result.manifestKey }));
      const manifestBody = await manifestObj.Body!.transformToString();
      const manifest = JSON.parse(manifestBody);

      expect(manifest.recordCount).toBe(result.recordCount);
      expect(manifest.segments[0].key).toBe(result.objects[0]);
      expect(manifest.segments[0].sha256).toBe(segmentSha256(segmentBody));

      // Manifest's chain head must match the live chain_head row.
      const [head] = await db.select().from(chainHead).where(eq(chainHead.id, 'head')).limit(1);
      expect(manifest.chainHead).toEqual({ seq: head.seq, hash: head.hash });
    } finally {
      await sql.end();
    }
  }, 30_000);

  afterAll(() => {
    s3?.destroy();
  });
});
