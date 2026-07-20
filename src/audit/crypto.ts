import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { eq } from 'drizzle-orm';
import type { DrizzleDb } from '../db/client.js';
import type { Config } from '../config.js';
import { subjectKeys } from '../db/schema.js';

// AES-256-GCM: iv(12) || tag(16) || ciphertext, base64.
export function encryptPayload(key: Buffer, plaintext: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ct]).toString('base64');
}
export function decryptPayload(key: Buffer, blob: string): string {
  const buf = Buffer.from(blob, 'base64');
  const iv = buf.subarray(0, 12), tag = buf.subarray(12, 28), ct = buf.subarray(28);
  const d = createDecipheriv('aes-256-gcm', key, iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]).toString('utf8');
}

// Per-subject data key wrapped under the master key. Destroying the row = crypto-shred.
export async function getOrCreateSubjectKey(db: DrizzleDb, cfg: Config, keyId: string): Promise<Buffer> {
  const [row] = await db.select().from(subjectKeys).where(eq(subjectKeys.keyId, keyId)).limit(1);
  if (row) return Buffer.from(decryptPayload(cfg.auditMasterKey, row.wrappedKey), 'base64');
  const dataKey = randomBytes(32);
  const wrapped = encryptPayload(cfg.auditMasterKey, dataKey.toString('base64'));
  await db.insert(subjectKeys).values({ keyId, wrappedKey: wrapped }).onConflictDoNothing();
  const [saved] = await db.select().from(subjectKeys).where(eq(subjectKeys.keyId, keyId)).limit(1);
  return Buffer.from(decryptPayload(cfg.auditMasterKey, saved!.wrappedKey), 'base64');
}

export async function shredSubject(db: DrizzleDb, keyId: string): Promise<void> {
  await db.delete(subjectKeys).where(eq(subjectKeys.keyId, keyId)); // chain skeleton stays intact
}
