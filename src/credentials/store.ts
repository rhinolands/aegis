import { and, eq } from 'drizzle-orm';
import type { DrizzleDb } from '../db/client.js';
import type { Config } from '../config.js';
import { scopedCredentials } from '../db/schema.js';
import { encryptPayload, decryptPayload } from '../audit/crypto.js';

export async function putCredential(
  db: DrizzleDb, cfg: Config, agentId: string, target: string, secret: string,
): Promise<void> {
  const ciphertext = encryptPayload(cfg.auditMasterKey, secret);
  await db.insert(scopedCredentials).values({ agentId, target, secretCiphertext: ciphertext });
}

export async function getCredential(
  db: DrizzleDb, cfg: Config, agentId: string, target: string,
): Promise<string | null> {
  const [row] = await db.select().from(scopedCredentials)
    .where(and(eq(scopedCredentials.agentId, agentId), eq(scopedCredentials.target, target)))
    .limit(1);
  if (!row) return null;
  return decryptPayload(cfg.auditMasterKey, row.secretCiphertext);
}
