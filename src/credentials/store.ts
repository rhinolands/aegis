import { and, eq } from 'drizzle-orm';
import type { DrizzleDb } from '../db/client.js';
import type { Config } from '../config.js';
import { scopedCredentials } from '../db/schema.js';
import { encryptPayload, decryptPayload } from '../audit/crypto.js';

export async function putCredential(
  db: DrizzleDb, cfg: Config, agentId: string, target: string, secret: string, upstreamUrl?: string,
): Promise<void> {
  const ciphertext = encryptPayload(cfg.auditMasterKey, secret);
  await db.insert(scopedCredentials).values({
    agentId, target, secretCiphertext: ciphertext, upstreamUrl: upstreamUrl ?? null,
  });
}

// Returns the secret ONLY — there is no destination attached to this result.
// Do NOT use this to drive an outbound request's destination: it has no
// upstream URL to leak, but a caller that pairs this secret with any
// caller-influenced or otherwise-sourced URL recreates the exact
// credential-exfiltration primitive this codebase has already had to fix
// once (an agent redirecting its own scoped credential to a server it
// controls). Any plane that mediates an outbound call carrying a credential
// MUST use getCredentialTarget() instead, so the destination is always
// resolved from the operator-registered scoped_credentials row rather than
// from the caller.
export async function getCredential(
  db: DrizzleDb, cfg: Config, agentId: string, target: string,
): Promise<string | null> {
  const [row] = await db.select().from(scopedCredentials)
    .where(and(eq(scopedCredentials.agentId, agentId), eq(scopedCredentials.target, target)))
    .limit(1);
  if (!row) return null;
  return decryptPayload(cfg.auditMasterKey, row.secretCiphertext);
}

// Resolves BOTH the scoped credential and its operator-registered upstream
// destination for (agentId, target) in one lookup. This is the only place
// callers should get an upstream destination from — it is never accepted
// from a request body, which is what prevents an agent from redirecting its
// own scoped credential to an attacker-controlled host.
export async function getCredentialTarget(
  db: DrizzleDb, cfg: Config, agentId: string, target: string,
): Promise<{ secret: string; upstreamUrl: string | null } | null> {
  const [row] = await db.select().from(scopedCredentials)
    .where(and(eq(scopedCredentials.agentId, agentId), eq(scopedCredentials.target, target)))
    .limit(1);
  if (!row) return null;
  return { secret: decryptPayload(cfg.auditMasterKey, row.secretCiphertext), upstreamUrl: row.upstreamUrl };
}
