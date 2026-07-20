import { createRemoteJWKSet, jwtVerify } from 'jose';
import type { Config } from '../config.js';
import type { Principal } from '../identity/principal.js';
import type { DrizzleDb } from '../db/client.js';
import { getAgentByName } from '../identity/registry.js';

const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();
function jwks(url: string) {
  let j = jwksCache.get(url);
  if (!j) { j = createRemoteJWKSet(new URL(url)); jwksCache.set(url, j); }
  return j;
}

// v0.1: JWT `sub` must equal a registered agent name; identity comes from the DB, not the token body.
export async function verifyJwt(db: DrizzleDb, cfg: Config, token: string): Promise<Principal | null> {
  for (const url of cfg.jwksUrls) {
    try {
      const { payload } = await jwtVerify(token, jwks(url));
      if (typeof payload.sub !== 'string') return null;
      const agent = await getAgentByName(db, payload.sub);
      if (!agent || !agent.active) return null;
      return { agentId: agent.id, name: agent.name, tenant: agent.tenant, onBehalfOf: [] };
    } catch { /* try next issuer */ }
  }
  return null;
}
