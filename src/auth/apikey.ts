import bcrypt from 'bcrypt';
import { and, eq } from 'drizzle-orm';
import type { DrizzleDb } from '../db/client.js';
import { agents, apiKeys } from '../db/schema.js';
import type { Principal } from '../identity/principal.js';

export async function verifyApiKey(db: DrizzleDb, raw: string): Promise<Principal | null> {
  if (!raw.startsWith('aegis_')) return null;
  const prefix = raw.slice(0, 14);
  const candidates = await db.select().from(apiKeys)
    .where(and(eq(apiKeys.prefix, prefix), eq(apiKeys.active, true)));
  for (const c of candidates) {
    if (await bcrypt.compare(raw, c.hash)) {
      const [agent] = await db.select().from(agents).where(eq(agents.id, c.agentId)).limit(1);
      if (!agent || !agent.active) return null;
      return { agentId: agent.id, name: agent.name, tenant: agent.tenant, onBehalfOf: [] };
    }
  }
  return null;
}
