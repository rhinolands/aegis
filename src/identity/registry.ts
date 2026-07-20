import { randomBytes } from 'node:crypto';
import bcrypt from 'bcrypt';
import { eq } from 'drizzle-orm';
import type { DrizzleDb } from '../db/client.js';
import { agents, apiKeys } from '../db/schema.js';

export type AgentRow = typeof agents.$inferSelect;

export interface RegisterInput {
  name: string; tenant: string;
  allowedTools?: string[]; allowedPeers?: string[]; allowedModels?: string[];
}

export async function registerAgent(db: DrizzleDb, input: RegisterInput) {
  const [agent] = await db.insert(agents).values({
    name: input.name, tenant: input.tenant,
    allowedTools: input.allowedTools ?? [], allowedPeers: input.allowedPeers ?? [],
    allowedModels: input.allowedModels ?? [],
  }).returning();

  const raw = `aegis_${randomBytes(24).toString('base64url')}`;
  const hash = await bcrypt.hash(raw, 12);
  await db.insert(apiKeys).values({ agentId: agent.id, prefix: raw.slice(0, 14), hash });
  return { agent, apiKey: raw };
}

export async function getAgentByName(db: DrizzleDb, name: string): Promise<AgentRow | null> {
  const [row] = await db.select().from(agents).where(eq(agents.name, name)).limit(1);
  return row ?? null;
}

export async function listAgents(db: DrizzleDb, tenant: string): Promise<AgentRow[]> {
  return db.select().from(agents).where(eq(agents.tenant, tenant));
}
