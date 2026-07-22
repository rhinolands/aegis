import { eq, sql } from 'drizzle-orm';
import type { DrizzleDb } from '../db/client.js';
import { budgets } from '../db/schema.js';

export async function seedBudget(
  db: DrizzleDb, agentId: string, tokenLimit: number, costLimitMicros: number,
): Promise<void> {
  await db.insert(budgets).values({ agentId, tokenLimit, costLimitMicros })
    .onConflictDoUpdate({ target: budgets.agentId, set: { tokenLimit, costLimitMicros } });
}

export async function ensureBudget(db: DrizzleDb, agentId: string): Promise<{ ok: boolean; reason?: string }> {
  const [b] = await db.select().from(budgets).where(eq(budgets.agentId, agentId)).limit(1);
  if (!b) return { ok: false, reason: 'no budget configured' }; // fail closed
  if (b.tokensUsed >= b.tokenLimit) return { ok: false, reason: 'token budget exceeded' };
  if (b.costUsedMicros >= b.costLimitMicros) return { ok: false, reason: 'cost budget exceeded' };
  return { ok: true };
}

export async function meterUsage(
  db: DrizzleDb, agentId: string, tokens: number, costMicros: number,
): Promise<void> {
  await db.update(budgets).set({
    tokensUsed: sql`${budgets.tokensUsed} + ${tokens}`,
    costUsedMicros: sql`${budgets.costUsedMicros} + ${costMicros}`,
  }).where(eq(budgets.agentId, agentId));
}
