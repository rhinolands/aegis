import { describe, it, expect } from 'vitest';
import { getDb } from '../src/db/client.js';
import { loadConfig } from '../src/config.js';
import { registerAgent } from '../src/identity/registry.js';
import { checkRate } from '../src/guard/ratelimit.js';
import { ensureBudget, meterUsage, seedBudget } from '../src/guard/budget.js';

const cfg = loadConfig(process.env);

describe('rate limit', () => {
  it('allows up to the limit then blocks', () => {
    const id = `rate-${Date.now()}`;
    expect(checkRate(id, 2, 60_000)).toBe(true);
    expect(checkRate(id, 2, 60_000)).toBe(true);
    expect(checkRate(id, 2, 60_000)).toBe(false);
  });
});

describe('budget', () => {
  it('blocks when the token meter exceeds the limit', async () => {
    const { db, sql } = getDb(cfg);
    const { agent } = await registerAgent(db, { name: `bud-${Date.now()}`, tenant: 'test' });
    await seedBudget(db, agent.id, 100, 1_000_000);
    expect((await ensureBudget(db, agent.id)).ok).toBe(true);
    await meterUsage(db, agent.id, 150, 0);
    expect((await ensureBudget(db, agent.id)).ok).toBe(false); // fail closed
    await sql.end();
  });

  it('fails closed when no budget row exists for the agent', async () => {
    const { db, sql } = getDb(cfg);
    const { agent } = await registerAgent(db, { name: `nobudget-${Date.now()}`, tenant: 'test' });
    // No seedBudget call — an unconfigured agent must be denied, not given unlimited spend.
    const result = await ensureBudget(db, agent.id);
    expect(result.ok).toBe(false);
    expect(result.reason).toBe('no budget configured');
    await sql.end();
  });
});
