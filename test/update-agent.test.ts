// Live-DB proof for the operator update surface (scripts/update-agent.ts).
//
// Three properties here are security properties, not conveniences:
//
//  1. `scoped_credentials` has NO unique constraint on (agent_id, target) —
//     only `id` is a PK (migrations/0000_init.sql) — `putCredential` is a plain
//     INSERT with no conflict clause, and `getCredentialTarget` resolves with
//     `.limit(1)` and NO `ORDER BY`. A second row therefore makes "which
//     credential does the gateway actually use" non-deterministic: it could
//     pick the garbage placeholder instead of the real upstream key. The
//     replacement path must collapse to EXACTLY one row, and a single read
//     cannot distinguish "deterministic" from "lucky" — so the determinism
//     assertion reads the credential back three times.
//
//  2. A model that is allowlisted but has no MODEL_PRICES entry meters $0
//     forever, which makes a cost cap vacuous while looking correct. The
//     refusal must happen BEFORE any write, which is why the unpriced test
//     asserts the agent's allowlist is unchanged afterwards rather than merely
//     that the call threw.
//
//  3. The upstream destination must stay a bare origin: the raw route appends
//     `/v1/messages` itself, so a path here yields `…/v1/messages/v1/messages`
//     and a 404 that looks like a gateway bug.
//
// These tests require a reachable Postgres and deliberately do NOT gate on one:
// a skipped run would swallow the proof, which is a failure, not a pass.

import { describe, it, expect } from 'vitest';
import { and, eq } from 'drizzle-orm';
import { getDb, type DrizzleDb } from '../src/db/client.js';
import { loadConfig } from '../src/config.js';
import { registerAgent } from '../src/identity/registry.js';
import { putCredential, getCredentialTarget } from '../src/credentials/store.js';
import { seedBudget, meterUsage } from '../src/guard/budget.js';
import { agents, budgets, scopedCredentials } from '../src/db/schema.js';
import { updateAgent, LLM_TARGET } from '../scripts/update-agent.js';

const cfg = loadConfig(process.env);

// Both ids below are real MODEL_PRICES keys (src/pricing/models.ts, plan 45-01).
const PRICED_SONNET = 'claude-sonnet-4-6';
const PRICED_HAIKU = 'claude-haiku-4-5-20251001';

// Deliberately ABSENT from MODEL_PRICES. It is a plausible future dated Sonnet
// variant — i.e. exactly the exact-match hazard models.ts's header names this
// CLI as the structural guard for — so the test proves the gate on the shape of
// mistake an operator would actually make, not on obvious garbage.
const UNPRICED_MODEL = 'claude-sonnet-4-6-20260301';

const ORIGIN = 'https://api.anthropic.com';

/** Number of `(agent, llm:anthropic)` credential rows. The whole invariant is that this is 1. */
async function credentialRowCount(db: DrizzleDb, agentId: string): Promise<number> {
  const rows = await db.select({ id: scopedCredentials.id }).from(scopedCredentials)
    .where(and(eq(scopedCredentials.agentId, agentId), eq(scopedCredentials.target, LLM_TARGET)));
  return rows.length;
}

// `agents.name` is globally unique, so every test registers its own agent with
// a Date.now()-suffixed name (same convention as test/plane-llm.test.ts:56).
function freshName(prefix: string): string {
  return `upd-${prefix}-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;
}

describe('update-agent CLI core', () => {
  it('sets allowed_models to exactly the supplied set and leaves the tools allowlist untouched', async () => {
    const { db, sql } = getDb(cfg);
    try {
      const name = freshName('models');
      const { agent } = await registerAgent(db, {
        name, tenant: 'test', allowedTools: ['acme-none'],
      });
      expect(agent.allowedModels).toEqual([]);

      const result = await updateAgent(db, cfg, {
        agentName: name,
        allowModels: [PRICED_SONNET, PRICED_HAIKU],
      });
      expect(result.allowedModels).toEqual([PRICED_SONNET, PRICED_HAIKU]);

      const [row] = await db.select().from(agents).where(eq(agents.id, agent.id)).limit(1);
      expect(row.allowedModels).toEqual([PRICED_SONNET, PRICED_HAIKU]);
      // Phase 46 owns the tools column; the live ["acme-none"] placeholder must survive.
      expect(row.allowedTools).toEqual(['acme-none']);
    } finally {
      await sql.end();
    }
  });

  it('replacing the credential twice leaves exactly one row and resolves deterministically', async () => {
    const { db, sql } = getDb(cfg);
    try {
      const name = freshName('replace');
      const { agent } = await registerAgent(db, { name, tenant: 'test', allowedTools: ['acme-none'] });

      await updateAgent(db, cfg, {
        agentName: name, setCredential: true, secret: 'upstream-key-first', upstreamUrl: ORIGIN,
      });
      const second = await updateAgent(db, cfg, {
        agentName: name, setCredential: true, secret: 'upstream-key-second', upstreamUrl: ORIGIN,
      });

      expect(second.credentialRowCount).toBe(1);
      expect(await credentialRowCount(db, agent.id)).toBe(1);

      // Three reads, not one: `.limit(1)` with no ORDER BY makes a single
      // matching read indistinguishable from a lucky one.
      const readA = await getCredentialTarget(db, cfg, agent.id, LLM_TARGET);
      const readB = await getCredentialTarget(db, cfg, agent.id, LLM_TARGET);
      const readC = await getCredentialTarget(db, cfg, agent.id, LLM_TARGET);
      expect(readA?.secret).toBe('upstream-key-second');
      expect(readB?.secret).toBe('upstream-key-second');
      expect(readC?.secret).toBe('upstream-key-second');
      expect(readA?.upstreamUrl).toBe(ORIGIN);
    } finally {
      await sql.end();
    }
  });

  it('collapses a pre-existing duplicate credential row back to exactly one', async () => {
    const { db, sql } = getDb(cfg);
    try {
      const name = freshName('dupe');
      const { agent } = await registerAgent(db, { name, tenant: 'test', allowedTools: ['acme-none'] });

      // Reproduce the exact hazard with the raw helper the seed script uses,
      // rather than a synthetic one: two blind INSERTs, no constraint to stop them.
      await putCredential(db, cfg, agent.id, LLM_TARGET, 'placeholder-one', ORIGIN);
      await putCredential(db, cfg, agent.id, LLM_TARGET, 'placeholder-two', ORIGIN);
      expect(await credentialRowCount(db, agent.id)).toBe(2);

      const result = await updateAgent(db, cfg, {
        agentName: name, setCredential: true, secret: 'upstream-key-real', upstreamUrl: ORIGIN,
      });

      expect(result.credentialRowCount).toBe(1);
      expect(await credentialRowCount(db, agent.id)).toBe(1);
      const read = await getCredentialTarget(db, cfg, agent.id, LLM_TARGET);
      expect(read?.secret).toBe('upstream-key-real');
    } finally {
      await sql.end();
    }
  });

  it('refuses a model with no MODEL_PRICES entry and leaves allowed_models unchanged', async () => {
    const { db, sql } = getDb(cfg);
    try {
      const name = freshName('unpriced');
      const { agent } = await registerAgent(db, {
        name, tenant: 'test', allowedTools: ['acme-none'], allowedModels: [PRICED_HAIKU],
      });

      await expect(updateAgent(db, cfg, {
        agentName: name,
        // One priced, one not: a partial write would be the worst outcome.
        allowModels: [PRICED_SONNET, UNPRICED_MODEL],
      })).rejects.toThrow(/MODEL_PRICES/);

      // The refusal PRECEDES the write — the allowlist is byte-identical to
      // what it was, not rolled back to it.
      const [row] = await db.select().from(agents).where(eq(agents.id, agent.id)).limit(1);
      expect(row.allowedModels).toEqual([PRICED_HAIKU]);
    } finally {
      await sql.end();
    }
  });

  it('rejects an upstream URL carrying a path or a non-https scheme, accepts the bare origin', async () => {
    const { db, sql } = getDb(cfg);
    try {
      const name = freshName('url');
      const { agent } = await registerAgent(db, { name, tenant: 'test', allowedTools: ['acme-none'] });

      await expect(updateAgent(db, cfg, {
        agentName: name, setCredential: true, secret: 'upstream-key-x',
        upstreamUrl: 'https://api.anthropic.com/v1/messages',
      })).rejects.toThrow(/origin/i);

      await expect(updateAgent(db, cfg, {
        agentName: name, setCredential: true, secret: 'upstream-key-x',
        upstreamUrl: 'http://api.anthropic.com',
      })).rejects.toThrow(/https/i);

      // Neither refusal wrote anything.
      expect(await credentialRowCount(db, agent.id)).toBe(0);

      const ok = await updateAgent(db, cfg, {
        agentName: name, setCredential: true, secret: 'upstream-key-x', upstreamUrl: ORIGIN,
      });
      expect(ok.credentialRowCount).toBe(1);
      expect(ok.upstreamUrl).toBe(ORIGIN);
    } finally {
      await sql.end();
    }
  });

  it('updates the budget limits without resetting the running meter', async () => {
    const { db, sql } = getDb(cfg);
    try {
      const name = freshName('budget');
      const { agent } = await registerAgent(db, { name, tenant: 'test', allowedTools: ['acme-none'] });
      await seedBudget(db, agent.id, 1_000_000, 1_000_000);
      await meterUsage(db, agent.id, 1_234, 5_678);

      const result = await updateAgent(db, cfg, {
        agentName: name, tokenLimit: 2_000_000, costLimitMicros: 250_000,
      });
      expect(result.budget).toEqual({ tokenLimit: 2_000_000, costLimitMicros: 250_000 });

      const [row] = await db.select().from(budgets).where(eq(budgets.agentId, agent.id)).limit(1);
      expect(row.tokenLimit).toBe(2_000_000);
      expect(row.costLimitMicros).toBe(250_000);
      // The table has no reset column and the used counters are the meter —
      // raising a cap must never silently refund spend.
      expect(row.tokensUsed).toBe(1_234);
      expect(row.costUsedMicros).toBe(5_678);
    } finally {
      await sql.end();
    }
  });

  it('refuses an unknown agent name without writing anything, naming the convention', async () => {
    const { db, sql } = getDb(cfg);
    try {
      const before = await db.select({ id: scopedCredentials.id }).from(scopedCredentials);
      await expect(updateAgent(db, cfg, {
        agentName: freshName('does-not-exist'),
        allowModels: [PRICED_SONNET],
        setCredential: true,
        secret: 'upstream-key-x',
      })).rejects.toThrow(/acme-\{lane\}/);
      const after = await db.select({ id: scopedCredentials.id }).from(scopedCredentials);
      expect(after.length).toBe(before.length);
    } finally {
      await sql.end();
    }
  });

  it('refuses to set a credential when the secret is absent or blank', async () => {
    const { db, sql } = getDb(cfg);
    try {
      const name = freshName('nosecret');
      const { agent } = await registerAgent(db, { name, tenant: 'test', allowedTools: ['acme-none'] });

      await expect(updateAgent(db, cfg, { agentName: name, setCredential: true }))
        .rejects.toThrow(/AEGIS_UPSTREAM_SECRET/);
      await expect(updateAgent(db, cfg, { agentName: name, setCredential: true, secret: '   ' }))
        .rejects.toThrow(/AEGIS_UPSTREAM_SECRET/);

      expect(await credentialRowCount(db, agent.id)).toBe(0);
    } finally {
      await sql.end();
    }
  });
});
