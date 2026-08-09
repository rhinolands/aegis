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
//  3. The upstream destination for the LLM target must stay a bare origin: the
//     raw route appends `/v1/messages` itself, so a path here yields
//     `…/v1/messages/v1/messages` and a 404 that looks like a gateway bug. The
//     opposite is true for an `mcp:<tool>` target — the MCP plane fetches the
//     registered URL verbatim (src/planes/mcp.ts), so a base reduced to its
//     bare origin would land every mediated call on `/`. The two rules are
//     therefore enforced by two separate validators, and this suite asserts
//     both: that the LLM rule is unchanged, and that an mcp row reads back with
//     its path INTACT.
//
//  4. `allowed_tools` is set by this CLI and REPLACED wholesale. A seeding
//     caller that looped one flag per invocation would leave only the last name
//     allowed, and an accumulate-instead-of-replace bug would widen a lane
//     silently — so the replacement property is asserted by passing three names
//     and then one, and reading back exactly one.
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

// WR-05 fault injection. Identical to the real config except for an AES key of
// the wrong length, which makes `createCipheriv` inside
// putCredential -> encryptPayload throw SYNCHRONOUSLY — i.e. the fault lands in
// exactly the window WR-05 is about: after the DELETE has run and before the
// INSERT. The injection point is the `cfg` argument updateAgent already takes,
// so nothing in the script is restructured to make it testable.
const FAULTY_CFG = { ...cfg, auditMasterKey: Buffer.alloc(8) };

// The real shape the Acme seed will pass: an in-cluster http origin carrying the
// exec path. Both halves matter — `http:` because there is no TLS on a cluster
// service DNS name, and the path because the MCP plane fetches this URL verbatim.
const MCP_BASE = 'http://acme-api.acme-system.svc.cluster.local:3001/internal/mcp/tools';
const TOOL_READ = 'acme.blueprint.read';
const TOOL_PROPOSE = 'acme.blueprint.propose_edit';
const TOOL_RULE = 'acme.advisor.lookup_rule';

/** Number of `(agent, llm:anthropic)` credential rows. The whole invariant is that this is 1. */
async function credentialRowCount(db: DrizzleDb, agentId: string): Promise<number> {
  const rows = await db.select({ id: scopedCredentials.id }).from(scopedCredentials)
    .where(and(eq(scopedCredentials.agentId, agentId), eq(scopedCredentials.target, LLM_TARGET)));
  return rows.length;
}

/** Same invariant, per `mcp:<tool>` target: exactly 1 row or selection is a coin flip. */
async function mcpRowCount(db: DrizzleDb, agentId: string, tool: string): Promise<number> {
  const rows = await db.select({ id: scopedCredentials.id }).from(scopedCredentials)
    .where(and(eq(scopedCredentials.agentId, agentId), eq(scopedCredentials.target, `mcp:${tool}`)));
  return rows.length;
}

/** The full set of credential rows for an agent, as a comparable snapshot for refusal cases. */
async function credentialSnapshot(db: DrizzleDb, agentId: string): Promise<string[]> {
  const rows = await db.select().from(scopedCredentials)
    .where(eq(scopedCredentials.agentId, agentId));
  return rows.map((r) => `${r.target}|${r.upstreamUrl ?? ''}`).sort();
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
      // No tools flag was supplied, so `allowed_tools` is not in the SET clause at
      // all and the live ["acme-none"] placeholder survives untouched. This CLI
      // now manages that column (see the symmetric case below); the two columns
      // must not bleed into each other in either direction.
      expect(row.allowedTools).toEqual(['acme-none']);
    } finally {
      await sql.end();
    }
  });

  it('sets allowed_tools to exactly the supplied set and leaves the models allowlist untouched', async () => {
    const { db, sql } = getDb(cfg);
    try {
      const name = freshName('tools');
      const { agent } = await registerAgent(db, {
        name, tenant: 'test', allowedTools: ['acme-none'], allowedModels: [PRICED_HAIKU],
      });

      const result = await updateAgent(db, cfg, {
        agentName: name,
        allowTools: [TOOL_READ, TOOL_PROPOSE, TOOL_RULE],
      });
      expect(result.allowedTools).toEqual([TOOL_READ, TOOL_PROPOSE, TOOL_RULE]);

      const [row] = await db.select().from(agents).where(eq(agents.id, agent.id)).limit(1);
      expect(row.allowedTools).toEqual([TOOL_READ, TOOL_PROPOSE, TOOL_RULE]);
      // The mirror of the assertion above: no model flag was supplied, so the
      // model allowlist is byte-identical.
      expect(row.allowedModels).toEqual([PRICED_HAIKU]);
    } finally {
      await sql.end();
    }
  });

  it('replaces the whole tools array rather than appending to it', async () => {
    const { db, sql } = getDb(cfg);
    try {
      const name = freshName('toolreplace');
      const { agent } = await registerAgent(db, { name, tenant: 'test', allowedTools: ['acme-none'] });

      await updateAgent(db, cfg, { agentName: name, allowTools: [TOOL_READ, TOOL_PROPOSE, TOOL_RULE] });
      // A caller that looped `--allow-tool` once per tool would land here with
      // one name and expect three. Whole-array replacement makes that mistake
      // loud (a lane denied everything but the last tool) rather than silent.
      const second = await updateAgent(db, cfg, { agentName: name, allowTools: [TOOL_RULE] });
      expect(second.allowedTools).toEqual([TOOL_RULE]);

      const [row] = await db.select().from(agents).where(eq(agents.id, agent.id)).limit(1);
      expect(row.allowedTools).toEqual([TOOL_RULE]);
    } finally {
      await sql.end();
    }
  });

  it('dedupes repeated tool names and drops an empty entry', async () => {
    const { db, sql } = getDb(cfg);
    try {
      const name = freshName('tooldupe');
      const { agent } = await registerAgent(db, { name, tenant: 'test', allowedTools: ['acme-none'] });

      const result = await updateAgent(db, cfg, {
        agentName: name,
        allowTools: [TOOL_READ, TOOL_READ, '', TOOL_PROPOSE],
      });
      expect(result.allowedTools).toEqual([TOOL_READ, TOOL_PROPOSE]);

      const [row] = await db.select().from(agents).where(eq(agents.id, agent.id)).limit(1);
      expect(row.allowedTools).toEqual([TOOL_READ, TOOL_PROPOSE]);
    } finally {
      await sql.end();
    }
  });

  it('writes an mcp:<tool> credential whose upstream_url keeps its path', async () => {
    const { db, sql } = getDb(cfg);
    try {
      const name = freshName('mcpwrite');
      const { agent } = await registerAgent(db, { name, tenant: 'test', allowedTools: ['acme-none'] });

      const result = await updateAgent(db, cfg, {
        agentName: name,
        mcpTools: [TOOL_READ, TOOL_PROPOSE],
        mcpUpstreamBase: MCP_BASE,
        secret: 'acme-pat-value',
      });

      expect(result.mcpCredentials.map((c) => c.target))
        .toEqual([`mcp:${TOOL_READ}`, `mcp:${TOOL_PROPOSE}`]);
      for (const written of result.mcpCredentials) expect(written.rowCount).toBe(1);

      // Assert on the value READ BACK from the row, not on the argument passed
      // in: a validator that returned the bare origin would still make the
      // argument-side assertion pass while every mediated call landed on `/`.
      const read = await getCredentialTarget(db, cfg, agent.id, `mcp:${TOOL_READ}`);
      expect(read?.upstreamUrl).toBe(`${MCP_BASE}/${TOOL_READ}`);
      expect(read?.upstreamUrl).toContain('/internal/mcp/tools/');
      const readProposeRow = await getCredentialTarget(db, cfg, agent.id, `mcp:${TOOL_PROPOSE}`);
      expect(readProposeRow?.upstreamUrl).toBe(`${MCP_BASE}/${TOOL_PROPOSE}`);

      expect(await mcpRowCount(db, agent.id, TOOL_READ)).toBe(1);
      expect(await mcpRowCount(db, agent.id, TOOL_PROPOSE)).toBe(1);
      // One invocation, N tools, one secret — and the LLM target is untouched by it.
      expect(await credentialRowCount(db, agent.id)).toBe(0);
    } finally {
      await sql.end();
    }
  });

  it('resolves a replaced mcp:<tool> credential deterministically across three reads', async () => {
    const { db, sql } = getDb(cfg);
    try {
      const name = freshName('mcpdet');
      const { agent } = await registerAgent(db, { name, tenant: 'test', allowedTools: ['acme-none'] });

      await updateAgent(db, cfg, {
        agentName: name, mcpTools: [TOOL_READ], mcpUpstreamBase: MCP_BASE, secret: 'pat-first',
      });
      const second = await updateAgent(db, cfg, {
        agentName: name, mcpTools: [TOOL_READ], mcpUpstreamBase: MCP_BASE, secret: 'pat-second',
      });
      expect(second.mcpCredentials[0].rowCount).toBe(1);
      expect(await mcpRowCount(db, agent.id, TOOL_READ)).toBe(1);

      // Three reads, not one: `.limit(1)` with no ORDER BY makes a single
      // matching read indistinguishable from a lucky one.
      const readA = await getCredentialTarget(db, cfg, agent.id, `mcp:${TOOL_READ}`);
      const readB = await getCredentialTarget(db, cfg, agent.id, `mcp:${TOOL_READ}`);
      const readC = await getCredentialTarget(db, cfg, agent.id, `mcp:${TOOL_READ}`);
      expect(readA?.secret).toBe('pat-second');
      expect(readB?.secret).toBe('pat-second');
      expect(readC?.secret).toBe('pat-second');
    } finally {
      await sql.end();
    }
  });

  it('collapses a pre-existing duplicate mcp:<tool> row back to exactly one', async () => {
    const { db, sql } = getDb(cfg);
    try {
      const name = freshName('mcpcollapse');
      const { agent } = await registerAgent(db, { name, tenant: 'test', allowedTools: ['acme-none'] });

      // The real helper twice, not a synthetic fixture: this is exactly how a
      // re-run of a seed script would produce the hazard.
      await putCredential(db, cfg, agent.id, `mcp:${TOOL_READ}`, 'placeholder-one', `${MCP_BASE}/${TOOL_READ}`);
      await putCredential(db, cfg, agent.id, `mcp:${TOOL_READ}`, 'placeholder-two', `${MCP_BASE}/${TOOL_READ}`);
      expect(await mcpRowCount(db, agent.id, TOOL_READ)).toBe(2);

      const result = await updateAgent(db, cfg, {
        agentName: name, mcpTools: [TOOL_READ], mcpUpstreamBase: MCP_BASE, secret: 'pat-real',
      });

      expect(result.mcpCredentials[0].rowCount).toBe(1);
      expect(await mcpRowCount(db, agent.id, TOOL_READ)).toBe(1);
      const read = await getCredentialTarget(db, cfg, agent.id, `mcp:${TOOL_READ}`);
      expect(read?.secret).toBe('pat-real');
    } finally {
      await sql.end();
    }
  });

  it('keeps the https-and-origin-only rule on the llm target while allowing a path for mcp targets', async () => {
    const { db, sql } = getDb(cfg);
    try {
      const name = freshName('scoped');
      const { agent } = await registerAgent(db, { name, tenant: 'test', allowedTools: ['acme-none'] });

      // The relaxation is scoped to mcp:* — the LLM route still appends
      // `/v1/messages` itself and still must not carry the credential in clear.
      await expect(updateAgent(db, cfg, {
        agentName: name, setCredential: true, secret: 'k',
        upstreamUrl: 'https://api.anthropic.com/v1/messages',
      })).rejects.toThrow(/origin/i);
      await expect(updateAgent(db, cfg, {
        agentName: name, setCredential: true, secret: 'k', upstreamUrl: 'http://api.anthropic.com',
      })).rejects.toThrow(/https/i);
      expect(await credentialRowCount(db, agent.id)).toBe(0);

      // The same shape of URL is ACCEPTED for an mcp target.
      const ok = await updateAgent(db, cfg, {
        agentName: name, mcpTools: [TOOL_READ], mcpUpstreamBase: MCP_BASE, secret: 'k',
      });
      expect(ok.mcpCredentials[0].upstreamUrl).toBe(`${MCP_BASE}/${TOOL_READ}`);

      // A query or fragment is still refused for an mcp base.
      await expect(updateAgent(db, cfg, {
        agentName: name, mcpTools: [TOOL_PROPOSE], mcpUpstreamBase: `${MCP_BASE}?x=1`, secret: 'k',
      })).rejects.toThrow(/query|fragment/i);
      expect(await mcpRowCount(db, agent.id, TOOL_PROPOSE)).toBe(0);
    } finally {
      await sql.end();
    }
  });

  it('refuses an mcp tool name that is empty after trim, leaving tools and credentials byte-identical', async () => {
    const { db, sql } = getDb(cfg);
    try {
      const name = freshName('mcpblank');
      const { agent } = await registerAgent(db, { name, tenant: 'test', allowedTools: ['acme-none'] });
      await updateAgent(db, cfg, {
        agentName: name, mcpTools: [TOOL_READ], mcpUpstreamBase: MCP_BASE, secret: 'pat-real',
      });
      const beforeCreds = await credentialSnapshot(db, agent.id);

      await expect(updateAgent(db, cfg, {
        agentName: name,
        allowTools: [TOOL_READ, TOOL_PROPOSE],
        mcpTools: [TOOL_PROPOSE, '   '],
        mcpUpstreamBase: MCP_BASE,
        secret: 'pat-real',
      })).rejects.toThrow(/--mcp-tool/);

      // The refusal PRECEDES the first write: the tools column still holds the
      // placeholder it was registered with, not the half-applied allowTools set.
      const [row] = await db.select().from(agents).where(eq(agents.id, agent.id)).limit(1);
      expect(row.allowedTools).toEqual(['acme-none']);
      expect(await credentialSnapshot(db, agent.id)).toEqual(beforeCreds);
      expect(await mcpRowCount(db, agent.id, TOOL_PROPOSE)).toBe(0);
    } finally {
      await sql.end();
    }
  });

  it('refuses a --mcp-tool value carrying dot segments before any write, leaving credentials byte-identical (WR-02)', async () => {
    const { db, sql } = getDb(cfg);
    try {
      const name = freshName('mcptraversal');
      const { agent } = await registerAgent(db, { name, tenant: 'test', allowedTools: ['acme-none'] });
      await updateAgent(db, cfg, {
        agentName: name, mcpTools: [TOOL_READ], mcpUpstreamBase: MCP_BASE, secret: 'pat-real',
      });
      const beforeCreds = await credentialSnapshot(db, agent.id);

      // The exact value from the Phase-46 review (WR-02). `${base}/${tool}`
      // yields `…/internal/mcp/tools/../../../api/blueprints`, which the WHATWG
      // URL normalization inside fetch() collapses to `…/api/blueprints` — a
      // REGISTERED credential pointing at a whole-tenant Acme route the exec
      // path does not serve, carrying the gateway-injected PAT. `encodeURIComponent`
      // does not help: it leaves `..` unchanged.
      await expect(updateAgent(db, cfg, {
        agentName: name,
        allowTools: [TOOL_READ, TOOL_PROPOSE],
        mcpTools: ['../../../api/blueprints'],
        mcpUpstreamBase: MCP_BASE,
        secret: 'pat-real',
      })).rejects.toThrow(/--mcp-tool/);

      // Property 2 of this file's header: read the state back, do not trust the
      // throw. The refusal must precede the FIRST write, so the tools column
      // still holds its registration placeholder and every credential row is
      // byte-identical to the snapshot taken above.
      const [row] = await db.select().from(agents).where(eq(agents.id, agent.id)).limit(1);
      expect(row.allowedTools).toEqual(['acme-none']);
      expect(await credentialSnapshot(db, agent.id)).toEqual(beforeCreds);
      expect(await mcpRowCount(db, agent.id, '../../../api/blueprints')).toBe(0);
    } finally {
      await sql.end();
    }
  });

  it('refuses every URL-reserved character in a --mcp-tool value, leaving credentials byte-identical (WR-02)', async () => {
    const { db, sql } = getDb(cfg);
    try {
      const name = freshName('mcpreserved');
      const { agent } = await registerAgent(db, { name, tenant: 'test', allowedTools: ['acme-none'] });
      await updateAgent(db, cfg, {
        agentName: name, mcpTools: [TOOL_READ], mcpUpstreamBase: MCP_BASE, secret: 'pat-real',
      });
      const beforeCreds = await credentialSnapshot(db, agent.id);

      // One value per reserved character that changes where the stored URL
      // resolves: a path separator, a query, a fragment, a percent-escape (the
      // encoded form of a dot segment) and a raw space. None survives a trim,
      // so the existing empty-after-trim refusal cannot be what rejects them.
      const RESERVED = [
        'acme/blueprint.read',
        'acme.blueprint?x=1',
        'acme.blueprint#frag',
        'acme.%2e%2e',
        'acme.blueprint read',
      ];
      for (const badTool of RESERVED) {
        await expect(updateAgent(db, cfg, {
          agentName: name, mcpTools: [badTool], mcpUpstreamBase: MCP_BASE, secret: 'pat-real',
        })).rejects.toThrow(/--mcp-tool/);
        expect(await credentialSnapshot(db, agent.id)).toEqual(beforeCreds);
      }
    } finally {
      await sql.end();
    }
  });

  it('still accepts an ordinary dotted, underscored or hyphenated tool name (WR-02 non-vacuity)', async () => {
    const { db, sql } = getDb(cfg);
    try {
      const name = freshName('mcpcharsetok');
      const { agent } = await registerAgent(db, { name, tenant: 'test', allowedTools: ['acme-none'] });

      // The positive control: a guard that rejected everything would pass the
      // two refusal cases above vacuously (the `allowlist-ceiling.test.ts:44`
      // idiom). Every character class the charset permits is exercised here —
      // dots between segments, an underscore and a hyphen inside one.
      const ok = await updateAgent(db, cfg, {
        agentName: name,
        mcpTools: [TOOL_READ, TOOL_PROPOSE, 'acme_lane-01'],
        mcpUpstreamBase: MCP_BASE,
        secret: 'pat-real',
      });
      expect(ok.mcpCredentials.map((c) => c.target))
        .toEqual([`mcp:${TOOL_READ}`, `mcp:${TOOL_PROPOSE}`, 'mcp:acme_lane-01']);
      for (const written of ok.mcpCredentials) expect(written.rowCount).toBe(1);

      // The shipped happy path is unchanged: the row reads back with its path intact.
      const read = await getCredentialTarget(db, cfg, agent.id, `mcp:${TOOL_READ}`);
      expect(read?.upstreamUrl).toBe(`${MCP_BASE}/${TOOL_READ}`);
      expect(read?.upstreamUrl).toContain('/internal/mcp/tools/');
    } finally {
      await sql.end();
    }
  });

  it('refuses an mcp credential write when no secret is supplied — it is never a flag', async () => {
    const { db, sql } = getDb(cfg);
    try {
      const name = freshName('mcpnosecret');
      const { agent } = await registerAgent(db, { name, tenant: 'test', allowedTools: ['acme-none'] });

      await expect(updateAgent(db, cfg, {
        agentName: name, mcpTools: [TOOL_READ], mcpUpstreamBase: MCP_BASE,
      })).rejects.toThrow(/AEGIS_UPSTREAM_SECRET/);
      await expect(updateAgent(db, cfg, {
        agentName: name, mcpTools: [TOOL_READ], mcpUpstreamBase: MCP_BASE, secret: '   ',
      })).rejects.toThrow(/AEGIS_UPSTREAM_SECRET/);

      expect(await mcpRowCount(db, agent.id, TOOL_READ)).toBe(0);
    } finally {
      await sql.end();
    }
  });

  it('refuses mcp tools without a base and a base without mcp tools, before the first write', async () => {
    const { db, sql } = getDb(cfg);
    try {
      const name = freshName('mcppair');
      const { agent } = await registerAgent(db, { name, tenant: 'test', allowedTools: ['acme-none'] });

      await expect(updateAgent(db, cfg, {
        agentName: name, allowTools: [TOOL_READ], mcpTools: [TOOL_READ], secret: 'k',
      })).rejects.toThrow(/--mcp-upstream-base/);
      await expect(updateAgent(db, cfg, {
        agentName: name, allowTools: [TOOL_READ], mcpUpstreamBase: MCP_BASE, secret: 'k',
      })).rejects.toThrow(/--mcp-tool/);

      const [row] = await db.select().from(agents).where(eq(agents.id, agent.id)).limit(1);
      expect(row.allowedTools).toEqual(['acme-none']);
      expect(await credentialSnapshot(db, agent.id)).toEqual([]);
    } finally {
      await sql.end();
    }
  });

  it('refuses an unknown agent name carrying tools and mcp targets without writing anything', async () => {
    const { db, sql } = getDb(cfg);
    try {
      const before = await db.select({ id: scopedCredentials.id }).from(scopedCredentials);
      await expect(updateAgent(db, cfg, {
        agentName: freshName('mcp-does-not-exist'),
        allowTools: [TOOL_READ],
        mcpTools: [TOOL_READ],
        mcpUpstreamBase: MCP_BASE,
        secret: 'k',
      })).rejects.toThrow(/acme-\{lane\}/);
      const after = await db.select({ id: scopedCredentials.id }).from(scopedCredentials);
      expect(after.length).toBe(before.length);
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

  it('rolls the llm credential swap back when the insert faults, leaving the pre-existing credential resolvable (WR-05)', async () => {
    const { db, sql } = getDb(cfg);
    try {
      const name = freshName('llmrollback');
      const { agent } = await registerAgent(db, { name, tenant: 'test', allowedTools: ['acme-none'] });
      await updateAgent(db, cfg, {
        agentName: name, setCredential: true, secret: 'upstream-key-original', upstreamUrl: ORIGIN,
      });
      expect(await credentialRowCount(db, agent.id)).toBe(1);

      // The replacement is DELETE-then-INSERT. Fault the INSERT and the
      // pre-existing working key is gone with nothing in its place: the LLM
      // plane then fails closed on every call for this agent until an operator
      // re-seeds. The count==1 post-condition below the swap cannot save it —
      // it only runs when the process survives that far, and here it does not.
      await expect(updateAgent(db, FAULTY_CFG, {
        agentName: name, setCredential: true, secret: 'upstream-key-replacement', upstreamUrl: ORIGIN,
      })).rejects.toThrow(/invalid key length/i);

      // Property 1 of this file's header: read it back. The DELETE must have
      // rolled back with the failed INSERT, so the ORIGINAL secret — not the
      // replacement, and not nothing — still resolves.
      expect(await credentialRowCount(db, agent.id)).toBe(1);
      const survived = await getCredentialTarget(db, cfg, agent.id, LLM_TARGET);
      expect(survived?.secret).toBe('upstream-key-original');
      expect(survived?.upstreamUrl).toBe(ORIGIN);

      // Positive control: the transaction must not change the happy path. A
      // normal, non-faulting run still replaces the value and still collapses
      // to exactly one row.
      const ok = await updateAgent(db, cfg, {
        agentName: name, setCredential: true, secret: 'upstream-key-replacement', upstreamUrl: ORIGIN,
      });
      expect(ok.credentialRowCount).toBe(1);
      expect(await credentialRowCount(db, agent.id)).toBe(1);
      expect((await getCredentialTarget(db, cfg, agent.id, LLM_TARGET))?.secret)
        .toBe('upstream-key-replacement');
    } finally {
      await sql.end();
    }
  });

  it('rolls each mcp:<tool> credential swap back when the insert faults, leaving every pre-existing credential resolvable (WR-05)', async () => {
    const { db, sql } = getDb(cfg);
    try {
      const name = freshName('mcprollback');
      const { agent } = await registerAgent(db, { name, tenant: 'test', allowedTools: ['acme-none'] });
      await updateAgent(db, cfg, {
        agentName: name, mcpTools: [TOOL_READ, TOOL_PROPOSE], mcpUpstreamBase: MCP_BASE,
        secret: 'pat-original',
      });
      expect(await mcpRowCount(db, agent.id, TOOL_READ)).toBe(1);
      expect(await mcpRowCount(db, agent.id, TOOL_PROPOSE)).toBe(1);

      // Two pairs, so this asserts the per-pair loop's atomicity twice over:
      // the FIRST pair's swap must roll back (its own transaction), and the
      // throw must abort the loop before the SECOND pair is touched at all.
      // Either way no target is left with zero rows.
      await expect(updateAgent(db, FAULTY_CFG, {
        agentName: name, mcpTools: [TOOL_READ, TOOL_PROPOSE], mcpUpstreamBase: MCP_BASE,
        secret: 'pat-replacement',
      })).rejects.toThrow(/invalid key length/i);

      expect(await mcpRowCount(db, agent.id, TOOL_READ)).toBe(1);
      expect(await mcpRowCount(db, agent.id, TOOL_PROPOSE)).toBe(1);
      const readSurvived = await getCredentialTarget(db, cfg, agent.id, `mcp:${TOOL_READ}`);
      expect(readSurvived?.secret).toBe('pat-original');
      expect(readSurvived?.upstreamUrl).toBe(`${MCP_BASE}/${TOOL_READ}`);
      const proposeSurvived = await getCredentialTarget(db, cfg, agent.id, `mcp:${TOOL_PROPOSE}`);
      expect(proposeSurvived?.secret).toBe('pat-original');
      expect(proposeSurvived?.upstreamUrl).toBe(`${MCP_BASE}/${TOOL_PROPOSE}`);

      // Positive control, same as the llm case: the wrapper must leave the
      // shipped replace-and-assert-count-1 behaviour exactly as it was.
      const ok = await updateAgent(db, cfg, {
        agentName: name, mcpTools: [TOOL_READ, TOOL_PROPOSE], mcpUpstreamBase: MCP_BASE,
        secret: 'pat-replacement',
      });
      for (const written of ok.mcpCredentials) expect(written.rowCount).toBe(1);
      expect((await getCredentialTarget(db, cfg, agent.id, `mcp:${TOOL_READ}`))?.secret)
        .toBe('pat-replacement');
      expect((await getCredentialTarget(db, cfg, agent.id, `mcp:${TOOL_PROPOSE}`))?.secret)
        .toBe('pat-replacement');
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
