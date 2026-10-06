import { describe, it, expect, beforeEach, afterEach, afterAll, vi } from 'vitest';
import { createHash } from 'node:crypto';
import { and, eq, sql as dsql } from 'drizzle-orm';
import { getDb, type DrizzleDb } from '../src/db/client.js';
import { loadConfig } from '../src/config.js';
import { registerAgent } from '../src/identity/registry.js';
import { seedBudget } from '../src/guard/budget.js';
import { verifyChain } from '../src/audit/verify.js';
import * as auditWriter from '../src/audit/writer.js';
import { agentConfigDigest, agentConfigSnapshot, type OperatorContext } from '../src/audit/operator.js';
import { agents, auditRecords, budgets, scopedCredentials } from '../src/db/schema.js';
import { updateAgent, LLM_TARGET } from '../scripts/update-agent.js';
import { registerWithAudit } from '../scripts/register.js';
import { resetChain as resetChainFor, asOwner } from './helpers/chain.js';

// Operator changes (register, allowlist, credential, budget) go into the SAME audit
// chain as agent calls. These tests pin the three properties that make that worth
// having: every write through the tooling leaves a record, no write lands without its
// record, and the record never carries a secret.

const cfg = loadConfig(process.env);
const resetChain = () => resetChainFor(cfg);
const SECRET = 'sk-operator-audit-test-not-a-real-key-0123456789';
const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');

function freshName(prefix: string): string {
  return `op-${prefix}-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;
}

function operator(name = 'alice'): OperatorContext {
  return { name, origin: 'test', correlationId: crypto.randomUUID() };
}

async function newAgent(db: DrizzleDb, tools = ['echo']) {
  const { agent } = await registerAgent(db, { name: freshName('agent'), tenant: 'op-test', allowedTools: tools });
  await seedBudget(db, agent.id, 1_000, 1_000);
  return agent;
}

// The operator records of one invocation, in chain order.
async function operatorRecords(db: DrizzleDb, correlationId: string) {
  return db.select().from(auditRecords)
    .where(and(eq(auditRecords.plane, 'operator'), dsql`${auditRecords.whenWhere}->>'correlationId' = ${correlationId}`))
    .orderBy(auditRecords.seq);
}

describe('operator changes in the audit chain', () => {
  beforeEach(resetChain);
  afterEach(() => { vi.restoreAllMocks(); });
  afterAll(resetChain);

  it('an allowlist change appends one record naming who, what, and the configuration before and after', async () => {
    const { db, sql } = getDb(cfg);
    const agent = await newAgent(db);
    const before = await agentConfigDigest(db, agent.name);
    const op = operator('alice');

    await updateAgent(db, cfg, { agentName: agent.name, allowTools: ['echo', 'danger'], operator: op });

    const recs = await operatorRecords(db, op.correlationId);
    expect(recs).toHaveLength(1);
    const [rec] = recs;
    expect(rec.who).toEqual({ agentId: 'operator:cli', identity: { agent: 'alice', onBehalfOf: [] } });
    expect(rec.tenant).toBe('op-test');
    expect(rec.verdict).toBe('allow');
    expect(rec.policyVersion).toBe('none');
    const what = rec.what as {
      target: string; operation: string;
      change: { fields: string[]; before: string; after: string; values: Record<string, { before: unknown; after: unknown }> };
    };
    expect(what.target).toBe(`agent:${agent.name}`);
    expect(what.operation).toBe('agent.allowlist.update');
    expect(what.change.fields).toEqual(['allowedTools']);
    // The record says what the allowlist became, not only that it changed.
    expect(what.change.values).toEqual({ allowedTools: { before: ['echo'], after: ['echo', 'danger'] } });
    expect(what.change.before).toBe(before);
    expect(what.change.after).toBe(await agentConfigDigest(db, agent.name));
    expect(what.change.after).not.toBe(before);
    expect(await verifyChain(db)).toEqual({ ok: true, checked: 1 });
    await sql.end();
  });

  it('records each write of one invocation, chained before-to-after, ending at the live configuration', async () => {
    const { db, sql } = getDb(cfg);
    const agent = await newAgent(db);
    const op = operator();

    await updateAgent(db, cfg, {
      agentName: agent.name, allowTools: ['echo', 'search'], setCredential: true, secret: SECRET,
      mcpTools: ['echo'], mcpUpstreamBase: 'http://tools.internal:3001/mcp', tokenLimit: 5_000, operator: op,
    });

    const recs = await operatorRecords(db, op.correlationId);
    const changes = recs.map((r) => (r.what as { operation: string; change: { fields: string[]; before: string; after: string } }));
    expect(changes.map((c) => c.operation)).toEqual([
      'agent.allowlist.update', 'credential.set', 'credential.set', 'budget.update',
    ]);
    expect(changes[1].change.fields).toEqual([`credentials[${LLM_TARGET}]`]);
    expect(changes[2].change.fields).toEqual(['credentials[mcp:echo]']);
    expect(changes[3].change.fields).toEqual(['budget']);
    for (let i = 1; i < changes.length; i++) expect(changes[i].change.before).toBe(changes[i - 1].change.after);
    expect(changes.at(-1)!.change.after).toBe(await agentConfigDigest(db, agent.name));
    expect((await verifyChain(db)).ok).toBe(true);
    await sql.end();
  });

  it('a credential change records a fingerprint of the stored ciphertext, never the secret or a hash of it', async () => {
    const { db, sql } = getDb(cfg);
    const agent = await newAgent(db);
    const op = operator();
    await updateAgent(db, cfg, { agentName: agent.name, setCredential: true, secret: SECRET, operator: op });

    const [stored] = await db.select().from(scopedCredentials)
      .where(and(eq(scopedCredentials.agentId, agent.id), eq(scopedCredentials.target, LLM_TARGET)));
    const snap = await agentConfigSnapshot(db, agent.name);
    expect(snap!.credentials).toEqual([
      { target: LLM_TARGET, upstreamUrl: 'https://api.anthropic.com', fingerprint: sha256(stored.secretCiphertext) },
    ]);

    const [credRec] = await operatorRecords(db, op.correlationId);
    const credValues = (credRec.what as { change: { values: Record<string, { before: unknown; after: unknown }> } }).change.values;
    expect(credValues).toEqual({
      [`credentials[${LLM_TARGET}]`]: {
        before: [],
        after: [{ target: LLM_TARGET, upstreamUrl: 'https://api.anthropic.com', fingerprint: sha256(stored.secretCiphertext) }],
      },
    });

    // The whole stored record, every column, as text.
    const [row] = await sql`select row_to_json(a)::text as j from audit_records a where when_where->>'correlationId' = ${op.correlationId}`;
    expect(row.j).not.toContain(SECRET);
    expect(row.j).not.toContain(sha256(SECRET));
    expect(JSON.stringify(snap)).not.toContain(SECRET);
    expect(JSON.stringify(snap)).not.toContain(sha256(SECRET));
    await sql.end();
  });

  it('registration through the CLI path is one transaction with one agent.register record', async () => {
    const { db, sql } = getDb(cfg);
    const op = operator('bob');
    const name = freshName('reg');
    const { agent } = await registerWithAudit(db, cfg, {
      name, tenant: 'op-test', tools: ['echo'], peers: [], models: [],
      tokenLimit: 100, costLimitMicros: 100,
      credTarget: 'mcp:echo', credSecret: SECRET, upstreamUrl: 'http://localhost:7070',
    }, op);

    const recs = await operatorRecords(db, op.correlationId);
    expect(recs).toHaveLength(1);
    const what = recs[0].what as { target: string; operation: string; change: { fields: string[]; before: string | null; after: string } };
    expect(what.operation).toBe('agent.register');
    expect(what.target).toBe(`agent:${agent.name}`);
    expect(what.change.before).toBeNull();
    expect(what.change.after).toBe(await agentConfigDigest(db, name));
    // A registration records the whole starting configuration, field by field.
    const regValues = (recs[0].what as { change: { values: Record<string, { before: unknown; after: unknown }> } }).change.values;
    const regSnap = await agentConfigSnapshot(db, name);
    expect(Object.keys(regValues).sort()).toEqual([...what.change.fields].sort());
    expect(regValues.allowedTools).toEqual({ before: null, after: ['echo'] });
    expect(regValues.budget).toEqual({ before: null, after: { tokenLimit: 100, costLimitMicros: 100 } });
    expect(regValues.credentials).toEqual({ before: null, after: regSnap!.credentials });
    expect(JSON.stringify(regValues)).not.toContain(SECRET);
    expect((recs[0].who as { identity: { agent: string } }).identity.agent).toBe('bob');
    await sql.end();
  });

  it('a read-only invocation writes no record', async () => {
    const { db, sql } = getDb(cfg);
    const agent = await newAgent(db);
    const op = operator();
    await updateAgent(db, cfg, { agentName: agent.name, operator: op });
    expect(await operatorRecords(db, op.correlationId)).toHaveLength(0);
    await sql.end();
  });

  // Regression: a config write must never land without its audit record. Every write
  // path is tried with the audit append failing, and the configuration must be exactly
  // what it was before.
  describe('no config write lands when its audit record cannot be written', () => {
    const auditDown = () => vi.spyOn(auditWriter, 'appendAudit').mockRejectedValue(new Error('audit db unreachable'));

    it('allowlist update', async () => {
      const { db, sql } = getDb(cfg);
      const agent = await newAgent(db);
      const before = await agentConfigDigest(db, agent.name);
      auditDown();
      await expect(updateAgent(db, cfg, { agentName: agent.name, allowTools: ['echo', 'danger'], operator: operator() }))
        .rejects.toThrow('audit db unreachable');
      vi.restoreAllMocks();
      const [row] = await db.select().from(agents).where(eq(agents.id, agent.id));
      expect(row.allowedTools).toEqual(['echo']);
      expect(await agentConfigDigest(db, agent.name)).toBe(before);
      await sql.end();
    });

    it('credential set (llm and mcp targets)', async () => {
      const { db, sql } = getDb(cfg);
      const agent = await newAgent(db);
      const before = await agentConfigDigest(db, agent.name);
      auditDown();
      await expect(updateAgent(db, cfg, { agentName: agent.name, setCredential: true, secret: SECRET, operator: operator() }))
        .rejects.toThrow('audit db unreachable');
      await expect(updateAgent(db, cfg, {
        agentName: agent.name, mcpTools: ['echo'], mcpUpstreamBase: 'http://tools.internal:3001/mcp', secret: SECRET, operator: operator(),
      })).rejects.toThrow('audit db unreachable');
      vi.restoreAllMocks();
      expect(await db.select().from(scopedCredentials).where(eq(scopedCredentials.agentId, agent.id))).toHaveLength(0);
      expect(await agentConfigDigest(db, agent.name)).toBe(before);
      await sql.end();
    });

    it('budget update', async () => {
      const { db, sql } = getDb(cfg);
      const agent = await newAgent(db);
      auditDown();
      await expect(updateAgent(db, cfg, { agentName: agent.name, tokenLimit: 9_999, operator: operator() }))
        .rejects.toThrow('audit db unreachable');
      vi.restoreAllMocks();
      const [b] = await db.select().from(budgets).where(eq(budgets.agentId, agent.id));
      expect(b.tokenLimit).toBe(1_000);
      await sql.end();
    });

    it('registration', async () => {
      const { db, sql } = getDb(cfg);
      const name = freshName('reg-down');
      auditDown();
      await expect(registerWithAudit(db, cfg, {
        name, tenant: 'op-test', tools: ['echo'], peers: [], models: [],
        tokenLimit: 100, costLimitMicros: 100,
        credTarget: 'mcp:echo', credSecret: SECRET, upstreamUrl: 'http://localhost:7070',
      }, operator())).rejects.toThrow('audit db unreachable');
      vi.restoreAllMocks();
      expect(await db.select().from(agents).where(eq(agents.name, name))).toHaveLength(0);
      expect(await agentConfigDigest(db, name)).toBeNull();
      await sql.end();
    });
  });

  it('an operator record rewritten to hide the change fails verification', async () => {
    const { db, sql } = getDb(cfg);
    const agent = await newAgent(db);
    const op = operator();
    await updateAgent(db, cfg, { agentName: agent.name, allowTools: ['echo', 'danger'], operator: op });
    expect((await verifyChain(db)).ok).toBe(true);

    // Make the record claim nothing changed: after := before, fields := [].
    await asOwner(sql, (tx) => tx`
      update audit_records
         set what = jsonb_set(jsonb_set(what, '{change,after}', what->'change'->'before'), '{change,fields}', '[]'::jsonb)
       where plane = 'operator' and when_where->>'correlationId' = ${op.correlationId}`);
    const res = await verifyChain(db);
    expect(res.ok).toBe(false);
    expect(res.reason).toContain('hash mismatch');
    await sql.end();
  });

  it('an operator record whose recorded values are rewritten fails verification', async () => {
    const { db, sql } = getDb(cfg);
    const agent = await newAgent(db);
    const op = operator();
    await updateAgent(db, cfg, { agentName: agent.name, allowTools: ['echo', 'danger'], operator: op });
    expect((await verifyChain(db)).ok).toBe(true);

    // Leave the digests and field names alone. Only rewrite the readable value, so
    // the record says the allowlist stayed ['echo'].
    await asOwner(sql, (tx) => tx`
      update audit_records
         set what = jsonb_set(what, '{change,values,allowedTools,after}', what->'change'->'values'->'allowedTools'->'before')
       where plane = 'operator' and when_where->>'correlationId' = ${op.correlationId}`);
    const res = await verifyChain(db);
    expect(res.ok).toBe(false);
    expect(res.reason).toContain('hash mismatch');
    await sql.end();
  });
});
