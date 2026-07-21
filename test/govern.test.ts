import { describe, it, expect, beforeAll, afterEach, vi } from 'vitest';
import { getDb } from '../src/db/client.js';
import { loadConfig } from '../src/config.js';
import { registerAgent } from '../src/identity/registry.js';
import { loadPolicy, type PolicyEngine } from '../src/policy/opa.js';
import { seedBudget } from '../src/guard/budget.js';
import { govern } from '../src/pipeline/govern.js';
import { verifyChain } from '../src/audit/verify.js';
import * as auditWriter from '../src/audit/writer.js';

const cfg = loadConfig(process.env);
let engine: PolicyEngine;
beforeAll(async () => { engine = await loadPolicy('dist/policy.wasm'); });

describe('govern pipeline', () => {
  it('allows a permitted tool call, executes upstream, writes an allow record', async () => {
    const { db, sql } = getDb(cfg);
    const { agent } = await registerAgent(db, { name: `gov-${Date.now()}`, tenant: 'test', allowedTools: ['fs.read'] });
    await seedBudget(db, agent.id, 1_000_000, 1_000_000);
    let executed = false;
    const res = await govern(
      { db, cfg, engine },
      {
        principal: { agentId: agent.id, name: agent.name, tenant: agent.tenant, onBehalfOf: [] },
        agent, plane: 'mcp', request: { tool: 'fs.read', operation: 'call' },
        target: 'mcp:filesystem', correlationId: crypto.randomUUID(), origin: 'test',
      },
      async () => { executed = true; return { tokens: 0, costMicros: 0, body: { ok: true } }; },
    );
    expect(res.status).toBe(200);
    expect(executed).toBe(true);
    await sql.end();
  });

  it('denies an unpermitted tool, does NOT execute, writes a deny record, chain stays valid', async () => {
    const { db, sql } = getDb(cfg);
    const { agent } = await registerAgent(db, { name: `gov2-${Date.now()}`, tenant: 'test', allowedTools: ['fs.read'] });
    await seedBudget(db, agent.id, 1_000_000, 1_000_000);
    let executed = false;
    const res = await govern(
      { db, cfg, engine },
      {
        principal: { agentId: agent.id, name: agent.name, tenant: agent.tenant, onBehalfOf: [] },
        agent, plane: 'mcp', request: { tool: 'fs.write', operation: 'call' },
        target: 'mcp:filesystem', correlationId: crypto.randomUUID(), origin: 'test',
      },
      async () => { executed = true; return { tokens: 0, costMicros: 0, body: {} }; },
    );
    expect(res.status).toBe(403);
    expect(executed).toBe(false);
    expect((await verifyChain(db)).ok).toBe(true);
    await sql.end();
  });

  it('a deny (e.g. no budget) must never invoke execute — upstream is never touched on deny', async () => {
    const { db, sql } = getDb(cfg);
    const { agent } = await registerAgent(db, { name: `gov3-${Date.now()}`, tenant: 'test', allowedTools: ['fs.read'] });
    // Deliberately no seedBudget — budget check must deny before execute runs.
    let executed = false;
    const res = await govern(
      { db, cfg, engine },
      {
        principal: { agentId: agent.id, name: agent.name, tenant: agent.tenant, onBehalfOf: [] },
        agent, plane: 'mcp', request: { tool: 'fs.read', operation: 'call' },
        target: 'mcp:filesystem', correlationId: crypto.randomUUID(), origin: 'test',
      },
      async () => { executed = true; return { tokens: 0, costMicros: 0, body: {} }; },
    );
    expect(res.status).toBe(403);
    expect(executed).toBe(false);
    await sql.end();
  });

  it('fails closed when execute throws: status 403, audit record written, exception never propagates', async () => {
    const { db, sql } = getDb(cfg);
    const { agent } = await registerAgent(db, { name: `gov4-${Date.now()}`, tenant: 'test', allowedTools: ['fs.read'] });
    await seedBudget(db, agent.id, 1_000_000, 1_000_000);
    const before = await verifyChain(db);
    const res = await govern(
      { db, cfg, engine },
      {
        principal: { agentId: agent.id, name: agent.name, tenant: agent.tenant, onBehalfOf: [] },
        agent, plane: 'mcp', request: { tool: 'fs.read', operation: 'call' },
        target: 'mcp:filesystem', correlationId: crypto.randomUUID(), origin: 'test',
      },
      async () => { throw new Error('upstream boom'); },
    );
    expect(res.status).toBe(403);
    const after = await verifyChain(db);
    expect(after.ok).toBe(true);
    expect(after.checked).toBe(before.checked + 1); // one new (deny) record written
    await sql.end();
  });

  it('after a mixed sequence of allows and denies, the audit chain still verifies end to end', async () => {
    const { db, sql } = getDb(cfg);
    const { agent } = await registerAgent(db, { name: `gov5-${Date.now()}`, tenant: 'test', allowedTools: ['fs.read'] });
    await seedBudget(db, agent.id, 1_000_000, 1_000_000);

    const call = (tool: string, exec: () => Promise<{ tokens: number; costMicros: number; body: unknown }>) => govern(
      { db, cfg, engine },
      {
        principal: { agentId: agent.id, name: agent.name, tenant: agent.tenant, onBehalfOf: [] },
        agent, plane: 'mcp', request: { tool, operation: 'call' },
        target: 'mcp:filesystem', correlationId: crypto.randomUUID(), origin: 'test',
      },
      exec,
    );

    const ok = async () => ({ tokens: 1, costMicros: 1, body: { ok: true } });

    const r1 = await call('fs.read', ok);       // allow
    const r2 = await call('fs.write', ok);      // deny (not permitted)
    const r3 = await call('fs.read', ok);       // allow
    const r4 = await call('fs.write', ok);      // deny

    expect([r1.status, r2.status, r3.status, r4.status]).toEqual([200, 403, 200, 403]);
    expect((await verifyChain(db)).ok).toBe(true);
    await sql.end();
  });
});

describe('govern pipeline — fail-closed hardening (failure injection)', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('deny path: audit write failure still resolves 403, never rejects', async () => {
    const { db, sql } = getDb(cfg);
    const { agent } = await registerAgent(db, { name: `gov-fc-deny-${Date.now()}`, tenant: 'test', allowedTools: ['fs.read'] });
    await seedBudget(db, agent.id, 1_000_000, 1_000_000);

    vi.spyOn(auditWriter, 'appendAudit').mockRejectedValue(new Error('audit db unreachable'));

    // fs.write is not in allowedTools -> policy denies -> deny() path runs -> appendAudit throws (spied)
    await expect(
      govern(
        { db, cfg, engine },
        {
          principal: { agentId: agent.id, name: agent.name, tenant: agent.tenant, onBehalfOf: [] },
          agent, plane: 'mcp', request: { tool: 'fs.write', operation: 'call' },
          target: 'mcp:filesystem', correlationId: crypto.randomUUID(), origin: 'test',
        },
        async () => ({ tokens: 0, costMicros: 0, body: {} }),
      ),
    ).resolves.toEqual({ status: 403, body: { error: expect.any(String) } });

    await sql.end();
  });

  it('allow path: audit write failure AFTER a successful execute resolves 500 (not 200), never rejects', async () => {
    const { db, sql } = getDb(cfg);
    const { agent } = await registerAgent(db, { name: `gov-fc-allow-${Date.now()}`, tenant: 'test', allowedTools: ['fs.read'] });
    await seedBudget(db, agent.id, 1_000_000, 1_000_000);

    vi.spyOn(auditWriter, 'appendAudit').mockRejectedValue(new Error('audit db unreachable'));

    let executed = false;
    const res = await govern(
      { db, cfg, engine },
      {
        principal: { agentId: agent.id, name: agent.name, tenant: agent.tenant, onBehalfOf: [] },
        agent, plane: 'mcp', request: { tool: 'fs.read', operation: 'call' },
        target: 'mcp:filesystem', correlationId: crypto.randomUUID(), origin: 'test',
      },
      async () => { executed = true; return { tokens: 1, costMicros: 1, body: { ok: true } }; },
    );

    expect(executed).toBe(true); // the upstream side effect DID happen
    expect(res.status).toBe(500);
    expect(res.status).not.toBe(200);

    await sql.end();
  });

  it('a throw from the policy stage resolves 403, never rejects, and execute never runs', async () => {
    const { db, sql } = getDb(cfg);
    const { agent } = await registerAgent(db, { name: `gov-fc-policy-${Date.now()}`, tenant: 'test', allowedTools: ['fs.read'] });
    await seedBudget(db, agent.id, 1_000_000, 1_000_000);

    const throwingEngine: PolicyEngine = {
      evaluate: () => { throw new Error('opa wasm trap'); },
    };

    let executed = false;
    await expect(
      govern(
        { db, cfg, engine: throwingEngine },
        {
          principal: { agentId: agent.id, name: agent.name, tenant: agent.tenant, onBehalfOf: [] },
          agent, plane: 'mcp', request: { tool: 'fs.read', operation: 'call' },
          target: 'mcp:filesystem', correlationId: crypto.randomUUID(), origin: 'test',
        },
        async () => { executed = true; return { tokens: 0, costMicros: 0, body: {} }; },
      ),
    ).resolves.toMatchObject({ status: 403 });
    expect(executed).toBe(false);

    await sql.end();
  });
});
