import { describe, it, expect, beforeAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadPolicy, type PolicyEngine } from '../src/policy/opa.js';
import { buildInput } from '../src/policy/input.js';
import { loadConfig } from '../src/config.js';
import { getDb } from '../src/db/client.js';
import { registerAgent } from '../src/identity/registry.js';
import { seedBudget } from '../src/guard/budget.js';
import { govern } from '../src/pipeline/govern.js';

const agent = { id: 'a', name: 'a', tenant: 't', allowedTools: ['fs.read'], allowedPeers: [], allowedModels: [], active: true, createdAt: new Date() };

// The product bundle plus one operator constraints file, compiled to WASM the
// same way scripts/build-policy.sh does. Proves the argument rules (regex.match
// included) evaluate inside the WASM engine, not only under `opa test`.
const CONSTRAINTS = String.raw`package aegis_constraints

tools := {"fs.read": {"path": {
	"allow": ["^(docs|notes)/[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$"],
	"deny": ["(^|/)\\.", "(^|/)\\.\\.(/|$)"],
}}}
`;

let engine: PolicyEngine;
beforeAll(async () => {
  const dir = mkdtempSync(join(tmpdir(), 'aegis-args-'));
  writeFileSync(join(dir, 'constraints.rego'), CONSTRAINTS);
  execFileSync('opa', ['build', '-t', 'wasm', '-e', 'gateway/decision', '-o', join(dir, 'b.tar.gz'), 'policy/bundle', dir]);
  execFileSync('tar', ['-xzf', join(dir, 'b.tar.gz'), '-C', dir, '/policy.wasm'], { stdio: 'ignore' });
  engine = await loadPolicy(join(dir, 'policy.wasm'));
});

describe('policy input carries tool arguments', () => {
  it('puts a plain-object args value on request.args', () => {
    const input = buildInput('mcp', agent as any, { tool: 'fs.read', operation: 'call' }, { path: 'notes/a.md' });
    expect(input.request.args).toEqual({ path: 'notes/a.md' });
  });
  it('normalises a non-object args value to {} so a constrained argument fails closed', () => {
    for (const bad of [null, undefined, 'notes/a.md', ['notes/a.md'], 42]) {
      expect(buildInput('mcp', agent as any, { tool: 'fs.read', operation: 'call' }, bad).request.args).toEqual({});
    }
  });
});

describe('argument constraints in the WASM engine', () => {
  const call = (args: unknown) => engine.evaluate(buildInput('mcp', agent as any, { tool: 'fs.read', operation: 'call' }, args));

  it('allows an argument that matches an allow pattern', () => {
    expect(call({ path: 'notes/a.md' })).toMatchObject({ allow: true, reason: 'tool allowed' });
  });
  it.each([
    ['outside the allowed prefixes', 'config/.env.production'],
    ['a hidden file inside an allowed prefix', 'notes/.env'],
    ['path traversal', 'notes/../config/.env.production'],
  ])('denies %s', (_label, path) => {
    expect(call({ path })).toMatchObject({ allow: false, reason: 'argument not allowed' });
  });
  it('denies when the constrained argument is missing', () => {
    expect(call({})).toMatchObject({ allow: false, reason: 'argument not allowed' });
  });
});

describe('govern() hands the call arguments to the policy', () => {
  it('evaluates with ctx.args on request.args', async () => {
    const cfg = loadConfig(process.env);
    const { db, sql } = getDb(cfg);
    const { agent: row } = await registerAgent(db, { name: `gov-args-${Date.now()}`, tenant: 'test', allowedTools: ['fs.read'] });
    await seedBudget(db, row.id, 1_000_000, 1_000_000);

    let seen: unknown;
    const spy: PolicyEngine = {
      evaluate: (input) => { seen = input.request.args; return { allow: false, reason: 'spy', policyVersion: 'spy' }; },
    };
    await govern(
      { db, cfg, engine: spy },
      {
        principal: { agentId: row.id, name: row.name, tenant: row.tenant, onBehalfOf: [] },
        agent: row, plane: 'mcp', request: { tool: 'fs.read', operation: 'call' },
        target: 'mcp:fs.read', correlationId: crypto.randomUUID(), origin: 'test', args: { path: 'notes/a.md' },
      },
      async () => ({ tokens: 0, costMicros: 0, body: {} }),
    );
    expect(seen).toEqual({ path: 'notes/a.md' });
    await sql.end();
  });
});

describe('policy args are always serialisable', () => {
  it('turns BigInt and circular args into a JSON-safe copy instead of breaking the WASM input', () => {
    const circular: Record<string, unknown> = { path: 'notes/a.md', n: 10n };
    circular.self = circular;
    const input = buildInput('mcp', agent as any, { tool: 'fs.read', operation: 'call' }, circular);
    expect(() => JSON.stringify(input)).not.toThrow();
    expect(input.request.args?.path).toBe('notes/a.md');
    expect(engine.evaluate(input)).toMatchObject({ allow: true, reason: 'tool allowed' });
  });
});
