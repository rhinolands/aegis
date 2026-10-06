import { createHash } from 'node:crypto';
import { userInfo } from 'node:os';
import { asc, eq } from 'drizzle-orm';
import type { DrizzleDb } from '../db/client.js';
import type { Config } from '../config.js';
import { agents, apiKeys, budgets, scopedCredentials } from '../db/schema.js';
import { argsDigest, canonical, type AuditRecord } from './record.js';
import { appendAudit } from './writer.js';

// Operator changes (register an agent, change an allowlist, set a credential or a
// destination, change a budget) are recorded in the SAME hash chain as agent calls,
// as ordinary audit records with plane 'operator'. One verifyChain() covers both.
// See docs/design/operator-audit.md.

// Who made the change and from where. In this repository the operator plane is the
// CLI scripts, with no operator credential, so `name` is ASSERTED (AEGIS_OPERATOR, or
// the OS user), not authenticated. The record says so: who.agentId is 'operator:cli'.
export interface OperatorContext {
  name: string;
  origin: string;          // e.g. 'cli:update-agent'
  correlationId: string;   // one per invocation, groups its records
  reason?: string;
}

export function operatorFromEnv(origin: string, env: NodeJS.ProcessEnv = process.env): OperatorContext {
  let name = env.AEGIS_OPERATOR?.trim();
  if (!name) {
    try { name = userInfo().username; } catch { name = 'unknown'; }
  }
  return { name, origin, correlationId: crypto.randomUUID() };
}

// The agent's full NON-SECRET configuration. Never a secret, and never a hash of one:
// a credential is represented by the sha256 of its stored ciphertext (random IV, so
// it says nothing about the secret, changes on every rotation, and can be checked
// against the stored row by anyone).
export interface AgentConfigSnapshot {
  name: string;
  tenant: string;
  active: boolean;
  allowedTools: string[];
  allowedPeers: string[];
  allowedModels: string[];
  apiKeys: Array<{ id: string; active: boolean }>;
  credentials: Array<{ target: string; upstreamUrl: string | null; fingerprint: string }>;
  budget: { tokenLimit: number; costLimitMicros: number } | null;
}

export async function agentConfigSnapshot(db: DrizzleDb, agentName: string): Promise<AgentConfigSnapshot | null> {
  const [agent] = await db.select().from(agents).where(eq(agents.name, agentName)).limit(1);
  if (!agent) return null;
  const keys = await db.select({ id: apiKeys.id, active: apiKeys.active }).from(apiKeys)
    .where(eq(apiKeys.agentId, agent.id)).orderBy(asc(apiKeys.id));
  const creds = await db.select().from(scopedCredentials).where(eq(scopedCredentials.agentId, agent.id));
  const [budget] = await db.select().from(budgets).where(eq(budgets.agentId, agent.id)).limit(1);
  return {
    name: agent.name,
    tenant: agent.tenant,
    active: agent.active,
    allowedTools: agent.allowedTools,
    allowedPeers: agent.allowedPeers,
    allowedModels: agent.allowedModels,
    apiKeys: keys,
    credentials: creds
      .map((c) => ({
        target: c.target,
        upstreamUrl: c.upstreamUrl,
        fingerprint: createHash('sha256').update(c.secretCiphertext).digest('hex'),
      }))
      .sort((a, b) => (a.target + a.fingerprint).localeCompare(b.target + b.fingerprint)),
    budget: budget ? { tokenLimit: budget.tokenLimit, costLimitMicros: budget.costLimitMicros } : null,
  };
}

export async function agentConfigDigest(db: DrizzleDb, agentName: string): Promise<string | null> {
  const snap = await agentConfigSnapshot(db, agentName);
  return snap ? argsDigest(snap) : null;
}

// What differs between two snapshots, as field names. Credentials are compared per
// target, so a destination change and a rotation of one target name that target.
export function changedFields(before: AgentConfigSnapshot | null, after: AgentConfigSnapshot | null): string[] {
  if (!before || !after) return Object.keys(after ?? before ?? {}).sort();
  const fields: string[] = [];
  for (const key of Object.keys(after) as Array<keyof AgentConfigSnapshot>) {
    if (key === 'credentials') continue;
    if (canonical(before[key]) !== canonical(after[key])) fields.push(key);
  }
  const byTarget = (s: AgentConfigSnapshot) => {
    const m = new Map<string, string[]>();
    for (const c of s.credentials) m.set(c.target, [...(m.get(c.target) ?? []), canonical(c)]);
    return m;
  };
  const b = byTarget(before), a = byTarget(after);
  for (const target of [...new Set([...b.keys(), ...a.keys()])].sort()) {
    if (canonical(b.get(target) ?? []) !== canonical(a.get(target) ?? [])) fields.push(`credentials[${target}]`);
  }
  return fields;
}

// The readable side of a change: for each changed field, its value before and after.
// Everything in a snapshot is non-secret by construction (a credential is its target,
// destination and ciphertext fingerprint), so the values can be recorded in clear. The
// digests say THAT the configuration changed and let anyone check a claimed state.
// The values say WHAT it became, so a reader does not have to guess.
export function changedValues(
  before: AgentConfigSnapshot | null, after: AgentConfigSnapshot | null, fields: string[],
): Record<string, { before: unknown; after: unknown }> {
  const pick = (snap: AgentConfigSnapshot | null, field: string): unknown => {
    if (!snap) return null;
    const target = /^credentials\[(.+)\]$/.exec(field)?.[1];
    if (target !== undefined) return snap.credentials.filter((c) => c.target === target);
    return snap[field as keyof AgentConfigSnapshot];
  };
  const values: Record<string, { before: unknown; after: unknown }> = {};
  for (const field of fields) values[field] = { before: pick(before, field), after: pick(after, field) };
  return values;
}

// Runs one config write and appends its operator record in ONE transaction: if the
// audit append fails, the write rolls back. A config change through the tooling
// cannot land without its record.
export async function auditedChange<T>(
  db: DrizzleDb, cfg: Config, op: OperatorContext,
  change: { agentName: string; operation: string },
  mutate: (tx: DrizzleDb) => Promise<T>,
): Promise<T> {
  return db.transaction(async (rawTx) => {
    // A transaction exposes the same query API; appendAudit() opens a nested
    // transaction (a savepoint) on it.
    const tx = rawTx as unknown as DrizzleDb;
    const before = await agentConfigSnapshot(tx, change.agentName);
    const result = await mutate(tx);
    const after = await agentConfigSnapshot(tx, change.agentName);
    const fields = changedFields(before, after);
    const changeRecord = {
      fields,
      before: before ? argsDigest(before) : null,
      after: after ? argsDigest(after) : null,
      values: changedValues(before, after, fields),
    };
    const rec: AuditRecord = {
      id: crypto.randomUUID(),
      ts: new Date().toISOString(),
      tenant: after?.tenant ?? before?.tenant ?? 'unknown',
      plane: 'operator',
      who: { agentId: 'operator:cli', identity: { agent: op.name, onBehalfOf: [] } },
      what: {
        target: `agent:${change.agentName}`,
        operation: change.operation,
        argsDigest: argsDigest(changeRecord),
        change: changeRecord,
      },
      whenWhere: { origin: op.origin, correlationId: op.correlationId },
      why: { reason: op.reason ?? 'operator change' },
      verdict: 'allow',        // the change was applied
      policyVersion: 'none',   // no policy bounds operator changes yet
      subjectKeyId: null,
    };
    await appendAudit(tx, cfg, rec);
    return result;
  });
}
