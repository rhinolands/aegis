import { createHash } from 'node:crypto';

export interface IdentityChain { agent: string; onBehalfOf: string[] }
export interface AuditWho { agentId: string; identity: IdentityChain }
export interface AuditWhat { target: string; operation: string; argsDigest: string }
export interface AuditWhenWhere { origin: string; correlationId: string }
export interface AuditWhy { reason: string; approval?: { by: string; granted: boolean } }

export interface AuditRecord {
  id: string;
  ts: string;                 // ISO 8601
  tenant: string;
  plane: 'mcp' | 'a2a' | 'llm' | 'approval';
  who: AuditWho;
  what: AuditWhat;
  whenWhere: AuditWhenWhere;
  why: AuditWhy;
  verdict: 'allow' | 'deny';
  policyVersion: string;
  subjectKeyId: string | null;
}

// Deterministic JSON with recursively sorted keys — the hashed representation.
export function canonical(value: unknown): string {
  return JSON.stringify(sort(value));
}
function sort(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sort);
  if (v && typeof v === 'object') {
    return Object.fromEntries(Object.keys(v as object).sort().map((k) => [k, sort((v as Record<string, unknown>)[k])]));
  }
  return v;
}

export function argsDigest(args: unknown): string {
  return createHash('sha256').update(canonical(args)).digest('hex');
}
