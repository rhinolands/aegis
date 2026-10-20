import type { AgentRow } from '../identity/registry.js';
import { canonical } from '../audit/record.js';

export type Plane = 'mcp' | 'a2a' | 'llm';

export interface PolicyRequest {
  tool?: string;
  peer?: string;
  model?: string;
  operation: string;
  // The call arguments, for argument-level rules (data.aegis_constraints in the
  // Rego). Evaluated in memory only: the audit record still stores just the
  // argsDigest, never the raw arguments.
  args?: Record<string, unknown>;
}

export interface PolicyInput {
  plane: Plane;
  agent: { name: string; tenant: string; allowedTools: string[]; allowedPeers: string[]; allowedModels: string[] };
  request: PolicyRequest;
}

// The policy gets a JSON-safe copy built by canonical(), the same total
// serializer the audit digest uses, so BigInt, circular references, throwing
// getters or hostile proxies in caller args cannot make the WASM input
// unserialisable (which would fail closed on a call that never had arguments
// constrained). A non-object args value becomes {}, so a constrained argument is
// simply missing and the policy fails closed instead of reading into a string or
// array.
function plainArgs(args: unknown): Record<string, unknown> {
  if (args === null || typeof args !== 'object' || Array.isArray(args)) return {};
  try {
    const safe: unknown = JSON.parse(canonical(args));
    return safe !== null && typeof safe === 'object' && !Array.isArray(safe) ? (safe as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

export function buildInput(plane: Plane, agent: AgentRow, request: PolicyRequest, args?: unknown): PolicyInput {
  return {
    plane,
    agent: {
      name: agent.name, tenant: agent.tenant,
      allowedTools: agent.allowedTools, allowedPeers: agent.allowedPeers, allowedModels: agent.allowedModels,
    },
    request: { ...request, args: plainArgs(args) },
  };
}
