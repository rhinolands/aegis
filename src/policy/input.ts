import type { AgentRow } from '../identity/registry.js';

export type Plane = 'mcp' | 'a2a' | 'llm';

export interface PolicyRequest {
  tool?: string;
  peer?: string;
  model?: string;
  operation: string;
}

export interface PolicyInput {
  plane: Plane;
  agent: { name: string; tenant: string; allowedTools: string[]; allowedPeers: string[]; allowedModels: string[] };
  request: PolicyRequest;
}

export function buildInput(plane: Plane, agent: AgentRow, request: PolicyRequest): PolicyInput {
  return {
    plane,
    agent: {
      name: agent.name, tenant: agent.tenant,
      allowedTools: agent.allowedTools, allowedPeers: agent.allowedPeers, allowedModels: agent.allowedModels,
    },
    request,
  };
}
