import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { tool } from '@anthropic-ai/claude-agent-sdk';
import { z } from 'zod';

// The agent's own gateway identity, written by run-*.sh after register.ts.
// This is the ONLY credential the agent process holds for its tools. Backend
// credentials live in aegis and are injected only after policy allows.
export interface AgentIdentity {
  agentId: string;
  apiKey: string;
  gateway: string;
}

export function loadIdentity(path = new URL('../.agent.json', import.meta.url)): AgentIdentity {
  return JSON.parse(readFileSync(path, 'utf8')) as AgentIdentity;
}

export interface GovernedResult {
  status: number;
  body: unknown;
}

// Every tool call goes to POST /mcp/<tool>. aegis authenticates the agent,
// evaluates policy, executes against the operator-registered upstream (or
// refuses), and appends an audit record for both outcomes.
export async function callAegis(
  id: AgentIdentity,
  toolName: string,
  operation: string,
  args: Record<string, unknown>,
  correlationId?: string,
): Promise<GovernedResult> {
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    'x-api-key': id.apiKey,
  };
  if (correlationId) headers['x-correlation-id'] = correlationId;
  const res = await fetch(`${id.gateway}/mcp/${encodeURIComponent(toolName)}`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ operation, args }),
  });
  const body = await res.json().catch(() => ({}));
  return { status: res.status, body };
}

// Turns a governed result into the MCP tool result Claude reads. A refusal is
// returned as an error result, so Claude sees that the call did not happen
// and the agent loop continues.
export function toToolResult(toolName: string, r: GovernedResult) {
  if (r.status === 200) {
    return { content: [{ type: 'text' as const, text: JSON.stringify(r.body) }] };
  }
  return {
    content: [
      {
        type: 'text' as const,
        text: `aegis refused ${toolName} (HTTP ${r.status}): ${JSON.stringify(r.body)}. The call was not executed.`,
      },
    ],
    isError: true,
  };
}

// Each call carries its own correlation id. aegis stores it in the audit
// record (when_where.correlationId) and relays it to the backend, so an agent
// tool call, its audit record and any backend execution join exactly.
let runTag = process.env.RUN_TAG ?? randomUUID().slice(0, 8);
let seq = 0;

// The eval sets a tag per scenario repetition so ids read like I3-r2-1.
export function setRunTag(tag: string): void {
  runTag = tag;
  seq = 0;
}

export type OnCall = (name: string, args: Record<string, unknown>, r: GovernedResult, correlationId: string) => void;

// A governed tool: Claude sees a normal tool, the handler only forwards to aegis.
export function governedTool<S extends z.ZodRawShape>(
  id: AgentIdentity,
  name: string,
  description: string,
  shape: S,
  onCall?: OnCall,
) {
  return tool(name, description, shape, async (args) => {
    const a = args as Record<string, unknown>;
    const correlationId = `${runTag}-${++seq}`;
    const r = await callAegis(id, name, 'call', a, correlationId);
    onCall?.(name, a, r, correlationId);
    return toToolResult(name, r);
  });
}
