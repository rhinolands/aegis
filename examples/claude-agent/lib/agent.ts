import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  createSdkMcpServer,
  query,
  type HookCallback,
  type PreToolUseHookInput,
  type ModelUsage,
} from '@anthropic-ai/claude-agent-sdk';
import { anthropicApiKey } from './keychain.js';

export const SERVER = 'aegis';
const PREFIX = `mcp__${SERVER}__`;

export interface RunOptions {
  prompt: string;
  systemPrompt: string;
  // Return value of governedTool(); typed loosely so callers can mix schemas.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  tools: any[];
  model: string;
  maxTurns: number;
  maxBudgetUsd: number;
  log?: (line: string) => void;
}

export interface RunResult {
  subtype: string;
  result: string;
  costUsd: number;
  numTurns: number;
  modelUsage: Record<string, ModelUsage>;
  blockedOutsideAegis: string[];
}

// Runs one agent session. The agent can reach the outside world only through
// the aegis-governed tools: every built-in tool is removed, no user or project
// settings are loaded, and a PreToolUse hook refuses any tool that is not one
// of ours (defence in depth, in case a future SDK adds a default tool).
export async function runAgent(o: RunOptions): Promise<RunResult> {
  const log = o.log ?? ((l: string) => console.log(l));
  const configDir = mkdtempSync(join(tmpdir(), 'aegis-agent-'));
  const abort = new AbortController();
  const blockedOutsideAegis: string[] = [];

  const onlyAegisTools: HookCallback = async (input) => {
    const pre = input as PreToolUseHookInput;
    if (pre.tool_name.startsWith(PREFIX) || pre.tool_name === 'ToolSearch') return {};
    blockedOutsideAegis.push(pre.tool_name);
    return {
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'deny',
        permissionDecisionReason: `${pre.tool_name} is not an aegis-governed tool`,
      },
    };
  };

  const server = createSdkMcpServer({ name: SERVER, version: '0.1.0', tools: o.tools, alwaysLoad: true });

  let out: RunResult | undefined;
  try {
    for await (const msg of query({
      prompt: o.prompt,
      options: {
        abortController: abort,
        model: o.model,
        systemPrompt: o.systemPrompt,
        maxTurns: o.maxTurns,
        maxBudgetUsd: o.maxBudgetUsd,
        tools: [],
        mcpServers: { [SERVER]: server },
        allowedTools: [`${PREFIX}*`],
        settingSources: [],
        persistSession: false,
        hooks: { PreToolUse: [{ hooks: [onlyAegisTools] }] },
        // Replaces the subprocess environment: nothing inherited except PATH,
        // a throwaway config dir (no user login, no user hooks), and the key.
        env: {
          PATH: process.env.PATH,
          HOME: configDir,
          CLAUDE_CONFIG_DIR: configDir,
          ANTHROPIC_API_KEY: anthropicApiKey(),
        },
      },
    })) {
      if (msg.type === 'system' && msg.subtype === 'init') {
        // Billing guard: refuse to continue unless the session is billed to
        // the API key from the Keychain (not a subscription login).
        if (msg.apiKeySource !== 'ANTHROPIC_API_KEY') {
          abort.abort();
          throw new Error(`refusing to run: apiKeySource is "${msg.apiKeySource}", expected ANTHROPIC_API_KEY`);
        }
        log(`[init] model=${msg.model} apiKeySource=${msg.apiKeySource} tools=${msg.tools.join(',')}`);
      } else if (msg.type === 'assistant') {
        for (const block of msg.message.content) {
          if (block.type === 'tool_use') log(`[claude -> tool] ${block.name} ${JSON.stringify(block.input)}`);
          else if (block.type === 'text' && block.text.trim()) log(`[claude] ${block.text.trim()}`);
        }
      } else if (msg.type === 'result') {
        out = {
          subtype: msg.subtype,
          result: msg.subtype === 'success' ? msg.result : '',
          costUsd: msg.total_cost_usd,
          numTurns: msg.num_turns,
          modelUsage: msg.modelUsage,
          blockedOutsideAegis,
        };
      }
    }
  } finally {
    rmSync(configDir, { recursive: true, force: true });
  }
  if (!out) throw new Error('agent ended without a result message');
  return out;
}
