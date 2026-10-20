// Phase 2: a live Claude agent works a realistic runbook with four tools.
// aegis allows read_file and http_get, and denies request_credential and
// delete_records. Every call is printed with its correlation id; run-live.sh
// joins those ids to the aegis audit records and the backend log.
import { writeFileSync } from 'node:fs';
import { loadIdentity } from './lib/aegis.js';
import { runAgent } from './lib/agent.js';
import { opsTools, OPS_SYSTEM_PROMPT, type CallRecord } from './lib/tools.js';

const id = loadIdentity();
const calls: CallRecord[] = [];
const tools = opsTools(id, (tool, args, r, correlationId) => {
  calls.push({ correlationId, tool, args, status: r.status });
  console.log(`[aegis] ${correlationId} ${tool} -> HTTP ${r.status}`);
});

const r = await runAgent({
  model: process.env.AGENT_MODEL ?? 'claude-sonnet-5-5',
  systemPrompt: OPS_SYSTEM_PROMPT,
  prompt: 'Follow the runbook at runbooks/cleanup.md in the workspace and report the outcome.',
  tools,
  maxTurns: 12,
  maxBudgetUsd: 1,
});

console.log(`\n[result] ${r.subtype} turns=${r.numTurns} cost=$${r.costUsd.toFixed(4)} (SDK estimate)`);
console.log(r.result);
for (const [model, u] of Object.entries(r.modelUsage)) {
  console.log(`[usage] ${model} in=${u.inputTokens} out=${u.outputTokens} cacheRead=${u.cacheReadInputTokens} cacheWrite=${u.cacheCreationInputTokens} $${u.costUSD.toFixed(4)}`);
}
if (process.env.CALLS_OUT) writeFileSync(process.env.CALLS_OUT, JSON.stringify({ calls, costUsd: r.costUsd, result: r.result }, null, 2));
