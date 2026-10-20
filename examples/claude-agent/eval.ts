// Phase 4 eval: every scenario runs as a fresh live agent session against
// the same aegis-registered identity. Grading is done afterwards by
// eval/grade.mjs from the joined logs, never by a model.
import { writeFileSync } from 'node:fs';
import { loadIdentity, setRunTag } from './lib/aegis.js';
import { runAgent } from './lib/agent.js';
import { opsTools, OPS_SYSTEM_PROMPT, COMPLIANT_SYSTEM_PROMPT, type CallRecord } from './lib/tools.js';
// Plain JS module shared with the grader.
import { SCENARIOS } from './eval/scenarios.mjs';

const REPS = Number(process.env.EVAL_REPS ?? 3);
const ONLY = process.env.EVAL_ONLY?.split(',');
// EVAL_AGENT=compliant runs the simulated compromised agent (see lib/tools.ts).
const SYSTEM = process.env.EVAL_AGENT === 'compliant' ? COMPLIANT_SYSTEM_PROMPT : OPS_SYSTEM_PROMPT;
const id = loadIdentity();
const runs: { scenario: string; category: string; rep: number; calls: CallRecord[]; costUsd: number; subtype: string; result: string }[] = [];

for (const s of SCENARIOS as { id: string; category: string; prompt: string }[]) {
  if (ONLY && !ONLY.includes(s.id)) continue;
  for (let rep = 1; rep <= REPS; rep++) {
    setRunTag(`${s.id}-r${rep}`);
    const calls: CallRecord[] = [];
    const tools = opsTools(id, (tool, args, r, correlationId) => calls.push({ correlationId, tool, args, status: r.status }));
    try {
      const r = await runAgent({
        model: process.env.AGENT_MODEL ?? 'claude-sonnet-5-5',
        systemPrompt: SYSTEM,
        prompt: s.prompt,
        tools,
        maxTurns: 10,
        maxBudgetUsd: 0.5,
        log: () => {},
      });
      runs.push({ scenario: s.id, category: s.category, rep, calls, costUsd: r.costUsd, subtype: r.subtype, result: r.result });
      console.log(`${s.id} r${rep}: ${calls.map((c) => `${c.tool}:${c.status}`).join(' ') || '(no tool calls)'}  $${r.costUsd.toFixed(4)}`);
    } catch (e) {
      runs.push({ scenario: s.id, category: s.category, rep, calls, costUsd: 0, subtype: 'error', result: String(e) });
      console.log(`${s.id} r${rep}: ERROR ${String(e)}`);
    }
  }
}

const total = runs.reduce((a, r) => a + r.costUsd, 0);
console.log(`\n${runs.length} sessions, SDK cost estimate $${total.toFixed(4)}`);
if (process.env.CALLS_OUT) {
  writeFileSync(process.env.CALLS_OUT, JSON.stringify({ calls: runs.flatMap((r) => r.calls), runs, costUsd: total }, null, 2));
}
