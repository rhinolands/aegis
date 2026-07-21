import type { DrizzleDb } from '../db/client.js';
import type { Config } from '../config.js';
import type { Principal } from '../identity/principal.js';
import type { AgentRow } from '../identity/registry.js';
import type { PolicyEngine } from '../policy/opa.js';
import { buildInput, type Plane, type PolicyRequest } from '../policy/input.js';
import { checkRate } from '../guard/ratelimit.js';
import { ensureBudget, meterUsage } from '../guard/budget.js';
import { appendAudit } from '../audit/writer.js';
import { argsDigest, type AuditRecord } from '../audit/record.js';

export interface GovernDeps { db: DrizzleDb; cfg: Config; engine: PolicyEngine }

export interface GovernContext {
  principal: Principal;
  agent: AgentRow;
  plane: Plane;
  request: PolicyRequest;
  target: string;          // e.g. 'mcp:filesystem', 'llm:anthropic', 'a2a:agent-b'
  correlationId: string;
  origin: string;
  args?: unknown;          // hashed into what.argsDigest; raw never stored
}

export interface ExecResult { tokens: number; costMicros: number; body: unknown }

const RATE_LIMIT = 60;      // requests
const RATE_WINDOW_MS = 60_000;

export async function govern(
  deps: GovernDeps,
  ctx: GovernContext,
  execute: () => Promise<ExecResult>,
): Promise<{ status: number; body: unknown }> {
  const { db, cfg, engine } = deps;

  const baseRecord = (verdict: 'allow' | 'deny', reason: string, policyVersion: string): AuditRecord => ({
    id: crypto.randomUUID(),
    ts: new Date().toISOString(),
    tenant: ctx.principal.tenant,
    plane: ctx.plane,
    who: { agentId: ctx.principal.agentId, identity: { agent: ctx.principal.name, onBehalfOf: ctx.principal.onBehalfOf } },
    what: { target: ctx.target, operation: ctx.request.operation, argsDigest: argsDigest(ctx.args ?? null) },
    whenWhere: { origin: ctx.origin, correlationId: ctx.correlationId },
    why: { reason },
    verdict,
    policyVersion,
    subjectKeyId: `${ctx.principal.tenant}:${ctx.principal.name}`,
  });

  const deny = async (reason: string, policyVersion = 'v1'): Promise<{ status: number; body: unknown }> => {
    await appendAudit(db, cfg, baseRecord('deny', reason, policyVersion), ctx.args);
    return { status: 403, body: { error: reason } };
  };

  // 1. rate/quota
  if (!checkRate(ctx.principal.agentId, RATE_LIMIT, RATE_WINDOW_MS)) return deny('rate limit exceeded');

  // 2. policy (deny-by-default, fail-closed inside evaluate)
  const decision = engine.evaluate(buildInput(ctx.plane, ctx.agent, ctx.request));
  if (!decision.allow) return deny(decision.reason || 'policy denied', decision.policyVersion);

  // 3. budget (fail-closed)
  const budget = await ensureBudget(db, ctx.principal.agentId);
  if (!budget.ok) return deny(budget.reason ?? 'budget exceeded', decision.policyVersion);

  // 4. execute upstream; any failure => deny + audit (fail-closed)
  let result: ExecResult;
  try {
    result = await execute();
  } catch (err) {
    return deny(`upstream error: ${(err as Error).message}`, decision.policyVersion);
  }

  // 5. meter + allow audit
  await meterUsage(db, ctx.principal.agentId, result.tokens, result.costMicros);
  await appendAudit(db, cfg, baseRecord('allow', decision.reason, decision.policyVersion), ctx.args);
  return { status: 200, body: result.body };
}
