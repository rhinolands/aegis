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
import { log } from '../log.js';

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

  // deny() must NEVER throw: it is the fail-closed exit used both for genuine policy
  // denials and for unexpected faults in earlier stages. If the audit write itself
  // fails here, we still have to return 403 (the safe default) — we just log the
  // intended record at error level so it's recoverable from logs instead of the
  // audit DB, rather than letting the exception escape and turn a deny into an
  // unhandled rejection.
  const deny = async (reason: string, policyVersion = 'v1'): Promise<{ status: number; body: unknown }> => {
    // baseRecord() itself is now INSIDE this guarded try. canonical() (used by
    // argsDigest() inside baseRecord) is total as of this fix and should never throw,
    // but this is defense in depth: even a future serializer regression degrades to a
    // logged-only record and a safe 403, instead of turning a deny into an unhandled
    // rejection.
    let record: AuditRecord | undefined;
    try {
      record = baseRecord('deny', reason, policyVersion);
      await appendAudit(db, cfg, record, ctx.args);
    } catch (err) {
      log.error(
        { err, auditRecord: record },
        'govern: deny-path record construction or audit write failed; record only recoverable from this log line',
      );
    }
    return { status: 403, body: { error: reason } };
  };

  let decision: { allow: boolean; reason: string; policyVersion: string } | undefined;
  try {
    // 1. rate/quota
    if (!checkRate(ctx.principal.agentId, RATE_LIMIT, RATE_WINDOW_MS)) return await deny('rate limit exceeded');

    // 2. policy (deny-by-default, fail-closed inside evaluate)
    decision = engine.evaluate(buildInput(ctx.plane, ctx.agent, ctx.request));
    if (!decision.allow) return await deny(decision.reason || 'policy denied', decision.policyVersion);

    // 3. budget (fail-closed)
    const budget = await ensureBudget(db, ctx.principal.agentId);
    if (!budget.ok) return await deny(budget.reason ?? 'budget exceeded', decision.policyVersion);
  } catch (err) {
    // Any unexpected fault in rate/policy/budget checks (WASM trap, DB blip, etc.)
    // must degrade to a deterministic deny rather than reject govern()'s promise —
    // nothing upstream has executed yet, so fail-closed is safe and lossless.
    return deny(`pre-execution error: ${err instanceof Error ? err.message : String(err)}`, decision?.policyVersion ?? 'v1');
  }

  // 4. execute upstream; any failure => deny + audit (fail-closed)
  let result: ExecResult;
  try {
    result = await execute();
  } catch (err) {
    return deny(`upstream error: ${err instanceof Error ? err.message : String(err)}`, decision.policyVersion);
  }

  // 5. meter + allow audit. The side effect has ALREADY happened (execute() above
  // succeeded), so this block is the irreducible case: there is no rollback. If
  // metering or the audit write fails here we must NOT return 200 — that would
  // claim full success while the governance record (the system's core invariant)
  // is silently missing. We also must not let the exception propagate, since the
  // upstream action did succeed and callers need a defined response. So: log the
  // complete intended audit record at error level (recoverable/replayable from
  // logs even though it never reached Postgres) and return 500 to make the
  // partial-failure state visible to the caller instead of pretending it's fine.
  // baseRecord() construction now happens INSIDE this guarded try (previously it ran
  // before the try, so a throw from argsDigest()/canonical() — e.g. a BigInt or
  // circular value in ctx.args, both realistic caller-supplied tool arguments — would
  // escape as an unhandled rejection after execute() had already succeeded: upstream
  // action done and billed, govern() rejects, no audit record, no defined response.
  // canonical() is now total (see audit/record.ts) so this should never throw in
  // practice; this restructuring is defense in depth for a future regression.
  let allowRecord: AuditRecord | undefined;
  try {
    allowRecord = baseRecord('allow', decision.reason, decision.policyVersion);
    await meterUsage(db, ctx.principal.agentId, result.tokens, result.costMicros);
    await appendAudit(db, cfg, allowRecord, ctx.args);
  } catch (err) {
    log.error(
      { err, auditRecord: allowRecord },
      'govern: allow-path upstream executed but record construction, metering, or audit write failed; record only recoverable from this log line',
    );
    return {
      status: 500,
      body: { error: 'upstream action executed but audit record could not be written', recordId: allowRecord?.id },
    };
  }
  return { status: 200, body: result.body };
}
