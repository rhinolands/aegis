import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import type { FastifyInstance } from 'fastify';
import { eq } from 'drizzle-orm';
import type { ServerDeps } from '../server.js';
import { authenticate, AuthError } from '../auth/authenticate.js';
import { agents } from '../db/schema.js';
import { getCredentialTarget } from '../credentials/store.js';
import { govern } from '../pipeline/govern.js';

// upstreamUrl is deliberately NOT part of this schema — same reasoning as the
// MCP plane (src/planes/mcp.ts) and the A2A plane (src/planes/a2a.ts):
// accepting a caller-supplied destination and then attaching the gateway's
// scoped upstream API key to it is a credential-exfiltration primitive. An
// authenticated agent allowlisted for a model could otherwise point the
// request at a server it controls and receive the injected key. The
// destination is always resolved server-side from the operator-registered
// scoped_credentials row for (agentId, `llm:${upstreamStyle}`) instead.
// zod's default object mode ("strip") drops any unknown key — including a
// caller-supplied upstreamUrl — before `parsed.data` is ever read, so a
// request that still sends one has it silently discarded rather than acted
// on in any way.
const bodySchema = z.object({
  operation: z.string(),
  payload: z.record(z.string(), z.unknown()).default({}),
  upstreamStyle: z.enum(['anthropic', 'openai']),
});

// [UNVERIFIED] Illustrative placeholder pricing ONLY. These per-1k-token
// micros figures are NOT sourced from any vendor price list and must never be
// presented to a user or used for real billing as-is. Before this table
// drives any user-visible cost figure or invoice, replace every entry with
// per-model pricing verified against >=2 independent primary sources (the
// vendor's own published pricing page/API, cross-checked against a second
// source), and sanity-check the resulting math against the meter's actual
// units (per-token vs per-1k vs per-1M) per ARIA's no-naked-numbers rule.
// Shipping this table unchanged into a cost report would misrepresent an
// invented number as fact.
const COST_MICROS_PER_1K: Record<string, number> = {
  'claude-sonnet-5': 3000,
  'claude-opus-4-8': 15000,
};

// Coerce every usage field through Number(...) || 0 before arithmetic. An
// upstream is untrusted input: if it returns a field as a string (e.g.
// usage.input_tokens: "40"), naive `+` does string concatenation instead of
// addition ("40" + 60 === "4060"), silently inflating the metered token
// count (and therefore costMicros) by orders of magnitude. Number(x) || 0
// also turns NaN/undefined/null/non-numeric strings into 0 rather than
// propagating garbage into the meter.
function extractTokens(style: 'anthropic' | 'openai', body: unknown): number {
  const u = (body as { usage?: Record<string, unknown> } | null | undefined)?.usage;
  if (!u) return 0;
  const n = (v: unknown): number => Number(v) || 0;
  if (style === 'anthropic') return n(u.input_tokens) + n(u.output_tokens);
  if (u.total_tokens != null) return n(u.total_tokens);
  return n(u.prompt_tokens) + n(u.completion_tokens);
}

export function registerLlmPlane(app: FastifyInstance, deps: ServerDeps): void {
  app.post('/llm/:model', async (req, reply) => {
    const { db, cfg, engine } = deps;
    const model = (req.params as { model: string }).model;

    // Identity comes ONLY from the authenticated credential (x-api-key /
    // Bearer JWT) — never from the request body or the :model param.
    let principal;
    try {
      principal = await authenticate(db, cfg, req);
    } catch (e) {
      if (e instanceof AuthError) return reply.code(403).send({ error: 'unauthenticated' });
      throw e;
    }

    const parsed = bodySchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: 'bad request' });
    const { operation, payload, upstreamStyle } = parsed.data;

    const [agent] = await db.select().from(agents).where(eq(agents.id, principal.agentId)).limit(1);
    if (!agent) return reply.code(403).send({ error: 'unknown agent' });

    const result = await govern(
      { db, cfg, engine },
      {
        principal,
        agent,
        plane: 'llm',
        request: { model, operation },
        target: `llm:${model}`,
        correlationId: (req.headers['x-correlation-id'] as string) ?? randomUUID(),
        origin: req.ip,
        args: payload,
      },
      async () => {
        // Gateway injects the scoped upstream LLM API key for
        // llm:<upstreamStyle> — the calling agent never holds it, it only
        // ever presents its own gateway-issued x-api-key. The credential
        // target is keyed by upstreamStyle (not by :model) because a single
        // operator-registered upstream (one Anthropic key, one OpenAI key)
        // typically serves every allowlisted model of that style; the
        // destination is resolved from the SAME operator-registered row as
        // the credential — never from the request body — so an agent cannot
        // redirect its own scoped credential to a server it controls.
        const registered = await getCredentialTarget(db, cfg, principal.agentId, `llm:${upstreamStyle}`);
        if (!registered || !registered.upstreamUrl) {
          // Fail closed: no registered destination for this (agent, style)
          // means there is nowhere authorized to send this request. Throwing
          // here is caught by govern(), which records a deny and returns
          // 403 — we must never fall back to any caller-supplied value.
          throw new Error('no registered upstream destination for this llm style');
        }
        const headers: Record<string, string> = { 'content-type': 'application/json' };
        if (upstreamStyle === 'anthropic') {
          headers['x-api-key'] = registered.secret;
          headers['anthropic-version'] = '2023-06-01';
        } else {
          headers['authorization'] = `Bearer ${registered.secret}`;
        }
        // redirect: 'manual' + explicit 3xx rejection below: a mediated call
        // must terminate at the operator-registered destination and must
        // never be silently redirected elsewhere. Node 22's undici happens to
        // strip auth headers on a cross-origin redirect, but that is runtime
        // behaviour we do not control and must not rely on — this asserts the
        // safety property in our own code instead.
        // Trusted, policy-gated values (`model`, `operation`) are spread LAST,
        // after `...payload`, so they always win over any caller-supplied key
        // of the same name. `payload` is fully caller-controlled
        // (z.record(z.string(), z.unknown()), no key restriction) — if it
        // were spread last, a caller could send payload.model to silently
        // execute against a different model than the one OPA just checked
        // (input.request.model), corrupting cost accounting (costMicros is
        // computed from the gated `model` below) and falsifying the audit
        // record (`what.target` names the model that was actually gated, not
        // whatever ran upstream). Do NOT "tidy" this back to
        // `{ model, operation, ...payload }` — that reintroduces the bypass.
        const upstream = await fetch(registered.upstreamUrl, {
          method: 'POST',
          headers,
          body: JSON.stringify({ ...payload, model, operation }),
          redirect: 'manual',
        });
        if (upstream.status >= 300 && upstream.status < 400) {
          throw new Error(`upstream attempted redirect (${upstream.status})`);
        }
        const body = await upstream.json().catch(() => ({}));
        if (!upstream.ok) throw new Error(`upstream ${upstream.status}`);
        const tokens = extractTokens(upstreamStyle, body);
        const costMicros = Math.round((tokens / 1000) * (COST_MICROS_PER_1K[model] ?? 0));
        return { tokens, costMicros, body };
      },
    );
    return reply.code(result.status).send(result.body);
  });
}
