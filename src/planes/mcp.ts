import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import type { FastifyInstance } from 'fastify';
import { eq } from 'drizzle-orm';
import type { ServerDeps } from '../server.js';
import { authenticate, AuthError } from '../auth/authenticate.js';
import { agents } from '../db/schema.js';
import { getCredentialTarget } from '../credentials/store.js';
import { govern } from '../pipeline/govern.js';

// upstreamUrl is deliberately NOT part of this schema. Accepting a caller-
// supplied destination and then attaching the gateway's scoped backend
// credential to it is a credential-exfiltration primitive: an authenticated
// agent with an allowlisted tool could point upstreamUrl at a server it
// controls and receive the secret it otherwise never holds. The destination
// is always resolved server-side from the operator-registered
// scoped_credentials row for (agentId, target) instead. zod's default object
// mode ("strip") drops any unknown key — including a caller-supplied
// upstreamUrl — before `parsed.data` is ever read, so a request that still
// sends one has it silently discarded rather than acted on in any way.
const bodySchema = z.object({
  operation: z.string(),
  args: z.record(z.string(), z.unknown()).default({}),
});

export function registerMcpPlane(app: FastifyInstance, deps: ServerDeps): void {
  app.post('/mcp/:tool', async (req, reply) => {
    const { db, cfg, engine } = deps;
    const tool = (req.params as { tool: string }).tool;

    // Identity comes ONLY from the authenticated credential (x-api-key /
    // Bearer JWT) — never from the request body or the :tool param.
    let principal;
    try {
      principal = await authenticate(db, cfg, req);
    } catch (e) {
      if (e instanceof AuthError) return reply.code(403).send({ error: 'unauthenticated' });
      throw e;
    }

    const parsed = bodySchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: 'bad request' });
    const { operation, args } = parsed.data;

    const [agent] = await db.select().from(agents).where(eq(agents.id, principal.agentId)).limit(1);
    if (!agent) return reply.code(403).send({ error: 'unknown agent' });

    // Normalized ONCE, here, and read from this const everywhere below —
    // including the upstream forward in execute(). A second read of
    // req.headers would reintroduce the raw caller string and could let the
    // audited record and the relayed header disagree.
    const correlationId = (req.headers['x-correlation-id'] as string) ?? randomUUID();

    const result = await govern(
      { db, cfg, engine },
      {
        principal,
        agent,
        plane: 'mcp',
        request: { tool, operation },
        target: `mcp:${tool}`,
        correlationId,
        origin: req.ip,
        args,
      },
      async () => {
        // Gateway injects the scoped backend credential for mcp:<tool> as the
        // upstream Authorization header — the calling agent never holds it,
        // it only ever presents its own gateway-issued x-api-key. The
        // destination is resolved from the SAME operator-registered row as
        // the credential — never from the request body — so an agent cannot
        // redirect its own scoped credential to a server it controls.
        const registered = await getCredentialTarget(db, cfg, principal.agentId, `mcp:${tool}`);
        if (!registered || !registered.upstreamUrl) {
          // Fail closed: no registered destination for this (agent, tool) means
          // there is nowhere authorized to send this request. Throwing here is
          // caught by govern(), which records a deny and returns 403 — we must
          // never fall back to any caller-supplied value.
          throw new Error('no registered upstream destination for this tool');
        }
        const headers: Record<string, string> = { 'content-type': 'application/json' };
        headers['authorization'] = `Bearer ${registered.secret}`;
        // G6 (Acme Phase 47 / AGW-08): relay the caller's correlation id to the
        // operator-registered upstream so the backend's own audit row can be
        // joined to this gateway record. Server-authored from the SAME
        // normalized `correlationId` the govern context is built from, never
        // re-read from the request — so the relayed header and the audited
        // record can never disagree. This is an opaque correlation token only:
        // it selects no destination, carries no authority, and gates nothing.
        // The destination and the credential still come solely from the
        // operator-registered row.
        headers['x-correlation-id'] = correlationId;
        // redirect: 'manual' + explicit 3xx rejection below: a mediated call
        // must terminate at the operator-registered destination and must
        // never be silently redirected elsewhere. Node 22's undici happens to
        // strip Authorization on a cross-origin redirect, but that is runtime
        // behaviour we do not control and must not rely on — this asserts the
        // safety property in our own code instead.
        const upstream = await fetch(registered.upstreamUrl, {
          method: 'POST',
          headers,
          body: JSON.stringify({ operation, args }),
          redirect: 'manual',
        });
        if (upstream.status >= 300 && upstream.status < 400) {
          throw new Error(`upstream attempted redirect (${upstream.status})`);
        }
        const body = await upstream.json().catch(() => ({}));
        if (!upstream.ok) throw new Error(`upstream ${upstream.status}`);
        return { tokens: 0, costMicros: 0, body };
      },
    );
    return reply.code(result.status).send(result.body);
  });
}
