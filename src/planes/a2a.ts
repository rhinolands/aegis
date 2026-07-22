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
// MCP plane (src/planes/mcp.ts): accepting a caller-supplied destination and
// then mediating a call toward it on the caller's behalf is a
// credential/destination-exfiltration primitive. An authenticated agent that
// is allowlisted to reach peer B could otherwise redirect the gateway (and
// anything it injects for that peer) to a server it controls. The peer's
// destination is always resolved server-side from the operator-registered
// scoped_credentials row for (agentId, `a2a:${peer}`) instead. zod's default
// object mode ("strip") drops any unknown key — including a caller-supplied
// upstreamUrl — before `parsed.data` is ever read, so a request that still
// sends one has it silently discarded rather than acted on in any way.
const bodySchema = z.object({
  operation: z.string(),
  args: z.record(z.string(), z.unknown()).default({}),
});

export function registerA2aPlane(app: FastifyInstance, deps: ServerDeps): void {
  app.post('/a2a/:peer', async (req, reply) => {
    const { db, cfg, engine } = deps;
    const peer = (req.params as { peer: string }).peer;

    // Identity comes ONLY from the authenticated credential (x-api-key /
    // Bearer JWT) — never from the request body or the :peer param.
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

    // A2A is the delegation boundary: extend the on-behalf-of chain with the
    // calling agent's own name before mediating to the peer, so the audit
    // trail (who.identity.onBehalfOf, via govern()'s baseRecord) and the
    // outbound x-on-behalf-of header both reflect the real delegation path.
    const callerPrincipal = { ...principal, onBehalfOf: [...principal.onBehalfOf, principal.name] };

    const result = await govern(
      { db, cfg, engine },
      {
        principal: callerPrincipal,
        agent,
        plane: 'a2a',
        request: { peer, operation },
        target: `a2a:${peer}`,
        correlationId: (req.headers['x-correlation-id'] as string) ?? randomUUID(),
        origin: req.ip,
        args,
      },
      async () => {
        // The destination is resolved from the SAME operator-registered row
        // that would hold any scoped credential for this peer — never from
        // the request body — so an agent cannot redirect this mediated call
        // to a server it controls.
        const registered = await getCredentialTarget(db, cfg, principal.agentId, `a2a:${peer}`);
        if (!registered || !registered.upstreamUrl) {
          // Fail closed: no registered destination for this (agent, peer)
          // means there is nowhere authorized to send this request. Throwing
          // here is caught by govern(), which records a deny and returns
          // 403 — we must never fall back to any caller-supplied value.
          throw new Error('no registered upstream destination for this peer');
        }
        const upstream = await fetch(registered.upstreamUrl, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'x-on-behalf-of': callerPrincipal.onBehalfOf.join('>'),
          },
          body: JSON.stringify({ operation, args }),
        });
        const body = await upstream.json().catch(() => ({}));
        if (!upstream.ok) throw new Error(`peer ${upstream.status}`);
        return { tokens: 0, costMicros: 0, body };
      },
    );
    return reply.code(result.status).send(result.body);
  });
}
