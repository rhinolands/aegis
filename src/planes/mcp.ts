import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import type { FastifyInstance } from 'fastify';
import { eq } from 'drizzle-orm';
import type { ServerDeps } from '../server.js';
import { authenticate, AuthError } from '../auth/authenticate.js';
import { agents } from '../db/schema.js';
import { getCredential } from '../credentials/store.js';
import { govern } from '../pipeline/govern.js';

const bodySchema = z.object({
  operation: z.string(),
  args: z.record(z.string(), z.unknown()).default({}),
  upstreamUrl: z.string().url(),
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
    const { operation, args, upstreamUrl } = parsed.data;

    const [agent] = await db.select().from(agents).where(eq(agents.id, principal.agentId)).limit(1);
    if (!agent) return reply.code(403).send({ error: 'unknown agent' });

    const result = await govern(
      { db, cfg, engine },
      {
        principal,
        agent,
        plane: 'mcp',
        request: { tool, operation },
        target: `mcp:${tool}`,
        correlationId: (req.headers['x-correlation-id'] as string) ?? randomUUID(),
        origin: req.ip,
        args,
      },
      async () => {
        // Gateway injects the scoped backend credential for mcp:<tool> as the
        // upstream Authorization header — the calling agent never holds it,
        // it only ever presents its own gateway-issued x-api-key.
        const cred = await getCredential(db, cfg, principal.agentId, `mcp:${tool}`);
        const headers: Record<string, string> = { 'content-type': 'application/json' };
        if (cred) headers['authorization'] = `Bearer ${cred}`;
        const upstream = await fetch(upstreamUrl, {
          method: 'POST',
          headers,
          body: JSON.stringify({ operation, args }),
        });
        const body = await upstream.json().catch(() => ({}));
        if (!upstream.ok) throw new Error(`upstream ${upstream.status}`);
        return { tokens: 0, costMicros: 0, body };
      },
    );
    return reply.code(result.status).send(result.body);
  });
}
