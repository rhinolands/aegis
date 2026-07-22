import Fastify, { type FastifyInstance } from 'fastify';
import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';
import type { Config } from './config.js';
import type { DrizzleDb } from './db/client.js';
import type { PolicyEngine } from './policy/opa.js';
import { registerMcpPlane } from './planes/mcp.js';
import { registerA2aPlane } from './planes/a2a.js';
import { registerLlmPlane } from './planes/llm.js';

export interface ServerDeps { cfg: Config; db: DrizzleDb; engine: PolicyEngine }

export function buildServer(deps: ServerDeps): FastifyInstance {
  const app = Fastify({ logger: false });
  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);
  app.decorate('deps', deps);
  // /health stays dependency-free so it works before the DB/policy engine are reachable.
  app.get('/health', async () => ({ status: 'ok' }));
  registerMcpPlane(app, deps);
  registerA2aPlane(app, deps);
  registerLlmPlane(app, deps);
  return app;
}

declare module 'fastify' {
  interface FastifyInstance { deps: ServerDeps }
}
