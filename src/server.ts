import Fastify, { type FastifyInstance } from 'fastify';
import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';
import type { Config } from './config.js';

export function buildServer(cfg: Config): FastifyInstance {
  const app = Fastify({ logger: false });
  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);
  app.decorate('config', cfg);
  app.get('/health', async () => ({ status: 'ok' }));
  return app;
}

declare module 'fastify' {
  interface FastifyInstance { config: Config }
}
