import { describe, it, expect, beforeAll } from 'vitest';
import { buildServer } from '../src/server.js';
import { loadConfig } from '../src/config.js';
import { getDb } from '../src/db/client.js';
import { loadPolicy, type PolicyEngine } from '../src/policy/opa.js';

const cfg = loadConfig({
  DATABASE_URL: 'postgres://u:p@localhost:5432/db',
  AUDIT_MASTER_KEY: Buffer.alloc(32, 7).toString('base64'),
} as NodeJS.ProcessEnv);

let engine: PolicyEngine;
beforeAll(async () => { engine = await loadPolicy('dist/policy.wasm'); });

describe('GET /health', () => {
  it('returns ok', async () => {
    // Constructing the postgres client does not open a connection until a
    // query runs, so this fake DATABASE_URL is safe here — /health never
    // touches db/engine, only buildServer's decoration requires them present.
    const { db } = getDb(cfg);
    const app = buildServer({ cfg, db, engine });
    const res = await app.inject({ method: 'GET', url: '/health' });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ status: 'ok' });
    await app.close();
  });
});
