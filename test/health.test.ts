import { describe, it, expect } from 'vitest';
import { buildServer } from '../src/server.js';
import { loadConfig } from '../src/config.js';

const cfg = loadConfig({
  DATABASE_URL: 'postgres://u:p@localhost:5432/db',
  AUDIT_MASTER_KEY: Buffer.alloc(32, 7).toString('base64'),
} as NodeJS.ProcessEnv);

describe('GET /health', () => {
  it('returns ok', async () => {
    const app = buildServer(cfg);
    const res = await app.inject({ method: 'GET', url: '/health' });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ status: 'ok' });
    await app.close();
  });
});
