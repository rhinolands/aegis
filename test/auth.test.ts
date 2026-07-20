import { describe, it, expect } from 'vitest';
import { getDb } from '../src/db/client.js';
import { loadConfig } from '../src/config.js';
import { registerAgent } from '../src/identity/registry.js';
import { authenticateApiKey, AuthError } from '../src/auth/authenticate.js';

const cfg = loadConfig(process.env);

describe('authenticate (api-key)', () => {
  it('resolves a principal from a valid key', async () => {
    const { db, sql } = getDb(cfg);
    const { agent, apiKey } = await registerAgent(db, { name: `au-${Date.now()}`, tenant: 'test' });
    const p = await authenticateApiKey(db, apiKey);
    expect(p.agentId).toBe(agent.id);
    expect(p.onBehalfOf).toEqual([]);
    await sql.end();
  });
  it('rejects an unknown key (fail closed)', async () => {
    const { db, sql } = getDb(cfg);
    await expect(authenticateApiKey(db, 'aegis_bogus')).rejects.toBeInstanceOf(AuthError);
    await sql.end();
  });
});
