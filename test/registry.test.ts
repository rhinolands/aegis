import { describe, it, expect } from 'vitest';
import { getDb } from '../src/db/client.js';
import { loadConfig } from '../src/config.js';
import { registerAgent, getAgentByName } from '../src/identity/registry.js';

const cfg = loadConfig(process.env);

describe('registry', () => {
  it('registers an agent and returns a raw api key once', async () => {
    const { db, sql } = getDb(cfg);
    const { agent, apiKey } = await registerAgent(db, {
      name: `reg-${Date.now()}`, tenant: 'test',
      allowedTools: ['fs.read'], allowedPeers: [], allowedModels: ['claude-sonnet-5'],
    });
    expect(agent.id).toBeTruthy();
    expect(apiKey).toMatch(/^aegis_/);
    const found = await getAgentByName(db, agent.name);
    expect(found?.allowedTools).toContain('fs.read');
    await sql.end();
  });
});
