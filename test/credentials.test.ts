import { describe, it, expect } from 'vitest';
import { getDb } from '../src/db/client.js';
import { loadConfig } from '../src/config.js';
import { registerAgent } from '../src/identity/registry.js';
import { putCredential, getCredential } from '../src/credentials/store.js';

const cfg = loadConfig(process.env);

describe('scoped credential store', () => {
  it('stores encrypted and retrieves plaintext for the owning agent', async () => {
    const { db, sql } = getDb(cfg);
    const { agent } = await registerAgent(db, { name: `cred-${Date.now()}`, tenant: 'test' });
    await putCredential(db, cfg, agent.id, 'mcp:filesystem', 'super-secret-token');
    expect(await getCredential(db, cfg, agent.id, 'mcp:filesystem')).toBe('super-secret-token');
    expect(await getCredential(db, cfg, agent.id, 'mcp:unknown')).toBeNull();
    await sql.end();
  });

  it('never returns another agent\'s credential for the same target (agent isolation)', async () => {
    const { db, sql } = getDb(cfg);
    const { agent: agentA } = await registerAgent(db, { name: `cred-a-${Date.now()}`, tenant: 'test' });
    const { agent: agentB } = await registerAgent(db, { name: `cred-b-${Date.now()}`, tenant: 'test' });

    await putCredential(db, cfg, agentA.id, 'mcp:filesystem', 'agent-a-secret');

    // Agent B queries the same target agent A stored a credential for.
    expect(await getCredential(db, cfg, agentB.id, 'mcp:filesystem')).toBeNull();
    // Agent A's own credential is still correctly retrievable.
    expect(await getCredential(db, cfg, agentA.id, 'mcp:filesystem')).toBe('agent-a-secret');

    await sql.end();
  });
});
