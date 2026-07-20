import { describe, it, expect, beforeAll } from 'vitest';
import { getDb } from '../src/db/client.js';
import { loadConfig } from '../src/config.js';
import { agents } from '../src/db/schema.js';

const cfg = loadConfig(process.env);
let reachable = true;

describe('db', () => {
  beforeAll(async () => {
    try { const { sql } = getDb(cfg); await sql`select 1`; await sql.end(); }
    catch { reachable = false; }
  });
  it('inserts and reads an agent', async () => {
    if (!reachable) return; // skip when no DB
    const { db, sql } = getDb(cfg);
    const [row] = await db.insert(agents).values({ name: `t-${Date.now()}`, tenant: 'test' }).returning();
    expect(row.id).toBeTruthy();
    await sql.end();
  });
});
