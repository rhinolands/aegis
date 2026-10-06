import postgres, { type Sql, type TransactionSql } from 'postgres';
import type { Config } from '../../src/config.js';

// Shared by the test files that tamper with (or depend on the exact shape of) the
// single global chain. Not a test file itself: vitest only collects *.test.ts.

// Resets the chain to empty through the explicit owner-level bypass. max: 1 because
// the script carries its own BEGIN/COMMIT, which postgres.js only allows on a
// single-connection client.
export async function resetChain(cfg: Config): Promise<void> {
  const sql = postgres(cfg.databaseUrl, { max: 1 });
  await sql.file('scripts/reset-dev-chain.sql');
  await sql.end();
}

// Simulate an attacker holding owner DB credentials: disable the append-only triggers,
// mutate, re-enable. One transaction: DDL is transactional, so the disabled-trigger
// state is never committed/visible to other sessions.
export async function asOwner(sql: Sql, mutate: (tx: TransactionSql) => Promise<unknown>): Promise<void> {
  await sql.begin(async (tx) => {
    await tx`alter table audit_records disable trigger user`;
    await tx`alter table chain_head disable trigger user`;
    await mutate(tx);
    await tx`alter table audit_records enable trigger user`;
    await tx`alter table chain_head enable trigger user`;
  });
}
