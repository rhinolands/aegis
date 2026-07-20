import postgres, { type Sql } from 'postgres';
import { drizzle } from 'drizzle-orm/postgres-js';
import * as schema from './schema.js';
import type { Config } from '../config.js';

export type DrizzleDb = ReturnType<typeof drizzle<typeof schema>>;

export function getDb(cfg: Config): { sql: Sql; db: DrizzleDb } {
  const sql = postgres(cfg.databaseUrl, { max: 10 });
  const db = drizzle(sql, { schema });
  return { sql, db };
}
