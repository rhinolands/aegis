#!/usr/bin/env -S npx tsx
// Read-only operator lens over the append-only audit spine. Answers "what just
// happened for correlation id X" legibly — who / what / why / verdict, one line
// per gateway decision — without hand-joining raw JSONB or reaching for a stale
// S3 export. It is the fresh-read companion to Acme's scripts/join-aegis-audit.sh
// (its column set is a superset of that script's AEGIS projection, so an operator
// can eyeball-join the two outputs on the shared correlation id).
//
// This tool is STRICTLY read-only: a single SELECT, no INSERT/UPDATE/DELETE, no
// schema object created, no weakening of the tamper-evident chain. It projects
// metadata columns ONLY — the encrypted payload column is never selected, never
// printed, and there is no plaintext-recovery path anywhere in this file.
//
// Usage:
//   npx tsx scripts/ledger.ts --correlation-id <uuid> [--tenant <t>] [--verdict allow|deny]
//
// --correlation-id is REQUIRED. An untenanted "all rows" dump is refused by
// construction (mirrors join-aegis-audit.sh's tenant-predicate discipline):
// the correlation id is the mandatory filter, --tenant/--verdict further scope it.

import { and, asc, eq, sql } from 'drizzle-orm';
import { loadConfig } from '../src/config.js';
import { getDb } from '../src/db/client.js';
import { auditRecords } from '../src/db/schema.js';
import type { AuditWho, AuditWhat, AuditWhenWhere, AuditWhy } from '../src/audit/record.js';

interface Args {
  correlationId?: string;
  tenant?: string;
  verdict?: string;
}

const USAGE = `usage: ledger.ts --correlation-id <uuid> [--tenant <t>] [--verdict allow|deny]

Read-only projection of audit_records for one correlation id: who / what / why /
verdict, one line per decision, ordered by seq. --correlation-id is required.
Never selects or prints the encrypted payload column; renders metadata only.`;

// The columns emitted, in order. A superset of join-aegis-audit.sh's AEGIS_SQL
// (seq, plane, verdict, target, reason, corr, ts) so the two can be eyeball-joined.
export const HEADER = 'seq|ts|tenant|plane|verdict|agentId|target|operation|reason|correlationId';

// The shape formatRow needs — a projected audit row. The encrypted payload
// column is deliberately absent from this type: it is neither selected nor rendered.
export interface LedgerRow {
  seq: number | bigint;
  ts: Date | string;
  tenant: string;
  plane: string;
  verdict: string;
  who: Partial<AuditWho> | null | unknown;
  what: Partial<AuditWhat> | null | unknown;
  whenWhere: Partial<AuditWhenWhere> | null | unknown;
  why: Partial<AuditWhy> | null | unknown;
}

// Pure, DB-free row->line formatter (unit-testable without Postgres). Projects
// exactly the metadata columns; the encrypted payload is structurally unreachable
// from here because LedgerRow carries no ciphertext field.
export function formatRow(row: LedgerRow): string {
  const who = (row.who ?? {}) as Partial<AuditWho>;
  const what = (row.what ?? {}) as Partial<AuditWhat>;
  const whenWhere = (row.whenWhere ?? {}) as Partial<AuditWhenWhere>;
  const why = (row.why ?? {}) as Partial<AuditWhy>;
  const ts = row.ts instanceof Date ? row.ts.toISOString() : String(row.ts);
  return [
    String(row.seq),
    ts,
    row.tenant,
    row.plane,
    row.verdict,
    who.agentId ?? '',
    what.target ?? '',
    what.operation ?? '',
    why.reason ?? '',
    whenWhere.correlationId ?? '',
  ].join('|');
}

function parseArgs(argv: string[]): Args {
  const args: Args = {};
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    const next = () => {
      const v = argv[++i];
      if (v === undefined) throw new Error(`missing value for ${flag}`);
      return v;
    };
    switch (flag) {
      case '--correlation-id': args.correlationId = next(); break;
      case '--tenant': args.tenant = next(); break;
      case '--verdict': args.verdict = next(); break;
      case '--help':
      case '-h':
        console.log(USAGE);
        process.exit(0);
        break;
      default:
        throw new Error(`unknown flag: ${flag}`);
    }
  }
  return args;
}

async function main(): Promise<void> {
  let args: Args;
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (err) {
    console.error((err as Error).message);
    console.error(USAGE);
    process.exit(1);
  }

  if (!args!.correlationId) {
    console.error('missing required flag: --correlation-id');
    console.error(USAGE);
    process.exit(1);
  }
  if (args!.verdict !== undefined && args!.verdict !== 'allow' && args!.verdict !== 'deny') {
    console.error("--verdict must be one of: allow, deny");
    console.error(USAGE);
    process.exit(1);
  }

  const cfg = loadConfig(process.env);
  const { db, sql: pg } = getDb(cfg);
  try {
    const predicate = and(
      // JSONB text-extraction operator; correlation id is the mandatory filter.
      sql`${auditRecords.whenWhere}->>'correlationId' = ${args!.correlationId}`,
      args!.tenant ? eq(auditRecords.tenant, args!.tenant) : undefined,
      args!.verdict ? eq(auditRecords.verdict, args!.verdict) : undefined,
    );

    // Explicit projection: metadata columns ONLY. The encrypted payload column is
    // not listed, so it never leaves Postgres.
    const rows = await db
      .select({
        seq: auditRecords.seq,
        ts: auditRecords.ts,
        tenant: auditRecords.tenant,
        plane: auditRecords.plane,
        verdict: auditRecords.verdict,
        who: auditRecords.who,
        what: auditRecords.what,
        whenWhere: auditRecords.whenWhere,
        why: auditRecords.why,
      })
      .from(auditRecords)
      .where(predicate)
      .orderBy(asc(auditRecords.seq));

    console.log(HEADER);
    for (const row of rows) {
      console.log(formatRow(row as unknown as LedgerRow));
    }
    console.error(`\n${rows.length} row(s) for correlation id ${args!.correlationId}`);
  } finally {
    await pg.end();
  }
}

main().catch((err) => {
  console.error('ledger failed:', (err as Error).message);
  process.exit(1);
});
