#!/usr/bin/env -S npx tsx
// Operator entry point for verifyChain(). Read-only: it runs SELECTs inside a
// read-only transaction and reads local files, nothing else.
//
// Usage:
//   npx tsx scripts/verify.ts                         in-database check only
//   npx tsx scripts/verify.ts --manifest <path>       also compare against an export
//
// --manifest points at a downloaded export manifest (audit/<day>/manifest.json)
// with its segment file(s) in the same directory. No object-store access is
// needed or attempted: the comparison works from the local copy.
//
// Prints the verification result as one JSON line. Exit code: 0 verified,
// 1 verification failed, 2 bad usage or an unusable export.

import { realpathSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { loadConfig } from '../src/config.js';
import { getDb, type DrizzleDb } from '../src/db/client.js';
import { verifyChain } from '../src/audit/verify.js';
import { readExportAnchor } from '../src/audit/export.js';

const USAGE = `usage: verify.ts [--manifest <path/to/manifest.json>]

Verifies the audit hash chain in the live database: every hash link, then the
tail against chain_head. With --manifest, also requires every exported record
and the exported chain head to be present in the live chain with the same hash.
The manifest and its segment files are read from local disk.`;

export function parseArgs(argv: string[]): { manifest?: string } {
  const args: { manifest?: string } = {};
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === '--manifest') {
      const v = argv[++i];
      if (v === undefined) throw new Error('missing value for --manifest');
      args.manifest = v;
    } else {
      throw new Error(`unknown flag: ${flag}`);
    }
  }
  return args;
}

// DB handle injected so the wiring is testable without spawning a process.
export async function runVerify(db: DrizzleDb, argv: string[]): Promise<{ exitCode: number; output: string }> {
  let anchor;
  try {
    const { manifest } = parseArgs(argv);
    if (manifest) anchor = await readExportAnchor(manifest);
  } catch (err) {
    return { exitCode: 2, output: (err as Error).message };
  }
  const result = await verifyChain(db, anchor);
  return { exitCode: result.ok ? 0 : 1, output: JSON.stringify(result) };
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  if (argv.includes('--help') || argv.includes('-h')) {
    console.log(USAGE);
    return;
  }
  const { db, sql } = getDb(loadConfig(process.env));
  try {
    const { exitCode, output } = await runVerify(db, argv);
    if (exitCode === 2) {
      console.error(output);
      console.error(USAGE);
    } else {
      console.log(output);
    }
    process.exitCode = exitCode;
  } finally {
    await sql.end();
  }
}

// Run the CLI only when executed directly, not when imported (e.g. by the test
// importing runVerify). Importing must not open a DB connection.
const invokedDirectly =
  !!process.argv[1] &&
  import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href;

if (invokedDirectly) {
  main().catch((err) => {
    console.error('verify failed:', (err as Error).message);
    process.exit(2);
  });
}
