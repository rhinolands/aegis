#!/usr/bin/env -S npx tsx
// Registers an agent end-to-end: identity + allowlists, a budget, and a scoped
// credential with its operator-registered upstream URL. This is the only way
// to onboard an agent in v0.1 — there is no admin HTTP plane by design, so
// this CLI is the full registration surface.
//
// Usage:
//   npx tsx scripts/register.ts \
//     --name <agent-name> --tenant <tenant> \
//     --tool <tool>[,<tool2>,...] \
//     [--peer <peer>[,...]] [--model <model>[,...]] \
//     [--token-limit <n>] [--cost-limit-micros <n>] \
//     --cred-target <target> --cred-secret <secret> --upstream-url <url>
//
// Notes:
//   --tool is required (at least one). --peer and --model are optional
//   allowlists. --cred-target/--cred-secret/--upstream-url are required
//   together: a plane denies fail-closed without a registered upstream URL,
//   so an agent registered without one cannot make a governed call.
//   The raw API key is printed exactly once, in the final JSON — it is never
//   recoverable afterward. Nothing you pass on the command line is logged.

import { loadConfig } from '../src/config.js';
import { getDb } from '../src/db/client.js';
import { registerAgent } from '../src/identity/registry.js';
import { seedBudget } from '../src/guard/budget.js';
import { putCredential } from '../src/credentials/store.js';

interface Args {
  name?: string;
  tenant?: string;
  tools: string[];
  peers: string[];
  models: string[];
  tokenLimit: number;
  costLimitMicros: number;
  credTarget?: string;
  credSecret?: string;
  upstreamUrl?: string;
}

const USAGE = `usage: register.ts --name <name> --tenant <tenant> --tool <tool>[,<tool2>,...]
                    [--peer <peer>[,...]] [--model <model>[,...]]
                    [--token-limit <n>] [--cost-limit-micros <n>]
                    --cred-target <target> --cred-secret <secret> --upstream-url <url>

Registers an agent, seeds its budget, and stores a scoped credential with its
upstream URL. Prints the new agent's raw API key exactly once, as JSON.`;

function splitList(v: string): string[] {
  return v.split(',').map((s) => s.trim()).filter(Boolean);
}

function parseArgs(argv: string[]): Args {
  const args: Args = { tools: [], peers: [], models: [], tokenLimit: 1_000_000, costLimitMicros: 1_000_000 };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    const next = () => {
      const v = argv[++i];
      if (v === undefined) throw new Error(`missing value for ${flag}`);
      return v;
    };
    switch (flag) {
      case '--name': args.name = next(); break;
      case '--tenant': args.tenant = next(); break;
      case '--tool': args.tools.push(...splitList(next())); break;
      case '--peer': args.peers.push(...splitList(next())); break;
      case '--model': args.models.push(...splitList(next())); break;
      case '--token-limit': args.tokenLimit = Number(next()); break;
      case '--cost-limit-micros': args.costLimitMicros = Number(next()); break;
      case '--cred-target': args.credTarget = next(); break;
      case '--cred-secret': args.credSecret = next(); break;
      case '--upstream-url': args.upstreamUrl = next(); break;
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

  const missing: string[] = [];
  if (!args.name) missing.push('--name');
  if (!args.tenant) missing.push('--tenant');
  if (args.tools.length === 0) missing.push('--tool');
  if (!args.credTarget) missing.push('--cred-target');
  if (!args.credSecret) missing.push('--cred-secret');
  if (!args.upstreamUrl) missing.push('--upstream-url');
  if (missing.length > 0 || !Number.isFinite(args.tokenLimit) || !Number.isFinite(args.costLimitMicros)) {
    if (missing.length > 0) console.error(`missing required flag(s): ${missing.join(', ')}`);
    if (!Number.isFinite(args.tokenLimit) || !Number.isFinite(args.costLimitMicros)) {
      console.error('--token-limit and --cost-limit-micros must be numbers');
    }
    console.error(USAGE);
    process.exit(1);
  }

  const cfg = loadConfig(process.env);
  const { db, sql } = getDb(cfg);
  try {
    const { agent, apiKey } = await registerAgent(db, {
      name: args.name!,
      tenant: args.tenant!,
      allowedTools: args.tools,
      allowedPeers: args.peers,
      allowedModels: args.models,
    });
    await seedBudget(db, agent.id, args.tokenLimit, args.costLimitMicros);
    await putCredential(db, cfg, agent.id, args.credTarget!, args.credSecret!, args.upstreamUrl);

    // Print exactly once: this is the only time the raw key is ever visible.
    console.log(JSON.stringify({
      agentId: agent.id,
      name: agent.name,
      tenant: agent.tenant,
      allowedTools: agent.allowedTools,
      allowedPeers: agent.allowedPeers,
      allowedModels: agent.allowedModels,
      budget: { tokenLimit: args.tokenLimit, costLimitMicros: args.costLimitMicros },
      credential: { target: args.credTarget, upstreamUrl: args.upstreamUrl },
      apiKey,
    }, null, 2));
  } finally {
    await sql.end();
  }
}

main().catch((err) => {
  console.error('register failed:', (err as Error).message);
  process.exit(1);
});
