#!/usr/bin/env -S npx tsx
// Updates an ALREADY-REGISTERED agent: its model allowlist, its scoped upstream
// credential, and its budget limits. `scripts/register.ts` is INSERT-only and
// `agents.name` is globally unique, so re-registering an existing agent is
// impossible — without this CLI there is no way to change any of the above
// short of hand-written SQL, and the three live Acme lane agents sit at
// `allowed_models = []`, which denies every LLM call by deny-by-default.
//
// Usage:
//   AEGIS_UPSTREAM_SECRET=... npx tsx scripts/update-agent.ts \
//     --agent-name <name> \
//     [--allow-model <model-id>]... \
//     [--set-credential] [--upstream-url <origin>] \
//     [--token-limit <n>] [--cost-limit-micros <n>]
//
// Also available as `npm run update-agent -- --agent-name …`.
//
// CREDENTIAL CUSTODY — a deliberate divergence from register.ts.
//   register.ts takes the credential as a command-line flag. This CLI does NOT,
//   and no flag here will ever accept one. A flag value lands in the operator's
//   shell history and is visible in `ps` output to every other process on the
//   box for the lifetime of the run, and the value handled here is the FIRST
//   real upstream vendor key to enter the Aegis database — every surface it can
//   leak through is new. It is read from the AEGIS_UPSTREAM_SECRET environment
//   variable only. It is never logged, never echoed, and never appears in the
//   completion JSON — not the value, and not a prefix, suffix, length or hash
//   of it, since all four are useful to an attacker and none are useful to an
//   operator who already has the key.
//
// WHY THE PRICE GATE LIVES HERE.
//   Every `--allow-model` value is checked against MODEL_PRICES before anything
//   is written. This CLI is the only way `allowed_models` can be set, so
//   refusing an unpriced model here makes the allowlist/price-table divergence
//   structurally UNREACHABLE rather than merely logged: a model that is allowed
//   but unpriced meters $0 forever, which makes a cost cap vacuous while looking
//   correct. The `unpriced_model` log line the LLM plane emits at request time
//   (plan 45-01) is the runtime backstop; this is the prevention.
//
// WHY THE CREDENTIAL WRITE IS DELETE-THEN-INSERT-THEN-COUNT.
//   `scoped_credentials` has NO unique constraint on (agent_id, target) — only
//   `id` is a primary key — `putCredential` is a plain INSERT with no conflict
//   clause, and `getCredentialTarget` resolves with `.limit(1)` and no
//   `ORDER BY`. A duplicate row therefore makes it non-deterministic which
//   credential the gateway actually uses: it could pick the garbage placeholder
//   the seed script wrote instead of the real key. So this deletes every
//   existing row for the pair, inserts exactly one, and then asserts the count
//   is 1 — refusing to report success on a state it cannot vouch for.
//
// WHAT THIS DELIBERATELY DOES NOT TOUCH.
//   The tools allowlist column. It carries an ["acme-none"] placeholder on the
//   live lane agents, it belongs to Phase 46, and this CLI has no flag for it.

import { and, eq, sql as dsql } from 'drizzle-orm';
import { pathToFileURL } from 'node:url';
import { loadConfig, type Config } from '../src/config.js';
import { getDb, type DrizzleDb } from '../src/db/client.js';
import { agents, budgets, scopedCredentials } from '../src/db/schema.js';
import { putCredential } from '../src/credentials/store.js';
import { seedBudget } from '../src/guard/budget.js';
import { MODEL_PRICES } from '../src/pricing/models.js';

/** The one scoped-credential target this CLI manages. */
export const LLM_TARGET = 'llm:anthropic';

/** Bare origin of the Anthropic API. The raw route appends the path itself. */
export const DEFAULT_UPSTREAM_ORIGIN = 'https://api.anthropic.com';

export interface UpdateAgentOptions {
  /** Globally-unique agent name, e.g. `acme-advisor-<acme-tenant-uuid>`. */
  agentName: string;
  /** When present, REPLACES the allowlist with exactly this set. Absent = leave alone. */
  allowModels?: string[];
  /** Replace the scoped upstream credential. Requires `secret`. */
  setCredential?: boolean;
  /** Read from AEGIS_UPSTREAM_SECRET by the CLI. Never a flag, never logged. */
  secret?: string;
  /** Origin only — no path. Defaults to the Anthropic API origin. */
  upstreamUrl?: string;
  tokenLimit?: number;
  costLimitMicros?: number;
}

export interface UpdateAgentResult {
  agentId: string;
  name: string;
  allowedModels: string[];
  /** Rows for (agent, llm:anthropic). The invariant is that this is 1 after a replacement. */
  credentialRowCount: number;
  upstreamUrl: string | null;
  budget: { tokenLimit: number; costLimitMicros: number } | null;
}

const USAGE = `usage: update-agent.ts --agent-name <name>
                       [--allow-model <model-id>]...
                       [--set-credential] [--upstream-url <origin>]
                       [--token-limit <n>] [--cost-limit-micros <n>]

Updates an already-registered agent. --allow-model is repeatable and REPLACES
the model allowlist with exactly the supplied set; every value must have a
MODEL_PRICES entry or nothing is written. --set-credential replaces the
(agent, ${LLM_TARGET}) credential in place and reads the upstream secret from
the AEGIS_UPSTREAM_SECRET environment variable — never from a flag.`;

interface Args {
  agentName?: string;
  models: string[];
  setCredential: boolean;
  upstreamUrl?: string;
  tokenLimit?: number;
  costLimitMicros?: number;
}

function parseArgs(argv: string[]): Args {
  const args: Args = { models: [], setCredential: false };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    const next = (): string => {
      const v = argv[++i];
      if (v === undefined) throw new Error(`missing value for ${flag}`);
      return v;
    };
    switch (flag) {
      case '--agent-name': args.agentName = next(); break;
      case '--allow-model': args.models.push(next().trim()); break;
      case '--set-credential': args.setCredential = true; break;
      case '--upstream-url': args.upstreamUrl = next(); break;
      case '--token-limit': args.tokenLimit = Number(next()); break;
      case '--cost-limit-micros': args.costLimitMicros = Number(next()); break;
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

/**
 * Every supplied model must be priced. Throws listing the offending ids AND the
 * full priced set, so an operator who hit the exact-match hazard (a dated model
 * variant that shares a family price but not its key) can see immediately what
 * the table actually contains.
 */
function assertPriced(models: string[]): void {
  const unpriced = models.filter((m) => MODEL_PRICES[m] === undefined);
  if (unpriced.length > 0) {
    throw new Error(
      `refusing to allowlist model(s) with no MODEL_PRICES entry: ${unpriced.join(', ')}. ` +
      `An allowlisted-but-unpriced model meters 0 cost forever, which makes the budget cap ` +
      `vacuous. Priced model ids are: ${Object.keys(MODEL_PRICES).join(', ')}. ` +
      `Nothing was written.`,
    );
  }
}

/**
 * The upstream destination must be a bare https origin. The raw route appends
 * `/v1/messages` itself, so a path stored here produces
 * `…/v1/messages/v1/messages` and a 404 that reads like a gateway bug. Rejecting
 * a non-https scheme also keeps the injected credential off the wire in clear.
 */
function assertOriginOnly(raw: string): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`--upstream-url is not a valid URL: ${raw}`);
  }
  if (url.protocol !== 'https:') {
    throw new Error(`--upstream-url must use https (got ${url.protocol.replace(':', '')}): ${raw}`);
  }
  if ((url.pathname !== '' && url.pathname !== '/') || url.search !== '' || url.hash !== '') {
    throw new Error(
      `--upstream-url must be a bare origin with no path, query or fragment (got ${raw}); ` +
      `the raw route appends the request path itself`,
    );
  }
  return url.origin;
}

function dedupe(values: string[]): string[] {
  return [...new Set(values.filter((v) => v.length > 0))];
}

/**
 * The whole update, as one callable so the live-DB suite can drive it directly
 * (`main()` below only parses argv). ALL validation runs before the FIRST write:
 * a half-configured agent is a worse outcome than a refused command.
 */
export async function updateAgent(
  db: DrizzleDb, cfg: Config, opts: UpdateAgentOptions,
): Promise<UpdateAgentResult> {
  // ---- validation, all of it, before anything is written ----
  const models = opts.allowModels === undefined ? undefined : dedupe(opts.allowModels);
  if (models !== undefined) assertPriced(models);

  let upstreamOrigin: string | undefined;
  let secret: string | undefined;
  if (opts.setCredential === true) {
    secret = opts.secret;
    if (secret === undefined || secret.trim().length === 0) {
      throw new Error(
        'AEGIS_UPSTREAM_SECRET is unset or blank — it holds the upstream key and is never ' +
        'accepted as a command-line flag. Export it for this one command only, e.g. ' +
        'AEGIS_UPSTREAM_SECRET="$(cat /path/to/key)" npm run update-agent -- …',
      );
    }
    upstreamOrigin = assertOriginOnly(opts.upstreamUrl ?? DEFAULT_UPSTREAM_ORIGIN);
  }

  const wantsBudget = opts.tokenLimit !== undefined || opts.costLimitMicros !== undefined;
  if (opts.tokenLimit !== undefined && !Number.isFinite(opts.tokenLimit)) {
    throw new Error('--token-limit must be a number');
  }
  if (opts.costLimitMicros !== undefined && !Number.isFinite(opts.costLimitMicros)) {
    throw new Error('--cost-limit-micros must be a number');
  }

  const [agent] = await db.select().from(agents).where(eq(agents.name, opts.agentName)).limit(1);
  if (!agent) {
    throw new Error(
      `unknown agent name: ${opts.agentName}. Agent names are globally unique and Acme's lane ` +
      `agents follow the tenant-qualified convention acme-{lane}-{acme-tenant-uuid} ` +
      `(lane = advisor | architect | governance). Nothing was written.`,
    );
  }

  // ---- writes ----
  let allowedModels = agent.allowedModels;
  if (models !== undefined) {
    // Single UPDATE scoped by id, replacing the whole array. The tools allowlist
    // column is deliberately not in this SET clause (Phase 46 owns it).
    const [updated] = await db.update(agents)
      .set({ allowedModels: models })
      .where(eq(agents.id, agent.id))
      .returning();
    allowedModels = updated.allowedModels;
  }

  const credWhere = and(
    eq(scopedCredentials.agentId, agent.id),
    eq(scopedCredentials.target, LLM_TARGET),
  );

  if (opts.setCredential === true) {
    // DELETE-then-INSERT, never a bare INSERT: there is no unique constraint to
    // stop a second row and no ORDER BY on the read that would make a duplicate
    // resolve predictably.
    await db.delete(scopedCredentials).where(credWhere);
    await putCredential(db, cfg, agent.id, LLM_TARGET, secret as string, upstreamOrigin as string);
  }

  // Hard post-condition. Reported on every run, asserted only when we wrote —
  // a read-only invocation should not fail because of pre-existing damage it
  // was not asked to repair.
  const [{ n }] = await db
    .select({ n: dsql<number>`count(*)::int` })
    .from(scopedCredentials)
    .where(credWhere);
  const credentialRowCount = Number(n);
  if (opts.setCredential === true && credentialRowCount !== 1) {
    throw new Error(
      `credential replacement left ${credentialRowCount} rows for (${agent.id}, ${LLM_TARGET}); ` +
      `exactly 1 is required or credential selection is non-deterministic`,
    );
  }

  const [existingBudget] = await db.select().from(budgets)
    .where(eq(budgets.agentId, agent.id)).limit(1);

  let budget: { tokenLimit: number; costLimitMicros: number } | null =
    existingBudget
      ? { tokenLimit: existingBudget.tokenLimit, costLimitMicros: existingBudget.costLimitMicros }
      : null;

  if (wantsBudget) {
    const tokenLimit = opts.tokenLimit ?? existingBudget?.tokenLimit;
    const costLimitMicros = opts.costLimitMicros ?? existingBudget?.costLimitMicros;
    if (tokenLimit === undefined || costLimitMicros === undefined) {
      throw new Error(
        'this agent has no budget row yet, so --token-limit and --cost-limit-micros must be ' +
        'supplied together',
      );
    }
    // Reuse the existing idempotent budget writer rather than forking a second
    // one. It sets the two LIMIT columns only, so the running meter columns are
    // untouched — raising a cap must never silently refund spend.
    await seedBudget(db, agent.id, tokenLimit, costLimitMicros);
    budget = { tokenLimit, costLimitMicros };
  }

  const [row] = await db.select().from(scopedCredentials).where(credWhere).limit(1);

  return {
    agentId: agent.id,
    name: agent.name,
    allowedModels,
    credentialRowCount,
    upstreamUrl: row?.upstreamUrl ?? null,
    budget,
  };
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
  if (!args.agentName) missing.push('--agent-name');
  const badNumber =
    (args.tokenLimit !== undefined && !Number.isFinite(args.tokenLimit)) ||
    (args.costLimitMicros !== undefined && !Number.isFinite(args.costLimitMicros));
  if (missing.length > 0 || badNumber) {
    if (missing.length > 0) console.error(`missing required flag(s): ${missing.join(', ')}`);
    if (badNumber) console.error('--token-limit and --cost-limit-micros must be numbers');
    console.error(USAGE);
    process.exit(1);
  }

  // Read the secret from the environment, and fail before the database is even
  // opened if it is not there. Nothing downstream ever prints this value.
  const secret = process.env.AEGIS_UPSTREAM_SECRET;
  if (args.setCredential && (secret === undefined || secret.trim().length === 0)) {
    console.error(
      '--set-credential requires the AEGIS_UPSTREAM_SECRET environment variable to be set to ' +
      'the upstream key. It is deliberately not accepted as a flag: flag values land in shell ' +
      'history and in `ps` output.',
    );
    console.error(USAGE);
    process.exit(1);
  }

  const cfg = loadConfig(process.env);
  const { db, sql } = getDb(cfg);
  try {
    const result = await updateAgent(db, cfg, {
      agentName: args.agentName!,
      ...(args.models.length > 0 ? { allowModels: args.models } : {}),
      ...(args.setCredential ? { setCredential: true, secret } : {}),
      ...(args.upstreamUrl !== undefined ? { upstreamUrl: args.upstreamUrl } : {}),
      ...(args.tokenLimit !== undefined ? { tokenLimit: args.tokenLimit } : {}),
      ...(args.costLimitMicros !== undefined ? { costLimitMicros: args.costLimitMicros } : {}),
    });

    // Completion record. Deliberately carries no credential material of any
    // kind — only the destination, which is operator-supplied and not secret.
    console.log(JSON.stringify({
      agentId: result.agentId,
      name: result.name,
      allowedModels: result.allowedModels,
      credential: {
        target: LLM_TARGET,
        rowCount: result.credentialRowCount,
        upstreamUrl: result.upstreamUrl,
        replaced: args.setCredential,
      },
      budget: result.budget,
    }, null, 2));
  } finally {
    await sql.end();
  }
}

// Only run when invoked as the entry point. register.ts calls main()
// unconditionally, but this module is also imported by test/update-agent.test.ts
// to drive updateAgent() directly, and an unconditional call would fire — and
// exit the test process — on import.
const entry = process.argv[1];
if (entry !== undefined && import.meta.url === pathToFileURL(entry).href) {
  main().catch((err) => {
    console.error('update-agent failed:', (err as Error).message);
    process.exit(1);
  });
}
