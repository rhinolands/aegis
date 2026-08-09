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
//     [--allow-tool <tool-name>]... \
//     [--set-credential] [--upstream-url <origin>] \
//     [--mcp-tool <tool-name>]... [--mcp-upstream-base <url>] [--secret-stdin] \
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
//   variable only, or — with --secret-stdin — from a single read of fd 0. It is
//   never logged, never echoed, and never appears in the completion JSON — not
//   the value, and not a prefix, suffix, length or hash of it, since all four
//   are useful to an attacker and none are useful to an operator who already
//   has the key.
//
//   WHY --secret-stdin EXISTS ALONGSIDE THE ENVIRONMENT VARIABLE.
//   It is a custody improvement, not a convenience: it lets a caller PIPE a
//   freshly minted credential straight into this process without the value ever
//   existing as a shell variable, a `$( … )` capture, a file, or an entry in the
//   environment of a process an operator might later dump. That is the same
//   discipline scripts/seed-aegis-identities.sh already uses for the register
//   CLI's stdout. The read happens ONCE and the value covers every row the
//   invocation writes. A flag is still refused by construction: no case in
//   parseArgs accepts a secret value.
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
//   is 1 — refusing to report success on a state it cannot vouch for. The same
//   sequence runs once PER TARGET, so writing N `mcp:<tool>` rows in a single
//   invocation gets N independent count==1 post-conditions.
//
// TWO CREDENTIAL TARGETS, TWO URL RULES — DELIBERATELY NOT SHARED.
//   `${LLM_TARGET}` points at a vendor API over the public internet: https only,
//   and a bare origin, because the raw route appends the request path itself.
//   An `mcp:<tool>` target points at an in-cluster service that mediates one
//   tool: http is permitted (there is no TLS on a cluster service DNS name) and
//   a PATH is not merely permitted but required — src/planes/mcp.ts fetches the
//   registered URL verbatim, so a base reduced to its bare origin would land
//   every mediated call on `/` and hit whatever handler happens to be there,
//   carrying an injected credential. The two rules therefore live in two
//   separate validators and neither is relaxed to accommodate the other.
//
// HOW THE TOOLS ALLOWLIST IS MANAGED (--allow-tool).
//   The column carried an ["acme-none"] placeholder on the live lane agents
//   until this flag existed; register.ts is INSERT-only and `agents.name` is
//   globally unique, so an existing lane agent could not be re-registered to
//   change it. --allow-tool now sets it, and like --allow-model it REPLACES the
//   whole array from ONE invocation. That contract is the point: a seeding
//   caller that looped, passing a single --allow-tool per run, would leave only
//   the last name allowed and deny the rest — so pass every tool the lane needs
//   as repeated flags on a single command.
//
//   There is deliberately NO price-gate twin for tools (see the validation
//   block below for the full reasoning): Aegis has no Acme tool catalog, and
//   inventing one here would be a second source of truth.

import { and, eq, sql as dsql } from 'drizzle-orm';
import { readFileSync } from 'node:fs';
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
  /** When present, REPLACES `allowed_tools` with exactly this set. Absent = leave alone. */
  allowTools?: string[];
  /** Replace the scoped upstream credential. Requires `secret`. */
  setCredential?: boolean;
  /** Read from AEGIS_UPSTREAM_SECRET or fd 0 by the CLI. Never a flag, never logged. */
  secret?: string;
  /** Origin only — no path. Defaults to the Anthropic API origin. */
  upstreamUrl?: string;
  /** Tool names to register `mcp:<tool>` credential rows for. Requires `mcpUpstreamBase`. */
  mcpTools?: string[];
  /** Base URL for the mcp rows; each row's destination is `<base>/<tool>`, path preserved. */
  mcpUpstreamBase?: string;
  tokenLimit?: number;
  costLimitMicros?: number;
}

export interface UpdateAgentResult {
  agentId: string;
  name: string;
  allowedModels: string[];
  allowedTools: string[];
  /** Rows for (agent, llm:anthropic). The invariant is that this is 1 after a replacement. */
  credentialRowCount: number;
  upstreamUrl: string | null;
  /** One entry per `mcp:<tool>` row written by THIS invocation. Empty when none were. */
  mcpCredentials: Array<{ target: string; upstreamUrl: string; rowCount: number }>;
  budget: { tokenLimit: number; costLimitMicros: number } | null;
}

const USAGE = `usage: update-agent.ts --agent-name <name>
                       [--allow-model <model-id>]...
                       [--allow-tool <tool-name>]...
                       [--set-credential] [--upstream-url <origin>]
                       [--mcp-tool <tool-name>]... [--mcp-upstream-base <url>]
                       [--secret-stdin]
                       [--token-limit <n>] [--cost-limit-micros <n>]

Updates an already-registered agent. --allow-model is repeatable and REPLACES
the model allowlist with exactly the supplied set; every value must have a
MODEL_PRICES entry or nothing is written. --set-credential replaces the
(agent, ${LLM_TARGET}) credential in place and reads the upstream secret from
the AEGIS_UPSTREAM_SECRET environment variable — never from a flag.

--allow-tool is repeatable and likewise REPLACES the tools allowlist with
exactly the supplied set. Pass every tool the lane needs in ONE invocation:
looping the command with a single --allow-tool each time leaves only the last
name allowed.

--mcp-tool is repeatable and registers one scoped credential per tool, at
target mcp:<tool>, whose destination is <--mcp-upstream-base>/<tool> with the
path preserved. The two flags are required together. The mcp base may use http
(in-cluster) and may carry a path; it may not carry a query or fragment. The
https-and-bare-origin rule for ${LLM_TARGET} is unchanged.

--secret-stdin reads the upstream secret from fd 0 exactly once and uses it for
every row written, so a caller can pipe a freshly minted credential in without
it ever becoming a shell variable. Without it the secret comes from
AEGIS_UPSTREAM_SECRET. It is never accepted as a flag.`;

interface Args {
  agentName?: string;
  models: string[];
  tools: string[];
  setCredential: boolean;
  mcpTools: string[];
  mcpUpstreamBase?: string;
  secretStdin: boolean;
  upstreamUrl?: string;
  tokenLimit?: number;
  costLimitMicros?: number;
}

function parseArgs(argv: string[]): Args {
  const args: Args = {
    models: [], tools: [], setCredential: false, mcpTools: [], secretStdin: false,
  };
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
      case '--allow-tool': args.tools.push(next().trim()); break;
      case '--set-credential': args.setCredential = true; break;
      case '--upstream-url': args.upstreamUrl = next(); break;
      case '--mcp-tool': args.mcpTools.push(next().trim()); break;
      case '--mcp-upstream-base': args.mcpUpstreamBase = next(); break;
      // Takes NO value: the secret arrives on fd 0, never in argv.
      case '--secret-stdin': args.secretStdin = true; break;
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

/**
 * The mcp sibling of assertOriginOnly, and deliberately a SEPARATE function
 * rather than a relaxed shared one: relaxing the vendor rule to accommodate an
 * in-cluster destination would quietly permit an unencrypted, path-bearing
 * upstream for the LLM route too.
 *
 * Permits http (a cluster service DNS name has no TLS) and permits a path,
 * which the mediated route depends on. Still refuses a query or fragment: the
 * tool name is appended to the path, and anything after it would be orphaned.
 *
 * RETURNS THE FULL HREF, NOT THE BARE ORIGIN. Reducing this to a scheme+host
 * would silently discard `/internal/mcp/tools`, and every mediated call would
 * land on `/` carrying an injected credential. The trailing slash is trimmed so
 * appending `'/' + tool` cannot produce a doubled separator.
 */
function assertMcpBase(raw: string): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`--mcp-upstream-base is not a valid URL: ${raw}. Nothing was written.`);
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error(
      `--mcp-upstream-base must use http or https (got ${url.protocol.replace(':', '')}): ${raw}. ` +
      `Nothing was written.`,
    );
  }
  if (url.search !== '' || url.hash !== '') {
    throw new Error(
      `--mcp-upstream-base must carry no query or fragment (got ${raw}); each row's destination ` +
      `is formed by appending the tool name to its path. Nothing was written.`,
    );
  }
  return url.href.replace(/\/+$/, '');
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

  // DECISION: there is no assertPriced twin for tools, and that is a choice, not
  // an omission. The obvious guard would be membership in the caller's tool
  // catalog — but Aegis has no Acme catalog, and hardcoding one here would make
  // this file a second source of truth that drifts silently from the real one.
  // The membership assertion therefore belongs to the Acme seed script, which
  // imports the catalog directly (allCandidateToolsFlat()).
  //
  // Naming the consequence so the gap is visible to whoever reads this next:
  // policy/bundle/gateway.rego authorizes with `input.request.tool in
  // input.agent.allowedTools` — plain set membership, no normalization, no
  // fuzzy match. A typo'd tool name written here is therefore a PERMANENT
  // SILENT DENY that is indistinguishable from a policy decision at request
  // time. Nothing downstream will ever correct it.
  const tools = opts.allowTools === undefined ? undefined : dedupe(opts.allowTools);

  const wantsMcp = opts.mcpTools !== undefined && opts.mcpTools.length > 0;
  const hasMcpBase =
    opts.mcpUpstreamBase !== undefined && opts.mcpUpstreamBase.trim().length > 0;

  let upstreamOrigin: string | undefined;
  let secret: string | undefined;
  if (opts.setCredential === true || wantsMcp) {
    secret = opts.secret;
    if (secret === undefined || secret.trim().length === 0) {
      throw new Error(
        'AEGIS_UPSTREAM_SECRET is unset or blank — it holds the upstream key and is never ' +
        'accepted as a command-line flag. Export it for this one command only, e.g. ' +
        'AEGIS_UPSTREAM_SECRET="$(cat /path/to/key)" npm run update-agent -- …, or pipe it ' +
        'in with --secret-stdin.',
      );
    }
  }
  if (opts.setCredential === true) {
    upstreamOrigin = assertOriginOnly(opts.upstreamUrl ?? DEFAULT_UPSTREAM_ORIGIN);
  }

  // The two mcp flags are meaningless apart: a tool with nowhere to send it, or
  // a destination nothing is registered against. Refuse rather than guess.
  if (wantsMcp && !hasMcpBase) {
    throw new Error(
      '--mcp-upstream-base is required whenever --mcp-tool is supplied: an mcp:<tool> row ' +
      'with no destination makes the MCP plane fail closed at request time. Nothing was written.',
    );
  }
  if (hasMcpBase && !wantsMcp) {
    throw new Error(
      '--mcp-upstream-base was supplied with no --mcp-tool, so there is no target to register ' +
      'it against. Nothing was written.',
    );
  }

  // Each (target, upstreamUrl) pair this invocation will write, resolved in full
  // BEFORE the first write so a bad name cannot leave half the set registered.
  const mcpPairs: Array<{ target: string; upstreamUrl: string }> = [];
  if (wantsMcp) {
    const trimmed = (opts.mcpTools as string[]).map((t) => t.trim());
    if (trimmed.some((t) => t.length === 0)) {
      // Unlike --allow-tool, an empty entry is NOT silently dropped here: it
      // would name the target `mcp:` and point it at a URL ending in `/`, which
      // is a registered credential at a destination nothing can reach.
      throw new Error(
        '--mcp-tool value is empty after trimming; every mcp target needs a tool name. ' +
        'Nothing was written.',
      );
    }
    // The tool name is appended to the base path VERBATIM two lines below, so
    // it is as load-bearing for the destination as the base itself — and
    // assertMcpBase validates only the base. Concrete bad end-state without
    // this guard: `--mcp-tool '../../../api/blueprints'` registers a live
    // credential whose stored URL WHATWG normalization (which fetch applies)
    // collapses to a whole-tenant Acme route the exec path does not serve,
    // carrying the gateway-injected PAT — every other Acme tenant route accepts
    // that bearer, because scope is enforced only at the exec endpoint. A
    // query, fragment, path separator, percent-escape or space does the same
    // thing more quietly. `encodeURIComponent` is not a fix here:
    // `encodeURIComponent('..') === '..'`.
    //
    // REFUSE, never sanitize (ASVS V5): a rewritten name would silently
    // register a target the caller never asked for, and `policy/bundle/
    // gateway.rego` matches allowedTools by plain set membership — so a
    // silently-altered name is a permanent, invisible deny. This is a CHARSET
    // check, deliberately not a catalog-membership check: Aegis has no Acme
    // tool catalog, and inventing one here was correctly declined above.
    const TOOL_NAME = /^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*$/;
    for (const tool of trimmed) {
      if (!TOOL_NAME.test(tool)) {
        throw new Error(
          `--mcp-tool "${tool}" contains URL-reserved or dot-segment characters; ` +
          `the value is appended to the upstream path verbatim. Nothing was written.`,
        );
      }
    }
    const base = assertMcpBase(opts.mcpUpstreamBase as string);
    for (const tool of new Set(trimmed)) {
      mcpPairs.push({ target: `mcp:${tool}`, upstreamUrl: `${base}/${tool}` });
    }
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
  let allowedTools = agent.allowedTools;
  if (models !== undefined || tools !== undefined) {
    // ONE UPDATE scoped by id for both allowlists — one statement, one round
    // trip, and each supplied array REPLACES its column wholesale. A column
    // whose flag was not supplied is not in the SET clause at all, so an
    // invocation that touches only one allowlist leaves the other byte-identical
    // rather than rewriting it with a value read a moment earlier.
    const [updated] = await db.update(agents)
      .set({
        ...(models !== undefined ? { allowedModels: models } : {}),
        ...(tools !== undefined ? { allowedTools: tools } : {}),
      })
      .where(eq(agents.id, agent.id))
      .returning();
    allowedModels = updated.allowedModels;
    allowedTools = updated.allowedTools;
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

  // The same DELETE-then-INSERT-then-assert-count-1 sequence as the LLM target
  // above, run once per mcp pair. Copied in shape on purpose: it is the only
  // thing standing between the MCP plane and a coin-flip over which credential
  // (and therefore which destination) a mediated call resolves.
  const mcpCredentials: Array<{ target: string; upstreamUrl: string; rowCount: number }> = [];
  for (const pair of mcpPairs) {
    const where = and(
      eq(scopedCredentials.agentId, agent.id),
      eq(scopedCredentials.target, pair.target),
    );
    await db.delete(scopedCredentials).where(where);
    await putCredential(db, cfg, agent.id, pair.target, secret as string, pair.upstreamUrl);
    const [{ n: mcpN }] = await db
      .select({ n: dsql<number>`count(*)::int` })
      .from(scopedCredentials)
      .where(where);
    const rowCount = Number(mcpN);
    if (rowCount !== 1) {
      throw new Error(
        `credential replacement left ${rowCount} rows for (${agent.id}, ${pair.target}); ` +
        `exactly 1 is required or credential selection is non-deterministic`,
      );
    }
    mcpCredentials.push({ target: pair.target, upstreamUrl: pair.upstreamUrl, rowCount });
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
    allowedTools,
    credentialRowCount,
    upstreamUrl: row?.upstreamUrl ?? null,
    mcpCredentials,
    budget,
  };
}

/**
 * One synchronous read of fd 0, trimmed. Synchronous and single-shot on purpose:
 * the value must be consumed once and held in exactly one place for the life of
 * the process. Nothing here logs it, and the caller is expected to have PIPED it
 * so it never became a shell variable or a file on the way in.
 */
function readSecretFromStdin(): string {
  try {
    return readFileSync(0, 'utf8').trim();
  } catch (err) {
    throw new Error(`--secret-stdin could not read fd 0: ${(err as Error).message}`);
  }
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

  // Read the secret from fd 0 or the environment, and fail before the database
  // is even opened if it is not there. Nothing downstream ever prints this
  // value. The stdin read happens exactly ONCE and covers every row written.
  const secret = args.secretStdin ? readSecretFromStdin() : process.env.AEGIS_UPSTREAM_SECRET;
  const needsSecret = args.setCredential || args.mcpTools.length > 0;
  if (needsSecret && (secret === undefined || secret.trim().length === 0)) {
    console.error(
      'a credential write requires the upstream key, supplied either on fd 0 with ' +
      '--secret-stdin or in the AEGIS_UPSTREAM_SECRET environment variable. It is deliberately ' +
      'not accepted as a flag: flag values land in shell history and in `ps` output.',
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
      ...(args.tools.length > 0 ? { allowTools: args.tools } : {}),
      ...(args.setCredential ? { setCredential: true } : {}),
      ...(needsSecret ? { secret } : {}),
      ...(args.mcpTools.length > 0 ? { mcpTools: args.mcpTools } : {}),
      ...(args.mcpUpstreamBase !== undefined ? { mcpUpstreamBase: args.mcpUpstreamBase } : {}),
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
      allowedTools: result.allowedTools,
      credential: {
        target: LLM_TARGET,
        rowCount: result.credentialRowCount,
        upstreamUrl: result.upstreamUrl,
        replaced: args.setCredential,
      },
      // Names and counts only, same contract as the LLM entry above.
      mcpCredentials: result.mcpCredentials,
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
