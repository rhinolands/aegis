# Aegis — Agent Governance Gateway

**One enforcement point for agent ingress, agent-to-agent (A2A) delegation, MCP tool egress, and LLM upstream calls.** AuthN at the edge, OPA policy authorization (deny-by-default), least-privilege per-agent identity, fail-closed everywhere, and a tamper-evident audit spine that answers *who / what / when / where / why / verdict* for every decision — allows **and** denies.

Apache-2.0. Self-hostable: one TypeScript service + Postgres.

**Threat model:** [THREAT_MODEL.md](THREAT_MODEL.md) maps these controls to the OWASP LLM Top 10, MITRE ATLAS and the agentic threat model, with explicit non-goals.

https://github.com/user-attachments/assets/62600322-78c9-4112-83fe-2cd4be6cddc4

*Real execution, from register to caught tamper. An allowed call. A denied call. A tampered audit record caught by the hash chain. Run it yourself with `bash scripts/demo.sh`.*

> **Status: v0.1 complete — 20 of 20 planned tasks.** The foundation, the audit spine, the policy engine, the guards, the govern pipeline, all three mediation planes (MCP, A2A, LLM), object-storage export, the Helm chart, the end-to-end demo script, and CI are all built and tested. See [What's actually built](#whats-actually-built) — that section is deliberately precise, because a governance tool that overstates its own guarantees is worse than none.

---

## Why this exists

The LLM-proxy problem is solved. Routing, key vaulting, budgets, retries — LiteLLM, Portkey, Kong, and Cloudflare all do it well, and Aegis does **not** try to compete there. LiteLLM composes perfectly well *behind* this gateway.

What remains underserved is **governance of what agents actually do**: which tools an agent may invoke, which peers it may delegate to, what credential is injected on its behalf, and whether any of it can be proven after the fact to an auditor. That is the problem Aegis addresses.

The design premise: an agent should never hold a broad credential, never call a peer directly, and never take an action that isn't independently reconstructable from an append-only log.

## Design principles

| Principle | How it's enforced |
|---|---|
| **Deny-by-default** | OPA/Rego policy compiled to WASM, evaluated in-process. The `default decision` is `allow: false`. An unknown plane, tool, peer, or model is denied without a rule needing to exist. |
| **Fail-closed** | Unknown caller, invalid credential, OPA error, missing budget, upstream failure → 403 **plus an audit record**. Every path through the policy evaluator returns a `Decision`; none can throw past the wrapper or coerce a non-boolean into an allow. |
| **Identity is injected, never asserted** | The gateway derives identity from the presented credential and the database — never from the request body. Each agent has its own app-only identity. No user impersonation, ever; user actions carry user identity, agent actions carry agent identity plus an on-behalf-of chain. |
| **Least-privilege credentials** | The agent authenticates with its own key. The gateway holds the scoped backend credential and injects it only after policy allows. A compromised agent key cannot exfiltrate the backend token. |
| **Denies are logged like allows** | The deny log is the point. A governance system that only records successes cannot answer the question an auditor actually asks. |
| **Tamper-evident, not just append-only** | Two database layers (privilege + trigger) stop mutation; a hash chain proves it. |

## Architecture

Every governed request flows through **one** pipeline — the planes differ only in how they build the policy input and how they execute upstream:

```
 caller ──JWT / API key──▶  1. AuthN at edge
                            2. Identity injection (+ on-behalf-of chain)
                            3. OPA eval  (WASM, in-process, deny-by-default)
                            4. Guard     (rate / quota / budget)
                            5. Execute   (proxy w/ scoped credential injection)
                            6. Audit append  (allow AND deny)
                                     │
                        Postgres (identities, audit chain)
                                     │ daily batch
                        Object storage (JSONL + sha256 manifest, WORM-optional)
```

Four governed planes, one pipeline: **ingress**, **A2A** (peer allowlist — A may invoke B.op; agents never call each other directly), **MCP egress** (per-agent tool allowlist, gateway injects the scoped credential), **LLM upstream** (model allowlist, token/cost metering).

## The audit spine

This is the part worth reading the code for.

**Hash chain.** `hash_n = sha256(hash_{n-1} ‖ canonical(record_n))`, where `canonical` is deterministic JSON with recursively sorted keys. `verifyChain()` reads the log and `chain_head` in one snapshot, replays the log in sequence order and recomputes every hash. It reports three distinct failure modes: a **hash mismatch** (a row was edited), a **prevHash break** (a row was deleted from the middle of the chain, or rows were reordered), and a **tail mismatch** against `chain_head` (the last rows were deleted, the table was emptied, or the head itself was removed or altered). What it cannot see is listed in the table below.

**Two layers of immutability.** The service role is granted `INSERT` + `SELECT` only on the audit table (a load-bearing GRANT), *and* triggers raise on any mutation attempt: a row-level `BEFORE UPDATE OR DELETE` trigger on the audit table, plus statement-level `BEFORE TRUNCATE` triggers on the audit table and on `chain_head`. Both layers are exercised by tests.

**Proven, not asserted.** The tamper test doesn't politely try an `UPDATE` and check for an error. It simulates an attacker who already holds owner-level database credentials: it **disables the trigger**, edits a record, re-enables it — and then shows `verifyChain()` still catches the edit. Defence-in-depth means the cryptographic layer has to hold when the database layer is bypassed. The same test file repeats the attack for a deleted last row, an emptied table, and a removed, stale or altered `chain_head`. Each one must fail verification, and each test was confirmed to go red when the check it covers is reverted.

### What each layer catches, and what it does not

The first two layers prevent. The last two detect. None of them is complete alone, and the limits are stated here on purpose.

| Layer | What it stops or catches | What it does not |
|---|---|---|
| **GRANT** (service role has `INSERT` + `SELECT` on `audit_records`) | A compromised gateway process cannot `UPDATE`, `DELETE` or `TRUNCATE` audit rows. | Does nothing against the table owner or a superuser. Only holds if the `aegis_service` role exists and the gateway connects as it. The service role must update `chain_head` to append, so it can corrupt the head, which verification then reports. |
| **Triggers** | `UPDATE`, `DELETE` and `TRUNCATE` on `audit_records`, and `TRUNCATE` on `chain_head`, raise for every role, the owner included. | An owner or superuser can disable the triggers first. `scripts/reset-dev-chain.sql` does exactly that for dev resets. Prevention ends at this row. |
| **`verifyChain()`** (in-database check) | An edited row. A row deleted mid-chain. Reordered rows. Deleted last rows. An emptied audit table whose head remains. A removed, stale or altered `chain_head`. | Any rewrite that stays self-consistent. The hash is unkeyed and `chain_head` lives in the same database as the rows, so a database owner can (1) delete the tail and rewrite `chain_head` to point at the new last row, (2) empty both tables, or (3) edit a row and recompute every later hash plus `chain_head`. All three verify clean. It also does not check payload ciphertext (see below). |
| **Exported manifest** (external anchor) | Each export writes the chain head (`seq` and `hash`) as it stood at export time to object storage. Any rewrite of a record at or before that head no longer matches it. This is the only layer that catches the three owner rewrites above. | Records written after the most recent export. With a daily export that window is up to a day, and a thorough owner-level rewrite inside it is not detectable. The anchor only exists if the export actually runs: `exportDay()` is a function, and no scheduler, CLI or CronJob in this repo calls it yet, so the operator has to. It is no anchor at all if the database owner can also rewrite the object store, so keep the store behind a separate credential and enable WORM or object lock. The comparison runs when the operator runs it, not on a schedule. |

**Checking the live chain against an export.** `npm run verify` runs the in-database check and prints the result as JSON (exit 0 verified, 1 failed, 2 unusable input). With `--manifest <path>` it also compares against a downloaded export: every exported record and the exported chain head must be present in the live chain with the same hash. It works offline from a local copy of `audit/<day>/` (the manifest with its segment next to it), and it refuses an export whose segment no longer matches the sha256 in its own manifest.

```bash
npm run verify -- --manifest ./audit/2026-10-05/manifest.json
```

The tests show each of the three owner rewrites passing the in-database check and then failing against an export taken before the rewrite.

**Operator changes are in the same chain.** Registering an agent, changing an allowlist, setting a credential or its destination, and changing a budget each write an operator record (`plane: operator`) in the same transaction as the change, so the change cannot land without its record. The record names the operator, the operation, each changed field with its value before and after, and sha256 digests of the agent's whole non-secret configuration before and after. A credential appears only as a fingerprint of its stored ciphertext, never as the secret or a hash of it. One `verifyChain()` covers agent and operator records alike. Limits, stated plainly: the operator name is asserted by the CLI (`AEGIS_OPERATOR` or the OS user), not authenticated. Nothing authorizes or bounds an operator change yet. A change written straight to the database, bypassing the CLI, leaves no record. Design and next steps: [docs/design/operator-audit.md](docs/design/operator-audit.md).

**What the hash covers.** The chain hashes the record skeleton: id, timestamp, tenant, plane, who, what (including `argsDigest`, the sha256 of the canonical arguments), when/where, why, verdict, policy version and subject key id. It does not hash `seq` (order is carried by the `prevHash` links) and it does not hash `payload_ciphertext`. The payload sits outside the hashed record by construction: it is the part crypto-shredding makes unreadable, while the skeleton is the part that has to keep verifying. The payload is still bound to the chain indirectly, because the plaintext that gets encrypted is the same canonical arguments that `argsDigest` commits to. Decrypt, hash, compare. A swapped ciphertext fails that comparison, and a corrupted one fails AES-GCM authentication. The limit: `verifyChain()` does not decrypt, so it does not run that comparison, and no shipped tool does yet. An owner who nulls or replaces a ciphertext is not flagged by chain verification, and once the subject key is shredded the comparison is impossible by design.

**Crypto-shredding.** GDPR erasure versus immutability is a real conflict. Payloads are encrypted (AES-256-GCM) under a per-subject data key wrapped by a master key; erasure destroys the key row, rendering the payload unrecoverable while the chain skeleton — and therefore the integrity proof — stays intact.

**Boring export format, on purpose.** Daily JSONL segments plus a sha256 manifest and chain head. Auditors have `grep`; they should not need a bespoke reader.

## What's actually built

Verified by `npm test` (180 passing across 25 test files as of v0.1+G, plus the
S3 export integration test, which reports a real vitest **skip** unless
`RUN_S3_INTEGRATION=1`) and `opa test policy/bundle` (9 passing). The suite grows
as features land — run `npm test` for the current count.

**Complete and tested**
- Config loading with fail-fast validation; Fastify server; health endpoint
- Postgres schema + append-only migrations (drizzle)
- Agent identity registry — bcrypt-hashed API keys, raw key returned exactly once, never persisted
- Edge AuthN — API key + JWT/JWKS, resolving an injected `Principal`; fail-closed on every path
- Audit record schema, deterministic canonicalization, args digesting (raw arguments are never stored)
- AES-256-GCM crypto-shred with per-subject wrapped keys
- Hash chain + transactional append-only writer (chain head advanced under `SELECT … FOR UPDATE`)
- Append-only enforcement: GRANT-level privileges **and** mutation-blocking triggers (row-level `UPDATE`/`DELETE`, statement-level `TRUNCATE`)
- `verifyChain()` full-chain verification including the tail check against `chain_head`, with edit, mid-chain delete, tail delete and truncation detection proven against a trigger bypass
- Operator changes recorded in the audit chain: registration, allowlists, credentials and destinations, budgets. Each config write and its record commit in one transaction, proven by tests that fail the audit append and check the configuration did not change
- Verification against an exported manifest (`npm run verify -- --manifest <path>`), offline from a local copy of the export, proven against consistent owner-level rewrites that the in-database check cannot see
- OPA/Rego policy bundle — deny-by-default, tool/peer/model allowlists, compiled to WASM (`opa build -t wasm`)
- In-process OPA evaluation with a fail-closed wrapper

- Scoped backend credential store — secrets encrypted at rest, scoped by `(agentId, target)`, with agent isolation explicitly tested
- Per-agent rate limiting (in-process sliding window) and fail-closed budget metering — an agent with no configured budget is denied, not granted unlimited spend
- **The govern pipeline** — the single ordered enforcement path (rate → policy → budget → execute → meter + audit) that all planes reuse. Denies short-circuit before any upstream call; allows and denies are both audited; `govern()` never throws, degrading to a deterministic status instead (see [fail-closed behaviour](#fail-closed-behaviour-of-the-pipeline))

- **MCP plane** — `POST /mcp/:tool`, per-agent tool allowlist, scoped credential injected by the gateway into the upstream call
- **A2A plane** — `POST /a2a/:peer`, peer allowlist, on-behalf-of delegation chain forwarded to the peer
- **LLM plane** — `POST /llm/:model`, model allowlist, governed passthrough with token metering into the budget

For all three planes the upstream destination is **operator-configured, never caller-supplied** — see [why that matters](#the-destination-is-not-the-callers-to-choose).

**Gateway additions (G1–G6, integration surface)** — these landed after the v0.1 core to make Aegis a drop-in enforcement point for a consuming product, and extend the same one-pipeline model without weakening deny-by-default or fail-closed:

- **G1 — anthropic-compat raw passthrough** (`POST /v1/messages`): forwards the caller's exact bytes to the operator-registered upstream **origin** with the request path appended (path-preserving), injecting the scoped `llm:anthropic` credential server-side. The destination is never caller-supplied — a caller-named `upstreamUrl` is structurally unreadable on this route — and any upstream 3xx is rejected rather than followed.
- **`mcp:<tool>` scoped credential targets**: the MCP plane resolves *both* the scoped backend credential **and** the destination from the single operator-registered `(agentId, mcp:<tool>)` row — never the request body — so a compromised agent cannot redirect its own injected credential to a server it controls.
- **G6 — correlation-id relay**: the gateway relays the caller's correlation id — server-authored from the same normalized id the audit record is built from, so the relayed header and the audited record can never disagree — to the operator-registered upstream on the MCP, A2A, and LLM planes, so a backend's own audit row joins back to the gateway decision. It is an opaque token: it selects no destination, carries no authority, and gates nothing.
- A published `gateway_code` deny vocabulary lets the consuming product switch on a stable machine-readable code and render its own refusal copy, while the wire refusal stays deliberately generic (it never reveals which control refused).

- **Object-storage export** — daily JSONL segments + sha256 manifest + chain-head pointer, written to any S3-compatible store (MinIO, S3, Azure Blob, GCS via interop endpoint). `exportDay()` is built and tested, but nothing in this repo schedules it yet. Running it daily is an operator task.
- **Agent registration CLI** (`scripts/register.ts`) — the only way to create an agent identity, its tool/peer/model allowlist, and its scoped backend credential; returns the raw API key exactly once
- **Helm chart** (`helm/aegis`) — k3s-first, single replica by design (see chart comments), pre-install migration Job, bring-your-own S3-compatible object store
- **`scripts/demo.sh`** — the five-minute end-to-end walkthrough (see [Demo](#demo) below)
- **CI** — GitHub Actions (build, typecheck, `opa test`, Postgres + S3 (SeaweedFS) integration tests, gitleaks, CLA bot) and a Forgejo `workflow_dispatch` e2e job

## The destination is not the caller's to choose

An early cut of the planes let the caller pass `upstreamUrl` in the request body. That is a credential-exfiltration hole: an authenticated agent with an allowlisted tool could point the gateway at a server it controlled and receive the injected backend secret. The agent never *holds* the credential — it just makes the gateway deliver it anywhere, which is the same thing.

Destinations are now resolved server-side from the operator-registered `(agent, target)` record. The caller names a tool, peer, or model; the gateway decides where that goes, and denies fail-closed when nothing is registered. Redirects are rejected (`redirect: 'manual'`, any 3xx is an upstream failure) so a compromised upstream cannot bounce the credential onward.

The same class of bug appeared once more on the LLM plane, where the caller-supplied `payload` was spread *after* the policy-gated `model`, letting a caller run a model they weren't allowlisted for — while cost was metered at the allowlisted model's rate and the audit record named the wrong model. Trusted values are now spread last. Both are locked by regression tests that were verified to fail when the fix is reverted.

## Fail-closed behaviour of the pipeline

`govern()` always returns a status — it never rejects. The interesting case is an audit-write failure, because the audit record *is* the product:

| Situation | Behaviour |
|---|---|
| Rate, policy, or budget check throws | audit attempt, then **403** — nothing has executed yet, so this is lossless |
| Deny-path audit write fails | still **403**; the full intended record is logged at error level |
| Allow-path audit write fails *after* the upstream call ran | **500**, not 200 — the side effect already happened and cannot be reported as clean success; the full record is logged so it is recoverable |

Because an audit record must be constructible before it can be written, `canonical()` is intrinsically total: BigInt values, circular references, throwing getters, hostile `Proxy` traps, and unbounded nesting all serialize deterministically rather than throwing. Inputs that already serialized are byte-identical to before, pinned by a regression test — a change that would invalidate existing audit chains fails loudly.

## Quickstart

Requires Node ≥ 22, Docker, and the [`opa`](https://www.openpolicyagent.org/docs/latest/#running-opa) binary.

```bash
npm install

# Postgres
docker run -d --name aegis-pg \
  -e POSTGRES_USER=aegis -e POSTGRES_PASSWORD=dev -e POSTGRES_DB=aegis \
  -p 5432:5432 postgres:16

export DATABASE_URL=postgres://aegis:dev@localhost:5432/aegis
export AUDIT_MASTER_KEY=$(head -c32 /dev/zero | base64)   # dev only

npx drizzle-kit migrate     # includes the append-only grants + trigger
npm run build               # compiles the Rego policy to WASM, then TypeScript
npm test                    # unit + integration suite
opa test policy/bundle -v   # 9 policy tests
```

The S3 export integration test only runs when `RUN_S3_INTEGRATION=1` is set
(otherwise it reports as a real vitest **skip**, never a false pass). Run it against
any local S3-compatible store. CI uses SeaweedFS, since MinIO images are no longer
anonymously pullable:

```bash
printf '{"identities":[{"name":"aegis","credentials":[{"accessKey":"aegis","secretKey":"aegis12345"}],"actions":["Admin","Read","Write","List","Tagging"]}]}' > /tmp/aegis-s3.json
docker run -d --name aegis-s3 -p 9000:9000 \
  -v /tmp/aegis-s3.json:/etc/seaweedfs/s3.json:ro \
  chrislusf/seaweedfs:4.48 \
  server -dir=/data -s3 -s3.port=9000 -s3.config=/etc/seaweedfs/s3.json

export RUN_S3_INTEGRATION=1
export EXPORT_S3_ENDPOINT=http://localhost:9000
export EXPORT_S3_BUCKET=aegis-audit
export EXPORT_S3_ACCESS_KEY=aegis
export EXPORT_S3_SECRET_KEY=aegis12345
npm test
```

Migrations run with `client_min_messages=warning` (set on the connection in `drizzle.config.ts`), so the benign `does not exist, skipping` notice from the append-only migration's `DROP TRIGGER IF EXISTS` doesn't read like a failure on a fresh database. Warnings and errors still surface. It is set on the connection rather than in the migration because migrations here are append-only and are never edited once applied.

The integration tests run against a real Postgres — no mocked database. They run serially by design: the hash chain is global singleton state, so parallel test files would interleave chain writes.

The verification tests tamper with the chain on purpose, so that test file resets the chain before each test and leaves it empty when it finishes. The demo also leaves a tampered chain behind. After a demo run or an interrupted test run, reset by hand:

```bash
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -q -f scripts/reset-dev-chain.sql
```

A plain `TRUNCATE` of either table is refused by the append-only triggers, even for the owner. The reset script is the explicit owner-level bypass (disable triggers, truncate, re-enable, in one transaction). Both the test suite and the demo wipe the audit chain, so never point either at a database whose audit log matters.

## Helm (k3s-first)

The chart at `helm/aegis` installs the gateway, a pre-install migration Job, and
config/secret templates. It is deliberately single-replica for v0.1 — the rate
limiter is in-process, not backed by shared state, so scaling replicas beyond 1
would silently multiply the effective per-caller rate limit (see the comment
at the top of `helm/aegis/values.yaml`).

```bash
helm install aegis ./helm/aegis \
  --set database.url=postgres://aegis:CHANGE_ME@your-postgres:5432/aegis \
  --set secrets.auditMasterKey=$(head -c32 /dev/zero | base64) \
  --set secrets.s3AccessKey=CHANGE_ME \
  --set secrets.s3SecretKey=CHANGE_ME
```

Nothing in `values.yaml` is a usable credential — secrets are placeholders,
supplied at install time via `--set`, `--set-file`, a gitignored local values
override, or a sealed-secrets/external-secrets pipeline. `objectStore.endpoint`
defaults to `http://minio:9000`, an in-namespace service name. The chart does not
deploy the store. MinIO images are no longer anonymously pullable, so for a new
k3s install run another S3-compatible store (CI uses SeaweedFS, see the local test
command above) under that service name, or point the endpoint at S3, Azure Blob,
or GCS by endpoint/region alone. No code change.

## Demo

`scripts/demo.sh` is the five-minute end-to-end proof of the whole product. It
starts (or reuses) the echo upstream and the gateway itself, then walks through:

1. Register an agent with exactly one allowlisted tool.
2. **Allowed** tool call → `200`, and the upstream shows the gateway injected a
   scoped backend credential the caller never held.
3. **Unauthorized** tool call (a tool not on the allowlist) → `403`, deny logged.
4. `verifyChain()` → **passes** against the chain built by steps 1 to 3: three
   records, because the registration in step 1 is itself an operator record.
5. Tamper with the latest record the way an attacker holding owner-level DB
   credentials would (disable the append-only trigger, edit, re-enable it) →
   `verifyChain()` → **fails**, proving the edit is caught.
6. Cover the tracks by deleting that last record outright. Every remaining hash
   link is intact again, so only the comparison against `chain_head` can see it →
   `verifyChain()` → **fails** with `tail truncated`.
7. On a fresh chain, the operator adds the denied tool to the allowlist. The change
   is shown as an operator record (who, what, configuration before and after).
   Rewrite that record so it claims nothing changed → `verifyChain()` → **fails**.
8. On a fresh chain, an injected instruction. A second agent that may only read
   tickets handles one that tells it to mail the data out. It was never given a
   mail tool → `403`, deny logged. Then the limit, on purpose: the operator
   grants the mail tool, the same two calls run again, and both are **allowed**.
   The gateway does not detect the injection. It decides per call on tool, peer
   and model, with no rule on call arguments or on sequences of calls, so the
   grant is the security decision and the chain records who made it. No model
   runs in this step: the script plays an agent that obeyed the injected text.

```bash
export DATABASE_URL=postgres://aegis:dev@localhost:5432/aegis   # dev only
npx drizzle-kit migrate
bash scripts/demo.sh
```

The script fails loudly (non-zero exit) the instant any step doesn't produce
its expected outcome — it never prints success regardless of what happened.

## Notes on engineering approach

Built test-first, one reviewed commit per task. A few things the process surfaced that are worth stating plainly:

- The policy's `default` rule cannot reference the `policy_version` constant — OPA rejects variables in default rule values. The literal has to be duplicated, which creates a silent drift risk: a version bump would make *denied* requests misreport the policy version in the audit trail. There is now a regression test comparing the emitted version against the constant on both allow and deny paths, validated by injecting the drift and confirming the test fails.
- `registerAgent` performs two inserts with no transaction of its own. The registration CLI now runs the whole registration (agent, key, budget, credential) and its operator record in one transaction. A direct library call outside that path still does not.
- `TRUNCATE` is not caught by a row-level trigger, and `verifyChain()` originally never compared the log against `chain_head`. Together that meant an owner could delete the last record, or empty the table, and verification still passed. Both are closed: statement-level `BEFORE TRUNCATE` triggers, and a tail check in `verifyChain()`, each with a regression test confirmed to fail when the fix is reverted. The least-privilege service role is still mandatory before any production deployment, because triggers can be disabled by the owner.
- An unkeyed hash chain stored next to its own head cannot, by itself, catch a database owner who rewrites history consistently. That is what the exported manifest and `npm run verify -- --manifest` are for. See the layer table under [The audit spine](#the-audit-spine) for the exact limits, including the window between exports.

## Roadmap

v0.1 completes the four planes, guards, object-storage export, a k3s-first Helm chart, and a five-minute demo: register an agent → allowed tool call → unauthorized tool call returns 403 with a deny record → chain verification passes → tamper → chain verification fails → delete the tampered record → chain verification still fails.

Deliberately out of scope for v0.1: admin console, SSO/OIDC admin plane (so operator identity in audit records is asserted, not authenticated), content-safety guard models, policy-bundle signing, Envoy integration.

## License

Apache-2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE). Contributions require signing the CLA; see [CONTRIBUTING.md](CONTRIBUTING.md).
