# Aegis — Agent Governance Gateway

**One enforcement point for agent ingress, agent-to-agent (A2A) delegation, MCP tool egress, and LLM upstream calls.** AuthN at the edge, OPA policy authorization (deny-by-default), least-privilege per-agent identity, fail-closed everywhere, and a tamper-evident audit spine that answers *who / what / when / where / why / verdict* for every decision — allows **and** denies.

Apache-2.0. Self-hostable: one TypeScript service + Postgres.

> **Status: v0.1 in progress — 15 of 20 planned tasks complete.** The foundation, the audit spine, the policy engine, the guards, the govern pipeline, and all three mediation planes (MCP, A2A, LLM) are built and tested. What remains is packaging: object-storage export, Helm chart, the end-to-end demo script, and CI. See [What's actually built](#whats-actually-built) — that section is deliberately precise, because a governance tool that overstates its own guarantees is worse than none.

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

**Hash chain.** `hash_n = sha256(hash_{n-1} ‖ canonical(record_n))`, where `canonical` is deterministic JSON with recursively sorted keys. `verifyChain()` replays the log in sequence order and recomputes every hash, detecting two distinct failure modes: a **hash mismatch** (a row was edited) and a **prevHash break** (a row was deleted or reordered).

**Two layers of immutability.** The service role is granted `INSERT` + `SELECT` only on the audit table (a load-bearing GRANT), *and* a `BEFORE UPDATE OR DELETE` trigger raises on any mutation attempt. Both are exercised by tests.

**Proven, not asserted.** The tamper test doesn't politely try an `UPDATE` and check for an error. It simulates an attacker who already holds owner-level database credentials: it **disables the trigger**, edits a record, re-enables it — and then shows `verifyChain()` still catches the edit. Defence-in-depth means the cryptographic layer has to hold when the database layer is bypassed.

**Crypto-shredding.** GDPR erasure versus immutability is a real conflict. Payloads are encrypted (AES-256-GCM) under a per-subject data key wrapped by a master key; erasure destroys the key row, rendering the payload unrecoverable while the chain skeleton — and therefore the integrity proof — stays intact.

**Boring export format, on purpose.** Daily JSONL segments plus a sha256 manifest and chain head. Auditors have `grep`; they should not need a bespoke reader.

## What's actually built

Verified by `npm test` (68 passing) and `opa test policy/bundle` (9 passing).

**Complete and tested**
- Config loading with fail-fast validation; Fastify server; health endpoint
- Postgres schema + append-only migrations (drizzle)
- Agent identity registry — bcrypt-hashed API keys, raw key returned exactly once, never persisted
- Edge AuthN — API key + JWT/JWKS, resolving an injected `Principal`; fail-closed on every path
- Audit record schema, deterministic canonicalization, args digesting (raw arguments are never stored)
- AES-256-GCM crypto-shred with per-subject wrapped keys
- Hash chain + transactional append-only writer (chain head advanced under `SELECT … FOR UPDATE`)
- Append-only enforcement: GRANT-level privileges **and** a mutation-blocking trigger
- `verifyChain()` full-chain verification, with tamper detection proven against a trigger bypass
- OPA/Rego policy bundle — deny-by-default, tool/peer/model allowlists, compiled to WASM (`opa build -t wasm`)
- In-process OPA evaluation with a fail-closed wrapper

- Scoped backend credential store — secrets encrypted at rest, scoped by `(agentId, target)`, with agent isolation explicitly tested
- Per-agent rate limiting (in-process sliding window) and fail-closed budget metering — an agent with no configured budget is denied, not granted unlimited spend
- **The govern pipeline** — the single ordered enforcement path (rate → policy → budget → execute → meter + audit) that all planes reuse. Denies short-circuit before any upstream call; allows and denies are both audited; `govern()` never throws, degrading to a deterministic status instead (see [fail-closed behaviour](#fail-closed-behaviour-of-the-pipeline))

- **MCP plane** — `POST /mcp/:tool`, per-agent tool allowlist, scoped credential injected by the gateway into the upstream call
- **A2A plane** — `POST /a2a/:peer`, peer allowlist, on-behalf-of delegation chain forwarded to the peer
- **LLM plane** — `POST /llm/:model`, model allowlist, governed passthrough with token metering into the budget

For all three planes the upstream destination is **operator-configured, never caller-supplied** — see [why that matters](#the-destination-is-not-the-callers-to-choose).

**Not yet built** (planned, tasks 16–20)
- Daily object-storage export; bootstrap wiring + register CLI; Helm chart; end-to-end demo script; CI

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
npm test                    # 24 tests
opa test policy/bundle -v   # 9 policy tests
```

Migrations run with `client_min_messages=warning` (set on the connection in `drizzle.config.ts`), so the benign `does not exist, skipping` notice from the append-only migration's `DROP TRIGGER IF EXISTS` doesn't read like a failure on a fresh database. Warnings and errors still surface. It is set on the connection rather than in the migration because migrations here are append-only and are never edited once applied.

The integration tests run against a real Postgres — no mocked database. They run serially by design: the hash chain is global singleton state, so parallel test files would interleave chain writes.

Because the tamper test deliberately breaks the chain, a *second* consecutive local run needs a reset:

```bash
docker exec aegis-pg psql -U aegis -d aegis -c "TRUNCATE audit_records, chain_head;"
```

## Notes on engineering approach

Built test-first, one reviewed commit per task. A few things the process surfaced that are worth stating plainly:

- The policy's `default` rule cannot reference the `policy_version` constant — OPA rejects variables in default rule values. The literal has to be duplicated, which creates a silent drift risk: a version bump would make *denied* requests misreport the policy version in the audit trail. There is now a regression test comparing the emitted version against the constant on both allow and deny paths, validated by injecting the drift and confirming the test fails.
- `registerAgent` currently performs two non-transactional inserts. Known gap, tracked for the key-rotation work.
- `TRUNCATE` is not caught by a row-level trigger. The append-only guarantee against truncation rests on the GRANT layer alone, which requires the least-privilege service role to actually exist — mandatory before any production deployment.

## Roadmap

v0.1 completes the four planes, guards, object-storage export, a k3s-first Helm chart, and a five-minute demo: register an agent → allowed tool call → unauthorized tool call returns 403 with a deny record → chain verification passes → tamper → chain verification fails.

Deliberately out of scope for v0.1: admin console, SSO/OIDC admin plane, content-safety guard models, policy-bundle signing, Envoy integration.

## License

Apache-2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE). Contributions require signing the CLA; see [CONTRIBUTING.md](CONTRIBUTING.md).
