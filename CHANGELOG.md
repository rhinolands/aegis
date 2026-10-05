# Changelog

Notable changes per release, newest first. Written for someone deciding whether to upgrade.

## v0.1.1 (2026-10-05)

An audit-integrity release. Upgrade if you rely on chain verification.

### What v0.1.0 got wrong

Chain verification in v0.1.0 did not catch two things the documentation said it caught:

- **A deleted last record.** Verification replayed the hash links and never looked at the recorded chain head. Removing the newest record leaves every remaining link intact, so verification passed.
- **An emptied audit table.** An empty log verified as valid with zero records checked. `TRUNCATE` was only revoked from the service role and was not stopped by any trigger.

Both needed owner-level database access. Both are fixed in this release, and the README and THREAT_MODEL no longer claim more than the code does.

### Fixed

- `verifyChain()` now compares the last record against `chain_head`. A deleted tail, an emptied table whose head remains, and a missing, stale or altered head each fail with a distinct reason, for example `tail truncated: chain_head seq 12, last row 11`.
- `TRUNCATE` on `audit_records` and on `chain_head` is refused by statement-level triggers, for every role including the table owner (migration `0003_audit_no_truncate`).

### Added

- Verification against an exported manifest: `npm run verify -- --manifest <path>`. Every exported record and the exported chain head must be present in the live chain with the same hash. It works offline from a downloaded copy of an export and refuses an export whose segment no longer matches its own manifest. `npm run verify` without the flag runs the in-database check.
- Demo step 6: after the edited record is caught, the attacker deletes it outright, and verification still fails.
- `scripts/reset-dev-chain.sql`, the explicit owner-level reset for dev and demo databases.

### Documented limits

The README and THREAT_MODEL now list, per layer, what is stopped or detected and what is not. The ones to know:

- The hash is unkeyed and the chain head is stored in the same database as the records. A database owner who rewrites history consistently passes the in-database check. Only a manifest exported before the rewrite catches it.
- Records written after the most recent export are not covered by that anchor.
- Nothing in this repository schedules the export yet. Running it is an operator task.
- The encrypted payload is not hashed directly. It is bound to the chain through the digest of the arguments, and chain verification does not decrypt to check it.

### Also since v0.1.0

- `THREAT_MODEL.md`: the controls mapped to the OWASP LLM Top 10, an agentic threat list and MITRE ATLAS.
- Demo presenter options (`PAUSE`, `REVEAL_DELAY`) and the tamper SQL shown on screen.
- CI and the documented local setup use SeaweedFS for the S3 export test. The Helm chart no longer assumes a bundled object store.

### Upgrade notes

- Run `npx drizzle-kit migrate` to apply migration `0003`.
- A plain `TRUNCATE audit_records, chain_head` no longer works on dev databases. Use `psql "$DATABASE_URL" -f scripts/reset-dev-chain.sql`.
- A chain that was already truncated at the tail will now fail verification. That is the fix working, not a regression.

## v0.1.0 (2026-08-15)

First tagged version: the four mediation planes (agent ingress, A2A, MCP egress, LLM upstream), deny-by-default OPA policy, scoped credential injection, the hash-chained audit log with crypto-shredding, object-storage export, the Helm chart and the end-to-end demo.
