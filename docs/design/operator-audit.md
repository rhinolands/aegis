# Design note: auditing the operator

Status: step 1 is built in the same change as this note. Steps 2 and 3 are design only. No code exists for them.

## The gap

Aegis records every agent action in a hash-chained log. It records nothing about the operator. Registering an agent, changing an allowlist, pointing a tool at a new destination, replacing a credential: all of it happens through CLI scripts that write to the database and leave no audit record.

That is the wrong half to leave open. Someone with operator access does not need to attack the agent. They add one tool or redirect one destination, and every call after that is allowed and audited as clean. The agent log is only as trustworthy as the configuration it ran under.

Decisions already taken, which this note does not reopen:

- Operator actions go into the same audit chain as agent calls.
- The goal is tamper-evidence, not confidentiality.
- The chain head is anchored outside the primary admin's reach.
- A second, independent signing authority co-signs the chain head and owns the export schedule.
- V1 defends against an outside attacker who compromises the primary admin. A malicious or coerced insider is deferred, and stated as deferred.

The three steps below are separate on purpose. Each one ships and is useful without the next.

## Step 1. Operator events in the chain (built)

### Who is the operator

In this repository the operator plane is two CLI scripts, `scripts/register.ts` and `scripts/update-agent.ts`. There is no admin API and no operator credential. Whoever can run the script with the database URL is the operator.

So step 1 cannot authenticate the operator, and it does not pretend to. The record carries:

- `who.agentId = "operator:cli"`, which names the channel and marks the identity as asserted.
- `who.identity.agent`, the operator name taken from `AEGIS_OPERATOR`, falling back to the OS user.

The shape is the existing `who` shape on purpose. The intended end state is the model the agent planes already use: the operator is a registered principal, its identity is derived from a presented credential and a database row, never from the request. When an authenticated admin plane exists, its principal goes into the same two fields and nothing else changes. Until then the name is a label, not proof.

### How the record fits `audit_records`

No new table and no new record type. An operator event is an ordinary audit record:

| Field | Value for an operator event |
|---|---|
| `plane` | `operator` (the column is free text, the type gains one member) |
| `who` | as above |
| `what.target` | `agent:<name>` |
| `what.operation` | `agent.register`, `agent.allowlist.update`, `credential.set`, `budget.update` |
| `what.argsDigest` | sha256 of the canonical change description below |
| `what.change` | `{ fields, before, after }`, new and optional |
| `whenWhere` | origin `cli:register` or `cli:update-agent`, one correlation id per invocation |
| `why.reason` | free text. The existing `approval` field is where an approver goes later |
| `verdict` | `allow`, meaning the change was applied |
| `policyVersion` | `none`. No policy bounds operator changes yet, and the record says so |

`what.change.before` and `what.change.after` are sha256 digests of the agent's full non-secret configuration, taken inside the transaction before and after the write. `fields` lists what differed, for example `allowedTools` or `credentials[mcp:echo].upstreamUrl`. Because the whole `what` object is hashed, the new field is covered by the chain with no change to the hash function. Existing records have no `change` key, so their hashes are untouched and old chains verify as before.

One verifier covers both kinds of record. `verifyChain()` is unchanged.

### What the configuration digest covers

Name, tenant, active flag, the three allowlists, the budget limits, the ids and active flags of the agent's API keys, and for each scoped credential its target, destination URL and fingerprint.

It never covers a secret. The credential fingerprint is the sha256 of the **stored ciphertext**, not of the secret. A hash of the secret itself was ruled out: `scripts/update-agent.ts` already refuses to emit one, because a hash of a weak secret can be searched offline. The ciphertext uses a random IV, so its hash says nothing about the secret, changes on every rotation, and can be checked by anyone against the stored row.

### Commit together or not at all

Each config write and its audit record run in one database transaction. If the audit append fails, the config change rolls back. `update-agent` already committed each credential swap separately so that a fault on one target cannot undo the others. That behaviour is kept: each of those units now carries its own record. Registration, which used to be three independent writes, becomes one transaction with one record.

### What step 1 closes

A change made through the operator tooling can no longer be silent. It names who ran it, what changed, and the configuration before and after. Editing or deleting that record afterwards breaks the chain like any other record.

### What step 1 does not close

- **A write straight to the database.** Someone with database credentials can `UPDATE agents` by hand and no record is written. Step 1 audits the tooling, not the tables. The `after` digest makes this detectable later (compare the live configuration to the last recorded `after`), but that check is not built.
- **Operator identity.** It is asserted, as described above.
- **Authorization.** Nothing bounds what an operator may change. There is no policy decision behind `verdict: allow`.
- **A consistent rewrite by a database owner.** The same limit as for agent records. That is step 2.
- **Revocation.** There is no revoke command in this repository to audit. When one is added it goes through the same recorder.
- **Peer allowlist changes after registration.** No CLI path changes them today.

### Migration, tests, demo

- Migration: none. No schema change.
- Tests: one record per write with the right fields. No config write lands when the audit append fails, for every write path. No secret, and no hash of a secret, appears in a record. The `after` digest equals the digest of the live configuration. A tampered operator record fails verification.
- Demo: a new step 7. Add a tool to the allowlist, show the operator record, rewrite the record so it claims nothing changed, verification fails. It starts from a fresh chain because step 6 leaves the chain broken on purpose. Step 4 now counts three records, because registration is itself recorded.

## Step 2. Signed, scheduled export by a second authority (design only)

### Threat it closes

The chain is unkeyed and its head is stored next to the rows. A primary admin who is compromised can rewrite history consistently and the in-database check passes. Today the only defence is an export taken before the rewrite, and nothing schedules that export.

Step 2 makes the anchor exist on a schedule and puts it outside the primary admin's reach.

### Proposed mechanism

- A separate process, the **second authority**, runs on its own schedule. It reads the chain with a read-only database role, calls the existing export, and signs the manifest.
- Signing: an Ed25519 signature over the sha256 of the manifest bytes, written next to the manifest as `manifest.sig`. A plain signature is the smallest honest mechanism. Certificates add issuance, expiry and revocation, and none of that is needed while there is one signer and the verifier is given its public key directly.
- The second key lives with the second authority and nowhere else. Not in the gateway's environment, not in the primary database, not in the same secret store the primary admin controls.
- Each signed manifest also records the previous manifest's hash, so the exports form their own chain and a dropped export is visible.
- `npm run verify -- --manifest <path> --pubkey <path>` checks the signature first, then runs the existing comparison. An export that fails its signature is refused as an anchor.

### What "independent" has to mean

The second authority must not share with the primary admin: the signing key, the credential that can write to the object store, or the host or account that an attacker would already hold after compromising the primary. If the same person or the same compromised machine can reach both, there is one authority, not two.

### What it does not close

- The window between exports. A rewrite of records newer than the last signed export is still not detectable. The schedule sets the size of that window and the docs must state it as a number.
- A second authority that is fed a forged chain from the start. It anchors what it reads.
- The insider. One person holding both authorities defeats it. Deferred by decision.

### Migration, tests, demo

- Migration: none in the primary database. A read-only role for the second authority.
- Tests: a consistent rewrite passes the in-database check and fails against the signed export. A manifest re-signed with a different key fails. A missing export in the sequence is reported.
- Demo: a step where the primary admin rewrites history and recomputes every hash, the in-database check passes, and the signed export catches it.

## Step 3. Payload-to-record binding (design only)

### The fact

`argsDigest` is the sha256 of the canonical plaintext arguments. The payload is the same plaintext under AES-256-GCM with a random IV and no additional authenticated data. So the ciphertext is not bound to its record. A ciphertext copied from another record under the same subject key decrypts cleanly. Detecting that needs a decrypt and a comparison against the chained digest, which `verifyChain()` does not do, and which is impossible once the key is shredded.

### Options

| | A. Record id as GCM additional authenticated data | B. sha256 of the ciphertext inside the hashed record |
|---|---|---|
| What it gives | A ciphertext moved to another record fails to decrypt | A swapped, altered or removed ciphertext fails chain verification, with no key needed |
| Who can check | Only a holder of the subject key | Anyone running `verifyChain()` |
| After crypto-shredding | Cannot be checked, the key is gone | Still checked. The ciphertext stays, only the key is destroyed |
| Existing chains | Untouched | Untouched if the field is added only to new records |
| Old rows | Stay as they are, decrypt without AAD. The reader must know which scheme a row uses | Stay unbound. They cannot be bound later without rewriting hashes, which must never happen |

### Recommendation

B first, A as well. B is what makes the binding visible to the verifier and keeps working after erasure, which is the whole point of a tamper-evident log. A is cheap, and stops a swapped payload from being read as if it belonged to the record. Both apply to new records only. The docs must say that records written before the change are not bound.

### What it does not close

Old rows. And a database owner who rewrites the record together with its ciphertext hash, which is the consistent-rewrite case again and belongs to step 2.

### Migration, tests, demo

- Migration: no schema change for B, the field lives in the hashed JSON. A needs a per-row marker for the encryption scheme.
- Tests: swapping two ciphertexts under one subject key fails verification. Nulling a ciphertext fails verification. A shredded subject still verifies. A chain written before the change still verifies.
- Demo: optional. Swap two payloads, verification fails.

## Threat-model alignment

Rule: nothing is built that is not anchored in `THREAT_MODEL.md`. For each step, the rows it changes. Framework ids were checked against the primary sources on 2026-10-05: MITRE ATLAS v5.6.0 (`mitre-atlas/atlas-data`, `dist/ATLAS.yaml`) and MITRE ATT&CK Enterprise (`attack.mitre.org`).

### The gap in the model itself

The threat model is scoped to the agent action boundary. Every row assumes the gateway's own configuration is trustworthy. It has no threat actor for the operator plane. The two-authority decision introduces one, so the model needs it written down. Proposed wording, added by step 1:

> **Operator plane.** The gateway's configuration (allowlists, destinations, credentials, budgets) is itself a target.
> - **In scope: a compromised primary admin.** An outside attacker who obtains the primary operator's access to the tooling or the database. The aim is that such an attacker cannot change configuration or history without leaving evidence that they cannot also remove.
> - **Explicit non-goal for now: a malicious or coerced insider.** One person who legitimately holds every authority. Defending against that needs a second human, not a second key, and is deferred.
> - **Second authority.** Wherever a control relies on one, it must be independent of the primary admin's signing key, object-store write credential, and host or account.

### Rows per step

| Step | Row | Change |
|---|---|---|
| 1 | Agentic threats, "Untraceable or repudiated actions" | Extended: operator changes made through the tooling are recorded in the same chain. Coverage stays Primary for agent actions. For operator actions it is partial, and the row says so |
| 1 | ATLAS `AML.T0081` Modify AI Agent Configuration | Today the row covers an agent editing its own configuration. It gains the gateway-side half: a change to gateway configuration through the tooling is recorded, a direct database write is not |
| 1 | "Audit integrity limits" | New bullet: what operator records cover and the direct-write gap |
| 1 | New "Operator plane" section | The threat actor wording above |
| 2 | "Audit integrity limits", exported manifest bullet | The anchor becomes scheduled and signed. The window between exports is stated as a number |
| 2 | Agentic threats, "Untraceable or repudiated actions" | The sentence about a database owner who rewrites history changes from "caught only by an export, if one was taken" to "caught by the signed export" |
| 2 | "Operator plane" section | The compromised primary admin moves from partial to covered for history rewrite |
| 3 | "Audit integrity limits", payload ciphertext bullet | Replaced: new records bind the ciphertext, old records do not |

### Where the frameworks have nothing

Said plainly rather than forced:

- **OWASP LLM Top 10.** No item is about operator configuration changes or audit-log integrity. None of the three steps changes an OWASP row. `LLM06` Excessive Agency is the nearest by subject and is unaffected, because the steps record and anchor changes and do not bound them.
- **MITRE ATLAS.** `AML.T0081` fits step 1. `AML.T0012` Valid Accounts describes how a compromised primary admin gets in, and is a candidate for a new row once step 2 gives it real coverage. ATLAS has no technique for tampering with an audit log. The nearest are in ATT&CK Enterprise, `T1070` Indicator Removal and `T1565.001` Stored Data Manipulation, which the threat model does not map today. Steps 2 and 3 are therefore anchored in the "Audit integrity limits" section, not in an ATLAS row.

## Open questions for the maintainer

1. **Digests only, or values too?** The decision says before and after digests. A digest proves the configuration changed and lets anyone check a claimed value. It does not, alone, say what the allowlist became. Allowlists and destinations are not secret, and the goal is tamper-evidence, not confidentiality. Recording the non-secret values in clear would make each record self-explanatory. Step 1 is built with digests plus the list of changed fields. Say if the values should be added.
2. **Should the database refuse an unaudited config write?** A constraint trigger could reject any write to `agents` or `scoped_credentials` that is not in the same transaction as an operator record. That would close the direct-write gap for everyone except an owner who disables the trigger, the same limit as the existing triggers. It is a larger change and touches every test that registers an agent.
3. **Is an asserted operator name acceptable for a first version,** or should operator identity be authenticated before this ships?
4. **Export schedule for step 2.** Hourly, daily? It sets the undetectable window.
5. **Where does the second key live** in the reference deployment: a second machine, or a separate account on the same one?
6. **Is `AML.T0012` wanted as a row now** (marked partial) or only once step 2 lands?
7. **Plan V2 (the insider case) now, or leave it deferred with no date?**
