# Aegis Threat Model

Scope: the agent **action boundary**. Aegis is one enforcement point that every agent action passes through: agent ingress, agent-to-agent (A2A) delegation, MCP tool egress, and LLM upstream calls. This document states what Aegis defends, how, and where it deliberately stops. A governance tool that overstates its guarantees is worse than none, so the coverage column is blunt.

## Premise

An agent is non-deterministic and reads untrusted input (user messages, retrieved documents, tool results, peer messages). You cannot reliably detect every hostile instruction inside that input, because natural language has no fixed grammar. So Aegis does not try to. It constrains what the agent is **allowed to do**, per action, so that an agent which has been talked past its instructions still cannot exceed the authority its task needs.

- **Detection is not Aegis's job.** Input scanning, prompt inspection, and injection classifiers live upstream of the gateway.
- **Enforcement is Aegis's job.** Deny-by-default policy, least-privilege scoped credentials, and a tamper-evident record of every decision, at the point where the action happens.

Coverage keys: **Primary** = a core control directly addresses it. **Containment** = Aegis does not prevent the cause but bounds the blast radius. **Out of scope** = a different layer owns it (named, not hidden).

## Controls (what the enforcement point actually does)

- **Deny-by-default authorization.** OPA/Rego policy compiled to WASM, evaluated in-process. The default decision is `allow: false`. An unknown plane, tool, peer, or model is denied without a rule needing to exist.
- **Per-agent allowlists on every plane.** MCP egress: a per-agent tool allowlist. A2A: a peer allowlist (agent A may invoke agent B.op only if the rule exists, and agents never call each other directly). LLM upstream: a model allowlist with token and cost metering.
- **Least-privilege credential injection.** The agent authenticates with its own key. The gateway holds the scoped backend credential and injects it only after policy allows. A compromised agent key cannot exfiltrate the backend token.
- **Identity injected, never asserted.** Identity is derived from the presented credential and the database, never from the request body. Each agent has its own app-only identity. No user impersonation: user actions carry user identity, agent actions carry agent identity plus an on-behalf-of chain.
- **Guard: rate, quota, budget.** Per-agent limits evaluated before execution.
- **Fail-closed everywhere.** Unknown caller, invalid credential, OPA error, missing budget, or upstream failure returns a denial plus an audit record. No path can throw past the wrapper or coerce a non-boolean into an allow.
- **Tamper-evident audit.** Allows and denies are both recorded. Two database layers (privilege plus triggers that raise on update, delete, and truncate) stop mutation, and a hash chain detects it: `hash_n = sha256(hash_{n-1} || canonical(record_n))`. Chain verification detects a row edited (hash mismatch), a row deleted mid-chain or reordered (prevHash break), and deleted last rows or an emptied table (tail mismatch against the recorded chain head). Export to object storage as daily JSONL segments plus a sha256 manifest that records the chain head, WORM-optional. Limits are listed under [Audit integrity limits](#audit-integrity-limits).

## OWASP LLM Top 10 mapping

| # | Risk | Aegis coverage | How, or why not |
|---|------|----------------|-----------------|
| LLM01 | Prompt Injection | Containment | Aegis does not detect injection. It bounds it: a hijacked agent still hits deny-by-default plus its tool/peer/model allowlist plus a scoped credential, so the injected instruction cannot reach an action the agent was never granted. |
| LLM02 | Sensitive Information Disclosure | Primary at the access boundary | On-behalf-of identity means the agent queries with the requesting user's authority, not a broad shared account, so it cannot fetch records that user could not. Tool allowlist plus scoped credential bound which backends it reaches. Aegis does not redact content inside a response. |
| LLM03 | Supply Chain | Out of scope | Model and dependency provenance is a build/pipeline concern, not a runtime action. |
| LLM04 | Data and Model Poisoning | Out of scope | Training and ingestion pipelines are upstream. The tamper-evident audit helps post-incident forensics only. |
| LLM05 | Improper Output Handling | Containment | Aegis governs the tool call an output would trigger, not output rendering. Mediating tool egress limits what a malformed or hostile output can actually cause downstream. |
| LLM06 | Excessive Agency | Primary | This is the core case. Per-agent tool, peer, and model allowlists plus least-privilege scoped credentials plus deny-by-default give the agent exactly the authority its task needs and nothing more. |
| LLM07 | System Prompt Leakage | Out of scope | Prompt content is upstream of the action boundary. |
| LLM08 | Vector and Embedding Weaknesses | Mostly out of scope | Retrieval internals are upstream. Aegis can allowlist which retrieval tools an agent may call, nothing more. |
| LLM09 | Misinformation | Out of scope | Output correctness is a model and evaluation concern. |
| LLM10 | Unbounded Consumption | Primary | The guard (rate, quota, budget) plus LLM-plane token and cost metering plus the model allowlist bound consumption before execution. |

## Agentic threats

| Threat | Aegis coverage | How |
|--------|----------------|-----|
| Tool misuse | Primary | Per-agent tool allowlist plus scoped credential injection plus deny-by-default. A tool the agent does not need is not wired in, so it cannot be called. |
| Cross-agent privilege escalation | Primary | A2A peer allowlist (A may invoke only B.op if a rule exists) and agents never calling each other directly. Each agent has its own app-only identity plus an on-behalf-of chain, so one agent cannot borrow another's authority. |
| Identity and impersonation | Primary | Identity is injected from the credential and database, not asserted from the request body. No user impersonation. Every action carries the identity it ran under. |
| Compromised agent credential | Primary | The agent holds only its own key. The scoped backend credential lives in the gateway and is injected only after policy allows, so a stolen agent key cannot exfiltrate the backend token. |
| Untraceable or repudiated actions | Primary | Hash-chained tamper-evident audit of allows and denies, two database immutability layers, chain verification that catches an edited row, a deleted row (mid-chain or at the tail), reordered rows, and an emptied table, and WORM-optional export whose manifest anchors the chain head outside the database. Answers who, what, when, where, why, and verdict for every decision. A database owner who rewrites history consistently is caught only by the exported manifest, and only for records exported before the rewrite. See [Audit integrity limits](#audit-integrity-limits). |
| Context or memory poisoning | Containment | Aegis does not inspect context. Poisoned context that drives the agent toward an action still meets deny-by-default and the allowlists at the boundary. |
| Cascading multi-agent failure | Containment | The peer allowlist and per-agent scope stop a compromised or malfunctioning agent from expanding its reach across the fleet. |

## MITRE ATLAS mapping

Technique IDs and names are from MITRE ATLAS v5.6.0 (`mitre-atlas/atlas-data`, verified 2026-09-29). Only techniques that touch the action boundary are listed. The coverage keys are the same as above.

| ATLAS technique | Aegis coverage | How, or why not |
|-----------------|----------------|-----------------|
| AML.T0053 AI Agent Tool Invocation | Primary | Per-agent tool allowlist plus deny-by-default. A tool the agent was never granted cannot be invoked through the gateway. |
| AML.T0083 Credentials from AI Agent Configuration | Primary | The agent's configuration holds only its own key. Backend credentials live in the gateway's scoped store and are injected only after policy allows the call. |
| AML.T0055 Unsecured Credentials | Primary for backend credentials | Backend secrets are encrypted at rest, scoped by agent and target, and never placed in the agent's environment. Credentials outside the gateway are out of scope. |
| AML.T0081 Modify AI Agent Configuration | Primary for authority | Allowlists, destinations and credentials are operator-registered on the gateway, not read from the agent's configuration. An agent that edits its own configuration does not gain authority. |
| AML.T0034 Cost Harvesting | Primary | The guard (rate, quota, budget) runs before execution, and the LLM plane meters tokens and cost. An agent with no configured budget is denied. |
| AML.T0034.002 Agentic Resource Consumption | Primary | Same guard and metering apply to tool and model calls, so a coerced agent hits its budget instead of an open bill. |
| AML.T0086 Exfiltration via AI Agent Tool Invocation | Containment | Only allowlisted tools are reachable, and their destinations are resolved server-side, so the caller cannot redirect a call to a server it controls. Data encoded into the parameters of an allowed tool is not inspected. |
| AML.T0101 Data Destruction via AI Agent Tool Invocation | Containment | Mutative tools are reachable only if explicitly allowlisted for that agent, and every call is recorded in the tamper-evident audit. Misuse of a granted tool is bounded, not prevented. |
| AML.T0098 AI Agent Tool Credential Harvesting | Containment | Tool scope and on-behalf-of identity limit which data stores the agent can read. Credentials sitting inside data the agent may legitimately read are not detected. |
| AML.T0057 LLM Data Leakage | Primary at the access boundary | The agent retrieves with the requesting user's authority, so it cannot fetch what that user could not. Aegis does not redact model output. |
| AML.T0051 LLM Prompt Injection | Containment | Not detected. A hijacked agent still meets deny-by-default, its allowlists and a scoped credential. |
| AML.T0054 LLM Jailbreak | Containment | Not detected. A jailbroken model can only request actions the agent was already granted. |
| AML.T0080 AI Agent Context Poisoning | Containment | Context is not inspected. Actions driven by poisoned context still pass the same policy check. |
| AML.T0029 Denial of AI Service | Containment | Per-agent rate limits stop one agent from flooding upstream models. Aegis is not a network-level DoS defense. |
| AML.T0070 RAG Poisoning | Out of scope | Ingestion and retrieval integrity belong upstream. Actions a poisoned answer triggers are still bounded at the gateway. |
| AML.T0110 AI Agent Tool Poisoning | Out of scope | Tool integrity is a supply-chain control. The gateway limits which tools and destinations are reachable, not what a tool's code does. |
| AML.T0024 Exfiltration via AI Inference API | Out of scope | Model-level inference attacks on training data are a model and serving concern. |

## Audit integrity limits

The audit trail is tamper-evident, not tamper-proof. What each layer does and does not cover:

- **Privilege layer.** The service role can only insert and select audit rows. This stops a compromised gateway process. It does nothing against the table owner or a superuser, and it only holds if the least-privilege role is actually deployed.
- **Trigger layer.** Update, delete, and truncate on the audit table, and truncate on the chain head, raise for every role. An owner or superuser can disable the triggers. Prevention ends here.
- **Chain verification.** Run against the live database, it catches an edited row, a row deleted mid-chain, reordered rows, deleted last rows, an emptied audit table whose head remains, and a removed or altered chain head. It does not catch a rewrite that stays self-consistent. The hash is unkeyed and the chain head is stored in the same database, so an owner can delete the tail and rewrite the head to match, empty both tables, or edit a row and recompute every later hash and the head. All three pass verification.
- **Exported manifest.** Each export records the chain head in object storage. A rewrite of any record at or before that exported head no longer matches it. This is the only layer that catches the owner rewrites above. It does not cover records written after the most recent export, so with a daily export a thorough owner-level rewrite of the last day's records is not detectable. The export is a function the operator must schedule. Nothing in the repository runs it automatically yet, and without it this layer does not exist. It is no anchor if the database owner can also rewrite the object store. Use a separate credential and WORM or object lock. The comparison of the live chain against the manifest is a manual check today.
- **Payload ciphertext.** The chain hashes the record skeleton, including the digest of the arguments, and not the encrypted payload. A replaced payload is detectable by decrypting it and comparing its hash to the chained digest. Chain verification does not perform that step, and after a subject key is shredded it cannot be performed at all.

## Non-goals (explicit boundaries)

Aegis is not, and does not try to be:

- An input scanner or prompt-injection detector.
- A model, data, or dependency supply-chain control.
- An output-correctness or hallucination filter.
- A retrieval or embedding security layer.

These are real problems owned by other layers. Aegis composes with them: it is the control that holds when detection upstream misses, because it never trusted the action to be safe in the first place.

## Design premise, restated

If a requirement says the system **must not** do something, that belongs in an enforced control, not in a prompt the model is trusted to honor. Aegis is where that control lives for agent actions: deny-by-default, least-privilege, fail-closed, and provable after the fact.

See the README for the architecture and the runnable demo (allow, deny, a tampered audit record caught by the hash chain, and a deleted last record caught by the tail check).
