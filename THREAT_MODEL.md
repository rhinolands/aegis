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
- **Tamper-evident audit.** Allows and denies are both recorded. Two database layers (privilege plus a before-update-or-delete trigger) stop mutation, and a hash chain proves it: `hash_n = sha256(hash_{n-1} || canonical(record_n))`. Chain verification detects a row edited (hash mismatch) or a row deleted or reordered (prevHash break). Daily export to object storage as JSONL plus a sha256 manifest, WORM-optional.

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
| Untraceable or repudiated actions | Primary | Hash-chained tamper-evident audit of allows and denies, two database immutability layers, chain verification that catches edit, delete, and reorder, and WORM-optional export. Answers who, what, when, where, why, and verdict for every decision. |
| Context or memory poisoning | Containment | Aegis does not inspect context. Poisoned context that drives the agent toward an action still meets deny-by-default and the allowlists at the boundary. |
| Cascading multi-agent failure | Containment | The peer allowlist and per-agent scope stop a compromised or malfunctioning agent from expanding its reach across the fleet. |

## Non-goals (explicit boundaries)

Aegis is not, and does not try to be:

- An input scanner or prompt-injection detector.
- A model, data, or dependency supply-chain control.
- An output-correctness or hallucination filter.
- A retrieval or embedding security layer.

These are real problems owned by other layers. Aegis composes with them: it is the control that holds when detection upstream misses, because it never trusted the action to be safe in the first place.

## Design premise, restated

If a requirement says the system **must not** do something, that belongs in an enforced control, not in a prompt the model is trusted to honor. Aegis is where that control lives for agent actions: deny-by-default, least-privilege, fail-closed, and provable after the fact.

See the README for the architecture and the runnable demo (allow, deny, and a tampered audit record caught by the hash chain).
