# Where aegis plugs in: Agent SDK vs Managed Agents

Phase 3 of the 20 Oct 2026 live-agent sprint. This is a documentation comparison, not a live
run: no Managed Agents session was created and nothing was spent on it. Every vendor claim
below is quoted from an Anthropic page fetched on 20 Oct 2026 and labelled with its URL
(the per-language field-name aliases the docs print in parentheses are left out of the quotes).
The aegis behaviour comes from this repo (policy is a per-tool allowlist in
`policy/bundle/gateway.rego`) and from the phase 1 and 2 runs in `../evidence/`.

## Summary

| Plug-in point | Agent SDK (what this repo runs) | Managed Agents | Can aegis govern it today? |
|---|---|---|---|
| Custom tools | In-process SDK MCP tools; the handler is ours and forwards to `POST /mcp/<tool>` | Custom tools are executed by the client app, which can forward to aegis the same way | **Yes, on both.** Same model as phase 1 and 2: aegis allows or denies, injects the scoped backend credential, audits both |
| Built-in tools (bash, file, web) | Removed with `tools: []`; a `PreToolUse` hook denies anything that is not an aegis tool | Run inside the Anthropic sandbox or on Anthropic servers; the client never executes them | **SDK: yes (removed or hook-gated). Managed Agents: no.** The only client hook is `always_ask` confirmation, which aegis could answer only with a decide-only endpoint it does not have yet |
| MCP servers | Any MCP server the app wires in; tool calls pass the `PreToolUse` hook | Anthropic connects to a remote MCP URL declared on the agent | **Not today.** aegis `/mcp/:tool` is a governed REST endpoint, not an MCP server, so Managed Agents cannot connect to it directly |
| Credentials | Agent holds only its aegis key; aegis injects the backend credential after policy allows | Vault credentials, substituted at egress; scoped by host | **Complementary.** The vault could hold the agent's aegis key; backend credentials stay in aegis |
| Network egress | Our host and our network controls | Environment `limited` networking with `allowed_hosts` | Outside aegis. Host-level, not per operation |
| Audit | aegis hash-chained record per governed call, joined by correlation id | Session event stream | aegis records only calls routed through it |

**Bottom line.** On the Agent SDK aegis can be the single enforcement point for every tool call,
because every tool runs in our process. On Managed Agents aegis governs custom tools fully,
but the built-in toolset and MCP toolset execute on Anthropic's side, where the only client
control is approving or denying a paused call. Making aegis govern those would need two
additions that do not exist today: a decide-only policy endpoint (for `always_ask`
confirmations) and an MCP-protocol front end (so a Managed Agents MCP toolset can point at
aegis).

## Evidence

### Agent SDK

- Custom tools run in our process. "The server runs in-process inside your application, not as a separate process."
  `[VERIFIED - https://code.claude.com/docs/en/agent-sdk/custom-tools]`
- Built-ins can be removed: `tools: []` means "All built-ins are removed. Claude can only use your MCP tools."
  `[VERIFIED - https://code.claude.com/docs/en/agent-sdk/custom-tools]`
- Hooks can block a call before it runs: for `PreToolUse`, "this is where you set `permissionDecision` (`"allow"`, `"deny"`, `"ask"`, or `"defer"`)".
  `[VERIFIED - https://code.claude.com/docs/en/agent-sdk/hooks]`
- Multiple hooks resolve most-restrictive first: "`deny` takes priority over `defer`, which takes priority over `ask`, which takes priority over `allow`."
  `[VERIFIED - https://code.claude.com/docs/en/agent-sdk/hooks]`
- Settings files load by default unless disabled: "Pass `[]` to disable user, project, and local settings."
  `[VERIFIED - https://code.claude.com/docs/en/agent-sdk/typescript]` (this repo passes `settingSources: []`)

### Managed Agents (beta, `managed-agents-2026-04-01`)

- Custom tools: "Claude does not run a custom tool itself. It emits a structured request, your code runs the operation, and you return the result to the session."
  `[VERIFIED - https://platform.claude.com/docs/en/managed-agents/tools]`
- Built-in toolset: Bash is described as "Execute bash commands in a shell session", Read as "Read a file from the sandbox filesystem". Individual tools can be disabled with `enabled: false`.
  `[VERIFIED - https://platform.claude.com/docs/en/managed-agents/tools]`
- Permission policies cover server-executed tools only: "Permission policies control whether server-executed tools (the pre-built agent toolset and MCP toolset) run automatically, wait for your approval, or have each call evaluated by the server. Custom tools are executed by your application and controlled by you, so they are not governed by permission policies."
  `[VERIFIED - https://platform.claude.com/docs/en/managed-agents/permission-policies]`
- The client-side hook for those tools is a confirmation: "Send a `user.tool_confirmation` event for each blocking event, passing the event ID in the `tool_use_id` parameter. Set `result` to `"allow"` or `"deny"`."
  `[VERIFIED - https://platform.claude.com/docs/en/managed-agents/permission-policies]`
- Under `auto`, server denials are final: "That includes calls the server denied under `auto`: your client cannot override them." And: "`auto` is not a human checkpoint."
  `[VERIFIED - https://platform.claude.com/docs/en/managed-agents/permission-policies]`
- MCP connector targets remote servers: the `mcp_servers` `type` "Must be `"url"`" and `url` is "The endpoint of the remote MCP server". The MCP toolset "defaults to a permission policy of `always_ask`".
  `[VERIFIED - https://platform.claude.com/docs/en/managed-agents/mcp-connector]`
- Vault environment-variable credentials: "When the agent initiates an outbound request, the opaque placeholder is substituted with the real secret at egress. The agent never sees the secret value."
  `[VERIFIED - https://platform.claude.com/docs/en/managed-agents/vaults]`
- Vault scoping is per host: "`allowed_hosts` in `networking` on a vault credential controls which requests use the secret, not which requests are allowed."
  `[VERIFIED - https://platform.claude.com/docs/en/managed-agents/vaults]`
- Environment networking is per host, not per operation: "Network access is granted per host, not per operation. The sandbox can send any request to an allowed host".
  `[VERIFIED - https://platform.claude.com/docs/en/managed-agents/environments]`
- Omitted networking is open: "a create request that omits it gets `unrestricted`."
  `[VERIFIED - https://platform.claude.com/docs/en/managed-agents/environments]`

## What would close the Managed Agents gap (not built)

1. **Decide-only endpoint.** A route that runs authN, policy and audit without executing an upstream call, so a Managed Agents client can turn each `always_ask` pause into an aegis decision and send it back as `user.tool_confirmation`. The audit record would then show the decision, but aegis would not see whether the tool ran or what it returned.
2. **MCP front end.** Serving the governed tools over MCP so a Managed Agents `mcp_toolset` can point at aegis, with the agent's aegis key in a vault `static_bearer` credential. Backend credentials would stay in aegis, as now.

Both are design notes for a follow-up, not claims about the current product.
