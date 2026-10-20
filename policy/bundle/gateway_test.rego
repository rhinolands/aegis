package gateway_test

import rego.v1
import data.gateway

agent := {"name": "a", "tenant": "t", "allowedTools": ["fs.read"], "allowedPeers": ["b"], "allowedModels": ["claude-sonnet-5"]}

test_mcp_allowed if {
	gateway.decision.allow with input as {"plane": "mcp", "agent": agent, "request": {"tool": "fs.read", "operation": "call"}}
}
test_mcp_denied_unknown_tool if {
	not gateway.decision.allow with input as {"plane": "mcp", "agent": agent, "request": {"tool": "fs.write", "operation": "call"}}
}
test_a2a_allowed if {
	gateway.decision.allow with input as {"plane": "a2a", "agent": agent, "request": {"peer": "b", "operation": "invoke"}}
}
test_a2a_denied_unknown_peer if {
	not gateway.decision.allow with input as {"plane": "a2a", "agent": agent, "request": {"peer": "c", "operation": "invoke"}}
}
test_llm_allowed if {
	gateway.decision.allow with input as {"plane": "llm", "agent": agent, "request": {"model": "claude-sonnet-5", "operation": "complete"}}
}
test_llm_denied_unknown_model if {
	not gateway.decision.allow with input as {"plane": "llm", "agent": agent, "request": {"model": "gpt-4", "operation": "complete"}}
}
test_deny_by_default_unknown_plane if {
	not gateway.decision.allow with input as {"plane": "carrier-pigeon", "agent": agent, "request": {}}
}

# Regression guard: policy_version must be reported consistently across BOTH the
# allow paths (which reference the policy_version var) and the default deny path
# (which hardcodes the literal, since OPA disallows var refs in default values).
# These compare against gateway.policy_version itself, not a hardcoded "v1", so
# bumping the constant without updating the default rule's literal fails here.
test_policy_version_reported_on_allow if {
	gateway.decision.policy_version == gateway.policy_version with input as {"plane": "mcp", "agent": agent, "request": {"tool": "fs.read", "operation": "call"}}
}
test_policy_version_reported_on_deny if {
	gateway.decision.policy_version == gateway.policy_version with input as {"plane": "carrier-pigeon", "agent": agent, "request": {}}
}

# --- MCP argument constraints -----------------------------------------------
# Operator-supplied rules live at data.aegis_constraints.tools, keyed by tool
# name, then by argument name, each with allow and (optional) deny regexes. A
# constrained argument must be a string, match at least one allow pattern and no
# deny pattern. A tool with no constraints keeps the plain allowlist behaviour
# (proven by test_mcp_allowed above, which runs with no constraints data).

constraints := {"fs.read": {"path": {
	"allow": ["^(docs|notes)/[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$"],
	"deny": ["(^|/)\\.", "(^|/)\\.\\.(/|$)"],
}}}

agent_empty := {"name": "a", "tenant": "t", "allowedTools": [], "allowedPeers": [], "allowedModels": []}

mcp_read(args) := {"plane": "mcp", "agent": agent, "request": {"tool": "fs.read", "operation": "call", "args": args}}

test_args_allowed_when_every_constrained_arg_matches if {
	d := gateway.decision with input as mcp_read({"path": "notes/a.md"}) with data.aegis_constraints.tools as constraints
	d.allow == true
	d.reason == "tool allowed"
}
test_args_denied_when_no_allow_pattern_matches if {
	d := gateway.decision with input as mcp_read({"path": "config/x.md"}) with data.aegis_constraints.tools as constraints
	d.allow == false
	d.reason == "argument not allowed"
}
test_args_denied_when_a_deny_pattern_matches if {
	# Inside an allowed prefix, but a hidden file.
	d := gateway.decision with input as mcp_read({"path": "notes/.env"}) with data.aegis_constraints.tools as constraints
	d.allow == false
	d.reason == "argument not allowed"
}
test_args_denied_on_path_traversal if {
	d := gateway.decision with input as mcp_read({"path": "notes/../config/.env.production"}) with data.aegis_constraints.tools as constraints
	d.allow == false
	d.reason == "argument not allowed"
}
test_args_denied_when_constrained_arg_missing if {
	d := gateway.decision with input as mcp_read({}) with data.aegis_constraints.tools as constraints
	d.allow == false
	d.reason == "argument not allowed"
}
test_args_denied_when_args_absent if {
	d := gateway.decision with input as {"plane": "mcp", "agent": agent, "request": {"tool": "fs.read", "operation": "call"}}
		with data.aegis_constraints.tools as constraints
	d.allow == false
	d.reason == "argument not allowed"
}
test_args_denied_when_constrained_arg_not_a_string if {
	d := gateway.decision with input as mcp_read({"path": ["notes/a.md"]}) with data.aegis_constraints.tools as constraints
	d.allow == false
	d.reason == "argument not allowed"
}
test_args_constraints_never_widen_the_allowlist if {
	# Arguments that satisfy the constraints do not let a non-allowlisted tool through.
	d := gateway.decision with input as {"plane": "mcp", "agent": agent_empty, "request": {"tool": "fs.read", "operation": "call", "args": {"path": "notes/a.md"}}}
		with data.aegis_constraints.tools as constraints
	d.allow == false
	d.reason == "deny-by-default"
}
test_args_unconstrained_tool_unaffected if {
	d := gateway.decision with input as {"plane": "mcp", "agent": agent, "request": {"tool": "fs.read", "operation": "call", "args": {"anything": 1}}}
		with data.aegis_constraints.tools as {"other.tool": {"x": {"allow": [".*"]}}}
	d.allow == true
	d.reason == "tool allowed"
}
test_policy_version_reported_on_argument_deny if {
	d := gateway.decision with input as mcp_read({"path": "config/x.md"}) with data.aegis_constraints.tools as constraints
	d.policy_version == gateway.policy_version
}
