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
