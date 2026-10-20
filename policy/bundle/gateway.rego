package gateway

import rego.v1

policy_version := "v1"

# NOTE: OPA disallows var references in a `default` rule's value, so this
# "v1" literal duplicates the `policy_version` constant above rather than
# referencing it directly. On any policy_version bump, BOTH must be updated
# in lockstep, or the deny path will silently misreport a stale version.
default decision := {"allow": false, "reason": "deny-by-default", "policy_version": "v1"}

decision := {"allow": true, "reason": "tool allowed", "policy_version": policy_version} if {
	input.plane == "mcp"
	input.request.tool in input.agent.allowedTools
	args_allowed
}

# An allowlisted tool whose arguments break an operator constraint. Mutually
# exclusive with the allow rule above (args_allowed vs not args_allowed), so the
# complete decision rule never has two values.
decision := {"allow": false, "reason": "argument not allowed", "policy_version": policy_version} if {
	input.plane == "mcp"
	input.request.tool in input.agent.allowedTools
	not args_allowed
}

# Argument constraints are operator data at data.aegis_constraints.tools:
#   {"<tool>": {"<arg>": {"allow": [regex...], "deny": [regex...]}}}
# A tool with no entry is unconstrained. For a tool with an entry, every listed
# argument must be a string that matches at least one allow regex and no deny
# regex. A missing or non-string argument fails closed. The patterns are anchored
# by whoever writes them; nothing here adds ^ or $.
args_allowed if not data.aegis_constraints.tools[input.request.tool]

args_allowed if {
	spec := data.aegis_constraints.tools[input.request.tool]
	every name, rule in spec {
		arg_ok(rule, object.get(object.get(input.request, "args", {}), name, null))
	}
}

arg_ok(rule, value) if {
	is_string(value)
	some pattern in rule.allow
	regex.match(pattern, value)
	not arg_denied(rule, value)
}

arg_denied(rule, value) if {
	some pattern in object.get(rule, "deny", [])
	regex.match(pattern, value)
}

decision := {"allow": true, "reason": "peer allowed", "policy_version": policy_version} if {
	input.plane == "a2a"
	input.request.peer in input.agent.allowedPeers
}

decision := {"allow": true, "reason": "model allowed", "policy_version": policy_version} if {
	input.plane == "llm"
	input.request.model in input.agent.allowedModels
}
