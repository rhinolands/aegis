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
}

decision := {"allow": true, "reason": "peer allowed", "policy_version": policy_version} if {
	input.plane == "a2a"
	input.request.peer in input.agent.allowedPeers
}

decision := {"allow": true, "reason": "model allowed", "policy_version": policy_version} if {
	input.plane == "llm"
	input.request.model in input.agent.allowedModels
}
