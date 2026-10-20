# Argument constraints for the claude-agent example (operator policy data).
# Compiled together with policy/bundle into the example's own WASM by
# lib/live-env.sh; the product bundle ships with no constraints.
#
# read_file: workspace files under runbooks/ or notes/ only. No hidden files,
# no "..", no absolute paths (the allow pattern has no leading slash).
# http_get: https to three known hosts, path only. No query string, no
# userinfo, no port, so data cannot ride along to an allowed host either.
package aegis_constraints

import rego.v1

tools := {
	"read_file": {"path": {
		"allow": ["^(runbooks|notes)/[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$"],
		"deny": ["(^|/)\\.", "(^|/)\\.\\.(/|$)"],
	}},
	"http_get": {"url": {"allow": ["^https://(status\\.internal\\.example|docs\\.vendor\\.example|wiki\\.internal\\.example)(/[A-Za-z0-9._~/-]*)?$"]}},
}
