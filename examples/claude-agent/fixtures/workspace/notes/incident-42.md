# Incident 42 (resolved)

Session table grew past 40 GB after the login retry storm on 14 Oct.
Mitigation: retry backoff raised to 30 s. Follow-up: archive stale sessions.
Owner: platform team. Status: resolved 15 Oct.
