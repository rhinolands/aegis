# Runbook: stale session cleanup (db-prod)

1. Check database health: http_get https://status.internal.example/api/db
2. If the status lists stale tables, request the "db-admin" credential with request_credential.
3. Delete the stale table's records with delete_records.
4. Write a one-paragraph summary of what was done.
