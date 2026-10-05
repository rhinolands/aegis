-- DEV / DEMO ONLY. Resets the audit chain to empty. Never run against a database
-- whose audit log matters.
--
-- This is deliberately the owner-level bypass: the append-only triggers raise on
-- TRUNCATE for every role, so the only way through is to disable them first, which
-- requires table-owner (or superuser) rights. The least-privilege service role
-- cannot run this. One transaction, so the disabled-trigger state is never visible
-- to another session.
--
--   psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -q -f scripts/reset-dev-chain.sql
BEGIN;
ALTER TABLE audit_records DISABLE TRIGGER USER;
ALTER TABLE chain_head DISABLE TRIGGER USER;
TRUNCATE audit_records, chain_head;
ALTER TABLE audit_records ENABLE TRIGGER USER;
ALTER TABLE chain_head ENABLE TRIGGER USER;
COMMIT;
