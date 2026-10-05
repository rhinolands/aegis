-- Custom SQL migration file, put your code below! --

-- TRUNCATE fires no row-level trigger, so trg_audit_no_mutate (0001) never sees it.
-- Until now the only guard against truncating the audit log was the REVOKE on the
-- service role, which does nothing for any other role. These statement-level triggers
-- raise on TRUNCATE for every role, the table owner included, and also fire when the
-- table is reached through TRUNCATE ... CASCADE.
--
-- chain_head gets the same guard: verifyChain() compares the last audit row against
-- it, so emptying it would erase the evidence that a tail was removed.
--
-- Limit, stated plainly: a table owner or superuser can still DISABLE these triggers.
-- That is what scripts/reset-dev-chain.sql does for dev resets. The triggers stop
-- accidents and every non-owner role. An owner-level bypass is a detection problem,
-- handled by verifyChain() and the exported manifests, not a prevention one.
CREATE OR REPLACE FUNCTION aegis_block_audit_truncate() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION '% is append-only (TRUNCATE)', TG_TABLE_NAME;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_no_truncate ON audit_records;
CREATE TRIGGER trg_audit_no_truncate
  BEFORE TRUNCATE ON audit_records
  FOR EACH STATEMENT EXECUTE FUNCTION aegis_block_audit_truncate();

DROP TRIGGER IF EXISTS trg_chain_head_no_truncate ON chain_head;
CREATE TRIGGER trg_chain_head_no_truncate
  BEFORE TRUNCATE ON chain_head
  FOR EACH STATEMENT EXECUTE FUNCTION aegis_block_audit_truncate();

-- GRANT layer: the 0001 REVOKE of TRUNCATE on audit_records stays as is. Add the same
-- for chain_head, which the service role only ever needs to read, insert and update.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegis_service') THEN
    REVOKE TRUNCATE ON chain_head FROM aegis_service;
  END IF;
END $$;
