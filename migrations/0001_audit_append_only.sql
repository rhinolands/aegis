-- Custom SQL migration file, put your code below! --

-- Second layer of defense: block UPDATE/DELETE on the audit table regardless of role.
CREATE OR REPLACE FUNCTION aegis_block_audit_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_records is append-only (%, seq=%)', TG_OP, OLD.seq;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_no_mutate ON audit_records;
CREATE TRIGGER trg_audit_no_mutate
  BEFORE UPDATE OR DELETE ON audit_records
  FOR EACH ROW EXECUTE FUNCTION aegis_block_audit_mutation();

-- Load-bearing GRANT: the service role gets INSERT + SELECT only on the audit table.
-- Assumes a least-privilege role 'aegis_service' the app connects as in production.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegis_service') THEN
    REVOKE ALL ON audit_records FROM aegis_service;
    GRANT INSERT, SELECT ON audit_records TO aegis_service;
    REVOKE UPDATE, DELETE, TRUNCATE ON audit_records FROM aegis_service;
  END IF;
END $$;
