-- Runtime grants for LexiGrid PostgreSQL backups.
-- Executed inside the archive restore transaction.
DO $$
DECLARE
    database_name text := current_database();
BEGIN
    IF (SELECT count(*) FROM public.alembic_version) <> 1 OR NOT EXISTS (
        SELECT 1 FROM public.alembic_version
        WHERE version_num = 'lexigrid_schema'
    ) THEN
        RAISE EXCEPTION 'Backup schema does not match this LexiGrid release';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_roles
        WHERE rolname = 'lexigrid_runtime' AND rolcanlogin
          AND NOT (rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolreplication)
    ) THEN
        RAISE EXCEPTION 'Provision a restricted lexigrid_runtime login before restoring';
    END IF;

    IF current_user = 'lexigrid_runtime' OR EXISTS (
        SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relkind = 'r'
          AND pg_get_userbyid(c.relowner) = 'lexigrid_runtime'
    ) THEN
        RAISE EXCEPTION 'The LexiGrid runtime role must not own restored tables';
    END IF;

    IF EXISTS (
        SELECT 1 FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_attribute a ON a.attrelid = c.oid
        WHERE n.nspname = 'public' AND c.relkind = 'r'
          AND a.attname = 'tenant_id' AND NOT a.attisdropped
          AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity)
    ) THEN
        RAISE EXCEPTION 'Restored tenant tables must enforce forced row-level security';
    END IF;

    EXECUTE format('REVOKE ALL ON DATABASE %I FROM PUBLIC', database_name);
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO lexigrid_runtime', database_name);
END
$$;

DO $$
BEGIN
    GRANT SELECT, INSERT, UPDATE ON public.workflow_deliveries TO lexigrid_runtime;
    REVOKE DELETE ON public.workflow_deliveries FROM lexigrid_runtime;
    IF has_table_privilege('lexigrid_runtime', 'public.workflow_deliveries', 'DELETE') THEN
        RAISE EXCEPTION 'Runtime role must not delete workflow delivery history';
    END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO lexigrid_runtime;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.alembic_version FROM lexigrid_runtime;
GRANT SELECT ON public.alembic_version TO lexigrid_runtime;
REVOKE CREATE ON SCHEMA public FROM lexigrid_runtime;

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE
    public.approvals, public.business_services, public.control_findings,
    public.control_links, public.control_tests, public.controls, public.enterprise_records,
    public.enterprise_relations, public.evidence, public.evidence_blobs, public.frameworks,
    public.login_throttles, public.loss_events, public.mail_runtime_settings, public.policies,
    public.remediations, public.requirements, public.risk_assessments, public.risk_comments,
    public.risk_contacts, public.risk_links, public.risk_treatments, public.risks,
    public.saml_replays, public.service_dependencies, public.tenants, public.users,
    public.vendor_assessments, public.vendors,
    public.workflow_notifications, public.workflow_runs
TO lexigrid_runtime;

GRANT SELECT, INSERT ON public.audit, public.workflow_decisions TO lexigrid_runtime;
REVOKE UPDATE, DELETE ON public.audit, public.workflow_decisions FROM lexigrid_runtime;

GRANT SELECT, INSERT, UPDATE ON TABLE
    public.risk_mail, public.risk_mail_settings, public.risk_reminders
TO lexigrid_runtime;
REVOKE DELETE ON TABLE
    public.risk_mail, public.risk_mail_settings, public.risk_reminders
FROM lexigrid_runtime;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO lexigrid_runtime;

DO $$
BEGIN
    IF has_schema_privilege('lexigrid_runtime', 'public', 'CREATE')
       OR has_table_privilege('lexigrid_runtime', 'public.risk_mail', 'DELETE')
       OR has_table_privilege('lexigrid_runtime', 'public.risk_mail_settings', 'DELETE')
       OR has_table_privilege('lexigrid_runtime', 'public.risk_reminders', 'DELETE')
       OR has_table_privilege('lexigrid_runtime', 'public.audit', 'UPDATE')
       OR has_table_privilege('lexigrid_runtime', 'public.audit', 'DELETE')
       OR has_table_privilege('lexigrid_runtime', 'public.workflow_decisions', 'UPDATE')
       OR has_table_privilege('lexigrid_runtime', 'public.workflow_decisions', 'DELETE') THEN
        RAISE EXCEPTION 'Restored runtime role has unexpected inherited privileges';
    END IF;
END
$$;
