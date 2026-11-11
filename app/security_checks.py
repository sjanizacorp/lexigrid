"""Runtime PostgreSQL security assertions. Author: Shahryar Jahangir, Aniza Inc."""
from sqlalchemy import text


def assert_postgres_runtime_security(engine):
    """Fail startup if app uses a privileged role or tenant tables lack FORCE RLS."""
    if engine.dialect.name != 'postgresql':
        raise RuntimeError('Production security checks require PostgreSQL')
    with engine.connect() as conn:
        role = conn.execute(text('''SELECT current_user, rolsuper, rolbypassrls
            FROM pg_roles WHERE rolname=current_user''')).one()
        if role[1] or role[2] or role[0] != 'lexigrid_runtime':
            raise RuntimeError('Application must use unprivileged lexigrid_runtime role')
        bad = conn.execute(text('''SELECT c.relname FROM pg_class c
            JOIN pg_namespace n ON n.oid=c.relnamespace
            JOIN information_schema.columns col ON col.table_schema=n.nspname AND col.table_name=c.relname
            WHERE n.nspname='public' AND c.relkind='r' AND col.column_name='tenant_id'
              AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity)
            ORDER BY c.relname''')).scalars().all()
        if bad:
            raise RuntimeError('Tenant tables without FORCE RLS: ' + ', '.join(bad))
        # The role must not be able to override transaction tenant context through owner privileges.
        owner = conn.execute(text('''SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname='public' AND c.relkind='r' AND pg_get_userbyid(c.relowner)=current_user''')).scalar_one()
        if owner:
            raise RuntimeError('Runtime role must not own application tables')
        writable_history = conn.execute(text("""
            SELECT name FROM unnest(ARRAY['public.audit','public.workflow_decisions']) AS name
            WHERE has_table_privilege(current_user, name, 'UPDATE')
               OR has_table_privilege(current_user, name, 'DELETE')
        """)).scalars().all()
        if writable_history:
            raise RuntimeError('Runtime role must not modify existing history: ' + ', '.join(writable_history))
    return True
