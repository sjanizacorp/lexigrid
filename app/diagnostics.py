"""Read-only deployment diagnostics. Author: Shahryar Jahangir, Aniza Inc."""
from .database_identity import validate_database_identity
import argparse
import json
import os
from sqlalchemy import create_engine, inspect, text


def inspect_deployment(engine, expected_revision=None):
    """No schema changes or secrets returned. Checks are scoped to the configured database."""
    report={'database_dialect':engine.dialect.name,'checks':{},'ready':False}
    with engine.connect() as conn:
        conn.execute(text('SELECT 1'))
        report['checks']['database_connectivity']=True
        names=set(inspect(conn).get_table_names())
        required={'tenants','users','risks','audit','workflow_deliveries','alembic_version'}
        report['checks']['required_tables']=sorted(required-names)==[]
        report['missing_tables']=sorted(required-names)
        if 'alembic_version' in names:
            revisions=conn.execute(text('SELECT version_num FROM alembic_version')).scalars().all()
            report['migration_revisions']=sorted(revisions)
            if expected_revision:
                report['checks']['expected_revision']=expected_revision in revisions
        if engine.dialect.name=='postgresql':
            role=conn.execute(text("SELECT current_user")).scalar_one()
            flags=conn.execute(text("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname=current_user")).one()
            report['checks']['restricted_runtime_role']=role=='lexigrid_runtime' and not any(flags)
            report['checks']['database_security']=False
            if report['checks']['required_tables']:
                from .security_checks import assert_postgres_runtime_security
                try:
                    report['checks']['database_security']=assert_postgres_runtime_security(engine)
                except RuntimeError:pass
            if 'risks' in names:
                enabled=conn.execute(text("SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid='public.risks'::regclass")).one()
                report['checks']['risk_rls_force']=all(enabled)
            report['checks']['tenant_context_not_persistent']=not bool(conn.execute(text("SELECT current_setting('app.tenant_id',true)")).scalar())
        else:
            report['checks']['postgresql_production_backend']=False
    report['ready']=all(report['checks'].values())
    return report


def main():
    parser=argparse.ArgumentParser(description='LexiGrid read-only deployment diagnostics')
    parser.add_argument('--expected-revision',default='lexigrid_schema')
    args=parser.parse_args()
    url=os.environ.get('DATABASE_URL')
    if not url: parser.error('DATABASE_URL must be set')
    engine=create_engine(validate_database_identity(url),pool_pre_ping=True)
    try:
        result=inspect_deployment(engine,args.expected_revision)
        print(json.dumps(result,indent=2,sort_keys=True))
        raise SystemExit(0 if result['ready'] else 2)
    finally:
        engine.dispose()


if __name__=='__main__': main()
