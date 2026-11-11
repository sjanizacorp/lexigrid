"""Provision restricted PostgreSQL runtime login after migrations.
Author: Shahryar Jahangir, Aniza Inc.
"""
from .database_identity import validate_database_identity
import argparse
import getpass
import os
from pathlib import Path
import tempfile
from sqlalchemy import create_engine, text


def provision(engine, password):
    if not password or len(password) < 24:
        raise RuntimeError("RUNTIME_DB_PASSWORD must be at least 24 characters")
    if engine.dialect.name != "postgresql":
        raise RuntimeError("Runtime role provisioning requires PostgreSQL")
    with engine.begin() as connection:
        # Role DDL does not accept a bind parameter as its password token.
        # psycopg Literal safely quotes the secret without string interpolation.
        from psycopg import sql
        raw = connection.connection.driver_connection
        with raw.cursor() as cursor:
            cursor.execute(sql.SQL("ALTER ROLE lexigrid_runtime LOGIN PASSWORD {}").format(sql.Literal(password)))
        connection.execute(text("ALTER ROLE lexigrid_runtime NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE"))
        connection.execute(text("REVOKE CREATE ON SCHEMA public FROM lexigrid_runtime"))
        database=connection.scalar(text("SELECT current_database()"))
        with raw.cursor() as cursor:
            cursor.execute(sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(sql.Identifier(database)))
            cursor.execute(sql.SQL("GRANT CONNECT ON DATABASE {} TO lexigrid_runtime").format(sql.Identifier(database)))


def configure_native(path, password, owner_url=None):
    """Explicit one-time switch after migrations; retain every original application key."""
    from sqlalchemy.engine import make_url
    path=Path(path)
    if path.is_symlink() or not path.is_file():
        raise RuntimeError('Expected an existing regular native configuration file')
    original=path.read_bytes()
    lines=original.decode().splitlines()
    urls=[line.split('=',1)[1] for line in lines if line.startswith('DATABASE_URL=')]
    if len(urls)!=1:raise RuntimeError('Expected exactly one DATABASE_URL in native configuration')
    current=make_url(validate_database_identity(urls[0]));owner=make_url(validate_database_identity(owner_url or urls[0]))
    if current.get_backend_name()!='postgresql' or owner.get_backend_name()!='postgresql':
        raise RuntimeError('Native runtime provisioning requires PostgreSQL')
    if (current.host,current.port,current.database,current.query)!=(owner.host,owner.port,owner.database,owner.query):
        raise RuntimeError('Owner connection must target the same configured database')
    if current.username=='lexigrid_runtime':
        raise RuntimeError('Runtime configuration is already active; use the separate role rotation procedure')
    runtime=current.set(username='lexigrid_runtime',password=password).render_as_string(hide_password=False)
    replacement=('\n'.join('DATABASE_URL='+runtime if line.startswith('DATABASE_URL=') else line for line in lines)+'\n').encode()
    engine=create_engine(owner)
    try:provision(engine,password)
    finally:engine.dispose()
    fd,name=tempfile.mkstemp(prefix='.native-config-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as handle:
            handle.write(replacement);handle.flush();os.fsync(handle.fileno())
        if path.read_bytes()!=original:raise RuntimeError('Configuration changed concurrently; runtime role configured but native file was retained')
        os.replace(name,path)
    finally:Path(name).unlink(missing_ok=True)


def main():
    parser=argparse.ArgumentParser(description='Explicit PostgreSQL runtime password provisioning')
    parser.add_argument('--native-config',type=Path,help='Switch an initial owner native configuration to runtime credentials')
    args=parser.parse_args()
    password=os.getenv('RUNTIME_DB_PASSWORD') or getpass.getpass('New restricted runtime database password (24+ characters): ')
    if args.native_config:
        configure_native(args.native_config,password,os.getenv('LEXIGRID_ADMIN_DATABASE_URL'))
        print('Restricted runtime configured; original application keys retained. Owner credentials are not stored in native runtime configuration.')
    else:
        engine=create_engine(validate_database_identity(os.environ['DATABASE_URL']))
        try:provision(engine,password)
        finally:engine.dispose()
        print('Restricted runtime role configured.')


if __name__ == '__main__':
    main()
