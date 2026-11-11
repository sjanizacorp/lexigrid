"""Require explicit PostgreSQL identity; never inherit the operating-system user.
Author: Shahryar Jahangir, Aniza Inc.
This module deliberately uses only the standard library for native launchers.
"""
from urllib.parse import urlsplit,unquote,parse_qsl


def validate_database_identity(url,*,require_postgres=False):
    try:
        parsed=urlsplit(url)
        postgres=parsed.scheme.split('+',1)[0] in {'postgres','postgresql'}
        if not postgres:
            if require_postgres:raise ValueError
            return url
        username=unquote(parsed.username or '')
        overrides=[value for name,value in parse_qsl(parsed.query,keep_blank_values=True) if name.lower() in {'user','username'}]
        if not username.strip() or '\x00' in username or overrides:
            raise ValueError
    except (TypeError,ValueError):
        raise RuntimeError('PostgreSQL connection must name a dedicated account explicitly in the URL, such as lexigrid_owner for maintenance or lexigrid_runtime for the application. Implicit operating-system/database-service usernames and query-string user overrides are not accepted.') from None
    return url


if __name__=='__main__':
    import os,sys
    try:validate_database_identity(os.environ.get('DATABASE_URL',''),require_postgres=True)
    except RuntimeError as error:sys.exit(str(error))
