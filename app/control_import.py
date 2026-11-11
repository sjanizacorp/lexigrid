"""Insert-only control imports with tenant-bound, race-safe duplicate handling.
Author: Shahryar Jahangir, Aniza Inc.
"""
from sqlalchemy import select
from .governance_records import Control
from .main import uid

def existing_ids(session,tenant,codes):
    codes=list({code for code in codes if 0<len(code)<=60 and '\x00' not in code});found={}
    for offset in range(0,len(codes),500):
        found.update(session.execute(select(Control.code,Control.id).where(
            Control.tenant_id==tenant,Control.code.in_(codes[offset:offset+500]))).all())
    return found


def insert_once(session,tenant,data):
    dialect=session.get_bind().dialect.name
    if dialect=='postgresql':
        from sqlalchemy.dialects.postgresql import insert
    elif dialect=='sqlite':
        from sqlalchemy.dialects.sqlite import insert
    else:raise RuntimeError('Control import requires SQLite or PostgreSQL')
    identity=uid()
    statement=insert(Control).values(id=identity,tenant_id=tenant,**data).on_conflict_do_nothing(
        index_elements=['tenant_id','code'])
    # psycopg can report rowcount=-1 for this statement; use its returned ID.
    if dialect=='postgresql':return session.execute(statement.returning(Control.id)).scalar_one_or_none()
    return identity if session.execute(statement).rowcount==1 else None
