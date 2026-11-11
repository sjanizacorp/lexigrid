"""Database-backed login throttle shared by all LexiGrid workers.
Author: Shahryar Jahangir, Aniza Inc.
"""
import hashlib
import time
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, BigInteger, select, update
from sqlalchemy.orm import Session
from fastapi import HTTPException

# Keep this model on the main application's metadata so development bootstrap works.
def install_model(Base):
    class LoginThrottle(Base):
        __tablename__ = 'login_throttles'
        key_hash = Column(String(64), primary_key=True)
        window_start = Column(BigInteger, nullable=False)
        attempts = Column(Integer, nullable=False)
    return LoginThrottle


def enforce_login_limit(session: Session, model, identity, *, max_attempts=8, window_seconds=300, clock=None):
    """Serialize concurrent attempts using a row lock on PostgreSQL.

    A unique constraint prevents duplicate counters; an upsert creates the row.
    Counters are charged before password verification and committed independently
    by the caller, including when authentication fails.
    """
    from sqlalchemy.dialects.postgresql import insert as pg_insert
    from sqlalchemy.dialects.sqlite import insert as sqlite_insert
    now = int(clock() if clock is not None else time.time())
    digest = hashlib.sha256(repr(identity).encode('utf-8')).hexdigest()
    dialect = session.bind.dialect.name
    if dialect == 'postgresql':
        stmt = pg_insert(model).values(key_hash=digest, window_start=now, attempts=0).on_conflict_do_nothing(index_elements=['key_hash'])
        session.execute(stmt)
    elif dialect == 'sqlite':
        stmt = sqlite_insert(model).values(key_hash=digest, window_start=now, attempts=0).on_conflict_do_nothing(index_elements=['key_hash'])
        session.execute(stmt)
    else:
        raise RuntimeError('Unsupported database for distributed authentication limiter')
    row = session.scalar(select(model).where(model.key_hash == digest).with_for_update())
    if now - row.window_start >= window_seconds:
        row.window_start, row.attempts = now, 0
    if row.attempts >= max_attempts:
        retry = window_seconds
        session.commit()
        raise HTTPException(429, 'Too many authentication attempts', headers={'Retry-After': str(retry)})
    row.attempts += 1
    session.commit()
