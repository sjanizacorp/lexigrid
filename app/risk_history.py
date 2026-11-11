"""Read-only risk revisions from committed audit records.

Author: Shahryar Jahangir, Aniza Inc.
This view does not rewrite history or infer missing historical field values.
"""
import hmac
import json

from fastapi import Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import main

ACTIONS = ('risk.create', 'risk.update', 'risk.resolve_close')
FIELDS = ('title', 'description', 'category', 'owner', 'likelihood', 'impact',
          'score', 'status', 'version', 'created_at', 'updated_at')


def snapshot(value):
    if not isinstance(value, dict):
        return None
    return {key: value[key] for key in FIELDS if key in value}


def revision(row, actor):
    integrity = 'unsigned'
    if row.integrity_mac:
        integrity = 'not_verified'
        if main.AUDIT_HMAC_KEY:
            expected = main.audit_digest(row.tenant_id, row.actor_id, row.action,
                                         row.object_id, row.details, row.at)
            integrity = 'verified' if hmac.compare_digest(row.integrity_mac, expected) else 'invalid'
    try:
        details = json.loads(row.details)
        if not isinstance(details, dict):
            raise ValueError('Invalid audit payload')
    except (ValueError, TypeError):
        details = {}
        integrity = 'invalid'
    # An invalid record is identified, but its altered content is not presented as history.
    if integrity == 'invalid':
        details = {}
    before = snapshot(details.get('before'))
    after = snapshot(details if row.action == 'risk.create' else details.get('after'))
    changes = []
    if before is not None and after is not None:
        changes = [{'field': key, 'before': before[key], 'after': after[key]}
                   for key in FIELDS if key in before and key in after and before[key] != after[key]]
    return {'id': row.id, 'at': row.at, 'action': row.action,
            'actor_id': row.actor_id, 'actor': actor or row.actor_id,
            'integrity': integrity, 'before': before, 'after': after,
            'changes': changes, 'resolution': details.get('resolution'),
            'source': details.get('source')}


@main.app.get('/api/risks/{rid}/history')
def risk_history(rid: str, limit: int = Query(50, ge=1, le=200),
                 offset: int = Query(0, ge=0),
                 u: main.User = Depends(main.principal), s: Session = Depends(main.db)):
    risk = main.get_risk(s, rid, u.tenant_id)
    conditions = (main.Audit.tenant_id == u.tenant_id,
                  main.Audit.object_id == rid, main.Audit.action.in_(ACTIONS))
    total = s.scalar(select(func.count()).select_from(main.Audit).where(*conditions))
    rows = s.scalars(select(main.Audit).where(*conditions)
                     .order_by(main.Audit.at.desc(), main.Audit.id.desc())
                     .offset(offset).limit(limit)).all()
    actor_ids = {row.actor_id for row in rows}
    actors = dict(s.execute(select(main.User.id, main.User.email).where(
        main.User.tenant_id == u.tenant_id, main.User.id.in_(actor_ids))).all()) if actor_ids else {}
    return {'risk_id': rid, 'current_version': risk.version, 'total': total,
            'limit': limit, 'offset': offset,
            'items': [revision(row, actors.get(row.actor_id)) for row in rows],
            'notice': 'Recorded create, edit, AI-applied score changes and closure events only. '
                      'Missing historical values are not reconstructed. Verified means this event '
                      'matches its audit signature; it does not prove the history is complete. '
                      'Unsigned or unverified events are not integrity-verified.'}
