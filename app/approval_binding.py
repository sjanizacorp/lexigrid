"""Bind legacy native approvals to exact tenant-owned content and recorded authors.

Author: Shahryar Jahangir, Aniza Inc. Uses existing immutable request audit events.
"""
import hashlib
import json

from fastapi import HTTPException
from sqlalchemy import select

from . import main


def target(s,tenant,kind,identity,lock=False):
    from .governance_records import Policy,Finding
    model,fields={
        'risk':(main.Risk,('title','description','category','owner','likelihood','impact','status','version')),
        'policy':(Policy,('code','title','body','owner','status','version')),
        'finding':(Finding,('control_id','title','severity','remediation','status'))}[kind]
    query=select(model).where(model.id==identity,model.tenant_id==tenant)
    if lock:query=query.with_for_update().execution_options(populate_existing=True)
    row=s.scalar(query)
    if row is None:raise HTTPException(404,'Approval target not found')
    values={'object_type':kind,'id':identity,'tenant_id':tenant}|{key:getattr(row,key) for key in fields}
    return row,hashlib.sha256(json.dumps(values,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()).hexdigest()


def status(s,approval,lock=False):
    events=s.scalars(select(main.Audit).where(main.Audit.tenant_id==approval.tenant_id,
        main.Audit.object_id==approval.id,main.Audit.action=='approval.request')).all()
    if len(events)!=1:return 'legacy_unbound'
    from .risk_history import revision
    signature=revision(events[0],None)['integrity']
    if signature in ('invalid','not_verified') or (main.AUDIT_HMAC_KEY and signature!='verified'):return 'integrity_unverified'
    try:
        details=json.loads(events[0].details)
        if not details.get('target_snapshot_sha256'):return 'legacy_unbound'
        if details.get('requester_id')!=approval.requester_id or events[0].actor_id!=approval.requester_id:return 'integrity_unverified'
        if approval.state=='approved':
            decisions=s.scalars(select(main.Audit).where(main.Audit.tenant_id==approval.tenant_id,
                main.Audit.object_id==approval.id,main.Audit.action=='approval.decision')).all()
            if len(decisions)!=1:return 'integrity_unverified'
            decision=decisions[0];signed=revision(decision,None)['integrity']
            if signed in ('invalid','not_verified') or (main.AUDIT_HMAC_KEY and signed!='verified'):return 'integrity_unverified'
            recorded=json.loads(decision.details)
            if decision.actor_id!=approval.approver_id or recorded.get('decision')!='approved' or recorded.get('note')!=approval.decision_note or recorded.get('version')!=approval.version-1:
                return 'integrity_unverified'
        _,current=target(s,approval.tenant_id,approval.object_type,approval.object_id,lock)
        return 'current' if current==details['target_snapshot_sha256'] else 'stale'
    except (ValueError,TypeError,KeyError,HTTPException):return 'target_unavailable'


def require_independent(s,approval,u):
    row,_=target(s,u.tenant_id,approval.object_type,approval.object_id,True)
    events=s.scalars(select(main.Audit).where(main.Audit.tenant_id==u.tenant_id,
        main.Audit.object_id==approval.object_id,main.Audit.action.in_({
            'risk':('risk.create','risk.update','risk.resolve_close'),
            'policy':('policy.create','policy.details_update','bulk.policies.create'),
            'finding':('finding.create',)}[approval.object_type]))).all()
    authors=set()
    for event in events:
        from .risk_history import revision
        if revision(event,None)['integrity'] in ('invalid','not_verified'):raise HTTPException(409,'Recorded authorship cannot be verified; investigate before approval')
        try:data=json.loads(event.details)
        except (ValueError,TypeError):raise HTTPException(409,'Recorded authorship is invalid') from None
        if data.get('source') not in ('risk_acceptance','risk_acceptance_expiry'):authors.add(event.actor_id)
    owner=str(getattr(row,'owner','')).strip().casefold()
    if approval.requester_id==u.id or u.id in authors or owner in (u.id.casefold(),u.email.casefold()):
        raise HTTPException(403,'Requester, recorded content authors and identified owners cannot approve this record')
