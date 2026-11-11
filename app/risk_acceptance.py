"""Content-bound, independently approved and expiring risk acceptance.

Author: Shahryar Jahangir, Aniza Inc. Existing records and audit controls are preserved.
"""
import hashlib
import json
import threading
from datetime import datetime, timezone
from types import SimpleNamespace

from fastapi import Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select, update, text, func
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from . import main
from .enterprise import EnterpriseRecord, out

KIND='risk_acceptance'
REVIEW='risk_acceptance_review'
FIELDS=('title','description','category','owner','likelihood','impact','status','version')


def payload(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False)


def digest(value):
    return hashlib.sha256(payload(value).encode()).hexdigest()


def snapshot(risk):
    return {key:getattr(risk,key) for key in FIELDS}


def instant(value):
    v=datetime.fromisoformat(value) if isinstance(value,str) else value
    if v.tzinfo is None:raise ValueError('Timezone required')
    return v.astimezone(timezone.utc)


def lock_risk(s,rid,tenant):
    r=s.scalar(select(main.Risk).where(main.Risk.id==rid,main.Risk.tenant_id==tenant).with_for_update())
    if r is None:raise HTTPException(404,'Risk not found')
    # SQLite ignores FOR UPDATE. An early compare-and-swap write serializes its writers too.
    try:
        changed=s.execute(update(main.Risk).where(main.Risk.id==rid,main.Risk.tenant_id==tenant,
            main.Risk.version==r.version).values(version=r.version))
    except OperationalError as exc:
        s.rollback()
        if s.bind.dialect.name=='sqlite':raise HTTPException(409,'Risk is being reviewed; refresh and retry') from exc
        raise
    if changed.rowcount!=1:s.rollback();raise HTTPException(409,'Risk changed; refresh and retry')
    return r


def authors(s,risk):
    from .risk_contacts import RiskContact
    events=s.scalars(select(main.Audit).where(main.Audit.tenant_id==risk.tenant_id,
        main.Audit.object_id==risk.id,main.Audit.action.in_(('risk.create','risk.update','risk.resolve_close')))).all()
    ids=set()
    for event in events:
        from .risk_history import revision
        if revision(event,None)['integrity'] in ('invalid','not_verified'):
            raise HTTPException(409,'Risk authorship history cannot be verified; investigate before acceptance review')
        try:details=json.loads(event.details)
        except (ValueError,TypeError):raise HTTPException(409,'Risk authorship history is invalid') from None
        if details.get('source') not in ('risk_acceptance','risk_acceptance_expiry'):ids.add(event.actor_id)
    owners=set(s.scalars(select(RiskContact.email).where(RiskContact.tenant_id==risk.tenant_id,
        RiskContact.risk_id==risk.id,RiskContact.role=='owner')).all())
    owners.add(risk.owner.strip())
    return ids,{v.casefold() for v in owners}


def scoped_records(s,tenant,rid):
    return s.scalars(select(EnterpriseRecord).where(EnterpriseRecord.tenant_id==tenant,
        EnterpriseRecord.kind==KIND,EnterpriseRecord.title==rid)
        .order_by(EnterpriseRecord.created_at.desc(),EnterpriseRecord.id)).all()


def effective(record,risk,now=None):
    data=json.loads(record.data)
    return bool(record.state=='approved' and risk.status=='accepted' and
        data.get('approved_risk_version')==risk.version and instant(data['expires_at'])>(now or main.utc()) and
        data.get('approved_snapshot_sha256')==digest(snapshot(risk)))


def actor_names(s,tenant,rows):
    identities=set()
    for row in rows:
        try:
            value=json.loads(row.data)
            identities.update(value[key] for key in ('requester_id','decided_by') if isinstance(value.get(key),str))
        except (ValueError,TypeError,AttributeError):continue
    return dict(s.execute(select(main.User.id,main.User.email).where(main.User.tenant_id==tenant,main.User.id.in_(identities))).all()) if identities else {}


def record_view(s,row,risk=None,names=None):
    try:
        data=json.loads(row.data);verify_request(s,row,data)
        if row.state in ('approved','expired','superseded'):verify_approval(s,row,data)
        value=out(row)
        names=names or {}
        value['requester']=names.get(data['requester_id'],data['requester_id'])
        value['decided_by']=names.get(data.get('decided_by'),data.get('decided_by'))
        value['provenance']='content_bound' if not main.AUDIT_HMAC_KEY else 'signature_verified'
        if risk is not None:value['effective']=effective(row,risk)
        return value
    except (HTTPException,ValueError,KeyError,TypeError):
        return {'id':row.id,'kind':row.kind,'title':row.title,'state':row.state,'version':row.version,
                'data':{},'effective':False,'provenance':'invalid_or_unavailable','created_at':row.created_at}


class RequestAcceptance(BaseModel):
    risk_version:int=Field(ge=1)
    reason:str=Field(min_length=10,max_length=5000)
    expires_at:datetime

    @field_validator('expires_at')
    @classmethod
    def aware_expiry(cls,value):
        if value.tzinfo is None:raise ValueError('Expiry must include a timezone')
        return value.astimezone(timezone.utc)


class AcceptanceDecision(BaseModel):
    version:int=Field(ge=1)
    decision:str=Field(pattern='^(approved|rejected|revoked)$')
    note:str=Field(min_length=10,max_length=5000)


@main.app.get('/api/risk-acceptances')
def acceptance_queue(state:str|None=Query(None,pattern='^(pending|approved|rejected|revoked|expired|superseded)$'),
                     limit:int=Query(50,ge=1,le=200),offset:int=Query(0,ge=0),
                     u:main.User=Depends(main.principal),s:Session=Depends(main.db)):
    conditions=[EnterpriseRecord.tenant_id==u.tenant_id,EnterpriseRecord.kind==KIND]
    if state:conditions.append(EnterpriseRecord.state==state)
    rows=s.scalars(select(EnterpriseRecord).where(*conditions)
        .order_by(EnterpriseRecord.created_at.desc(),EnterpriseRecord.id).offset(offset).limit(limit)).all()
    names=actor_names(s,u.tenant_id,rows)
    return {'total':s.scalar(select(func.count()).select_from(EnterpriseRecord).where(*conditions)),
        'items':[record_view(s,row,names=names) for row in rows]}


@main.app.get('/api/risk-acceptance-reviews')
def review_queue(limit:int=Query(50,ge=1,le=200),offset:int=Query(0,ge=0),
                 u:main.User=Depends(main.principal),s:Session=Depends(main.db)):
    conditions=(EnterpriseRecord.tenant_id==u.tenant_id,EnterpriseRecord.kind==REVIEW,EnterpriseRecord.state=='review_required')
    rows=s.execute(select(EnterpriseRecord,main.Risk.title).outerjoin(main.Risk,
        (main.Risk.id==EnterpriseRecord.title)&(main.Risk.tenant_id==u.tenant_id)).where(*conditions)
        .order_by(EnterpriseRecord.created_at.desc(),EnterpriseRecord.id).offset(offset).limit(limit)).all()
    return {'total':s.scalar(select(func.count()).select_from(EnterpriseRecord).where(*conditions)),
        'items':[out(row)|{'risk_title':title} for row,title in rows]}


@main.app.get('/api/risks/{rid}/acceptances')
def list_acceptances(rid:str,limit:int=Query(50,ge=1,le=200),offset:int=Query(0,ge=0),
                     u:main.User=Depends(main.principal),s:Session=Depends(main.db)):
    risk=main.get_risk(s,rid,u.tenant_id)
    conditions=(EnterpriseRecord.tenant_id==u.tenant_id,EnterpriseRecord.kind==KIND,EnterpriseRecord.title==rid)
    rows=s.scalars(select(EnterpriseRecord).where(*conditions).order_by(EnterpriseRecord.created_at.desc(),EnterpriseRecord.id)
        .offset(offset).limit(limit)).all()
    def checked(row):
        try:
            data=json.loads(row.data);verify_request(s,row,data)
            if row.state=='approved':verify_approval(s,row,data)
            return effective(row,risk)
        except (HTTPException,ValueError,KeyError,TypeError):return False
    approved=s.scalars(select(EnterpriseRecord).where(*conditions,EnterpriseRecord.state=='approved')).all()
    valid=any(checked(row) for row in approved)
    names=actor_names(s,u.tenant_id,rows)
    actor_ids,owners=authors(s,risk)
    return {'risk_id':rid,'risk_version':risk.version,'total':s.scalar(select(func.count()).select_from(EnterpriseRecord).where(*conditions)),'valid_acceptance':valid,
        'legacy_or_unverified':risk.status=='accepted' and not valid,
        'can_approve':u.role in ('tenant_admin','risk_manager','auditor','platform_admin') and u.id not in actor_ids and u.email.casefold() not in owners and u.id.casefold() not in owners,
        'items':[record_view(s,row,risk,names) for row in rows],
        'notice':'Acceptance applies only to the exact reviewed risk until its UTC expiry. Any risk revision invalidates it. '
                 'Recorded authors, accountable owner identities and the requester cannot approve. Free-text owner labels '
                 'are not directory identities. Legacy accepted risks are preserved and require documented review.'}


@main.app.post('/api/risks/{rid}/acceptances',status_code=201)
def request_acceptance(rid:str,body:RequestAcceptance,u:main.User=Depends(main.permit('tenant_admin','risk_manager','risk_editor')),s:Session=Depends(main.db)):
    risk=lock_risk(s,rid,u.tenant_id)
    if risk.version!=body.risk_version:raise HTTPException(409,'Risk version changed; refresh before requesting review')
    if risk.status=='closed':raise HTTPException(409,'Reopen the risk before requesting acceptance')
    if body.expires_at<=main.utc():raise HTTPException(422,'Expiry must be in the future')
    if len(body.reason.strip())<10:raise HTTPException(422,'Provide a substantive acceptance rationale')
    if s.scalar(select(EnterpriseRecord.id).where(EnterpriseRecord.tenant_id==u.tenant_id,
        EnterpriseRecord.kind==KIND,EnterpriseRecord.title==rid,EnterpriseRecord.state=='pending').limit(1)):
        raise HTTPException(409,'A pending acceptance already exists; reject it before replacing it')
    data={'risk_id':rid,'risk_snapshot':snapshot(risk),'snapshot_sha256':digest(snapshot(risk)),
          'requester_id':u.id,'reason':body.reason.strip(),'expires_at':body.expires_at.isoformat()}
    row=EnterpriseRecord(id=main.uid(),tenant_id=u.tenant_id,kind=KIND,title=rid,owner=risk.owner,
        state='pending',created_by=u.id,data=payload(data))
    s.add(row);s.flush()
    main.log(s,u,'risk.acceptance.requested',row.id,{'risk_id':rid,'request_sha256':digest(data),'request':data},
        operation_details={'risk_id':rid,'request_sha256':digest(data),'expires_at':data['expires_at']})
    response=out(row);s.commit();return response


def verify_request(s,row,data):
    events=s.scalars(select(main.Audit).where(main.Audit.tenant_id==row.tenant_id,
        main.Audit.object_id==row.id,main.Audit.action=='risk.acceptance.requested')).all()
    if len(events)!=1:raise HTTPException(409,'Acceptance request provenance is missing or ambiguous')
    event=events[0]
    from .risk_history import revision
    checked=revision(event,None)
    if checked['integrity'] in ('invalid','not_verified') or (main.AUDIT_HMAC_KEY and checked['integrity']!='verified'):
        raise HTTPException(409,'Acceptance request audit integrity cannot be verified')
    original=json.loads(event.details)
    # Decision metadata is appended later; the reviewed request remains independently bound.
    request={key:data[key] for key in ('risk_id','risk_snapshot','snapshot_sha256','requester_id','reason','expires_at')}
    if original.get('request_sha256')!=digest(request) or row.created_by!=request['requester_id'] or event.actor_id!=row.created_by or request['risk_id']!=row.title:
        raise HTTPException(409,'Acceptance request content changed; investigate before review')
    if row.state=='pending' and s.scalar(select(main.Audit.id).where(main.Audit.tenant_id==row.tenant_id,
        main.Audit.object_id==row.id,main.Audit.action.in_(('risk.acceptance.approved','risk.acceptance.rejected','risk.acceptance.revoked'))).limit(1)):
        raise HTTPException(409,'Acceptance was already decided; investigate its lifecycle integrity')


def verify_approval(s,row,data):
    events=s.scalars(select(main.Audit).where(main.Audit.tenant_id==row.tenant_id,
        main.Audit.object_id==row.id,main.Audit.action=='risk.acceptance.approved')).all()
    if len(events)!=1:raise HTTPException(409,'Acceptance approval provenance is missing or ambiguous')
    event=events[0]
    from .risk_history import revision
    status=revision(event,None)['integrity']
    if status in ('invalid','not_verified') or (main.AUDIT_HMAC_KEY and status!='verified'):
        raise HTTPException(409,'Acceptance approval provenance cannot be verified')
    if json.loads(event.details).get('decision')!=data:
        raise HTTPException(409,'Acceptance approval content changed; investigate before relying on it')


@main.app.post('/api/risks/{rid}/acceptances/{aid}/decision')
def decide_acceptance(rid:str,aid:str,body:AcceptanceDecision,u:main.User=Depends(main.permit('tenant_admin','risk_manager','auditor')),s:Session=Depends(main.db)):
    risk=lock_risk(s,rid,u.tenant_id)
    row=s.scalar(select(EnterpriseRecord).where(EnterpriseRecord.id==aid,EnterpriseRecord.tenant_id==u.tenant_id,
        EnterpriseRecord.kind==KIND,EnterpriseRecord.title==rid))
    if row is None:raise HTTPException(404,'Acceptance not found')
    try:data=json.loads(row.data);verify_request(s,row,data)
    except (ValueError,KeyError,TypeError):raise HTTPException(409,'Acceptance request data is invalid; investigate its provenance') from None
    if body.version!=row.version:raise HTTPException(409,'Acceptance changed; refresh before reviewing')
    if len(body.note.strip())<10:raise HTTPException(422,'Provide a substantive decision rationale')
    if body.decision=='revoked':
        if row.state!='approved':raise HTTPException(409,'Only an approved acceptance can be revoked')
        verify_approval(s,row,data)
    elif row.state!='pending':raise HTTPException(409,'Acceptance is no longer pending')
    author_ids,owners=authors(s,risk)
    if body.decision=='approved' and (u.id==data['requester_id'] or u.id in author_ids or u.email.casefold() in owners or u.id.casefold() in owners):
        raise HTTPException(403,'Requester, recorded risk authors and accountable owners cannot approve acceptance')
    old=main.risk_dict(risk)
    if body.decision=='approved':
        if risk.status=='closed' or data['snapshot_sha256']!=digest(snapshot(risk)):
            raise HTTPException(409,'Reviewed risk content changed; reject this request and request a fresh review')
        if instant(data['expires_at'])<=main.utc():raise HTTPException(409,'Acceptance expiry has passed; request a new review')
        risk.status='accepted';risk.version+=1;risk.updated_at=main.utc()
        data.update(approved_risk_version=risk.version,approved_snapshot_sha256=digest(snapshot(risk)))
    elif body.decision=='revoked' and risk.status=='accepted' and data.get('approved_risk_version')==risk.version and data.get('approved_snapshot_sha256')==digest(snapshot(risk)):
        risk.status='mitigating';risk.version+=1;risk.updated_at=main.utc()
    data.update(decided_by=u.id,decided_at=main.utc().isoformat(),decision_note=body.note.strip())
    row.state=body.decision;row.version+=1;row.updated_at=main.utc();row.data=payload(data)
    if body.decision=='approved':
        prior=s.scalars(select(EnterpriseRecord).where(EnterpriseRecord.tenant_id==u.tenant_id,
            EnterpriseRecord.kind==KIND,EnterpriseRecord.title==rid,EnterpriseRecord.id!=aid,EnterpriseRecord.state=='approved')).all()
        for previous in prior:
            previous.state='superseded';previous.version+=1;previous.updated_at=main.utc()
            main.log(s,u,'risk.acceptance.superseded',previous.id,{'risk_id':rid,'new_acceptance_id':aid})
        reviews=s.scalars(select(EnterpriseRecord).where(EnterpriseRecord.tenant_id==u.tenant_id,
            EnterpriseRecord.kind==REVIEW,EnterpriseRecord.title==rid,EnterpriseRecord.state=='review_required')).all()
        for review in reviews:
            review.state='resolved';review.version+=1;review.updated_at=main.utc()
            main.log(s,u,'risk.acceptance.review_resolved',review.id,{'risk_id':rid,'new_acceptance_id':aid})
    s.flush()
    if risk.version!=old['version']:
        main.log(s,u,'risk.update',rid,{'before':old,'after':main.risk_dict(risk),'source':'risk_acceptance','acceptance_id':aid},
            operation_details={'source':'risk_acceptance','acceptance_id':aid,'before_version':old['version'],'version':risk.version,'status':risk.status})
        from .risk_mail_automation import queue_risk_change
        queue_risk_change(s,risk,u.email,'acceptance '+body.decision,old)
    main.log(s,u,'risk.acceptance.'+body.decision,aid,{'risk_id':rid,'decision':data,'record_version':row.version},
        operation_details={'risk_id':rid,'decision':body.decision,'record_version':row.version,'expires_at':data['expires_at']})
    response={'acceptance':out(row),'risk':main.risk_dict(risk)};s.commit();return response


def expire_tenant(s,tenant,now=None):
    now=now or main.utc();count=0
    rows=s.scalars(select(EnterpriseRecord).where(EnterpriseRecord.tenant_id==tenant,
        EnterpriseRecord.kind==KIND,EnterpriseRecord.state=='approved').order_by(EnterpriseRecord.title,EnterpriseRecord.id)).all()
    for candidate in rows:
        data=json.loads(candidate.data)
        if instant(data['expires_at'])>now:continue
        risk=lock_risk(s,candidate.title,tenant)
        s.refresh(candidate)
        if candidate.state!='approved':continue
        data=json.loads(candidate.data);verify_request(s,candidate,data);verify_approval(s,candidate,data)
        old=main.risk_dict(risk)
        if risk.status!='accepted' or data.get('approved_risk_version')!=risk.version or data.get('approved_snapshot_sha256')!=digest(snapshot(risk)):
            candidate.state='superseded';candidate.version+=1;candidate.updated_at=now
            main.log(s,SimpleNamespace(id='system:risk-acceptance-expiry',tenant_id=tenant),
                'risk.acceptance.superseded',candidate.id,{'risk_id':risk.id,'current_risk_version':risk.version})
            continue
        risk.status='mitigating';risk.version+=1;risk.updated_at=now
        candidate.state='expired';candidate.version+=1;candidate.updated_at=now
        actor=SimpleNamespace(id='system:risk-acceptance-expiry',tenant_id=tenant)
        review=EnterpriseRecord(id=main.uid(),tenant_id=tenant,kind=REVIEW,title=risk.id,owner=risk.owner,
            state='review_required',created_by=actor.id,data=payload({'risk_id':risk.id,'risk_title':risk.title,'acceptance_id':candidate.id,
            'expires_at':data['expires_at'],'risk_version':risk.version,'reason':'Acceptance expired; review or request fresh independent approval.'}))
        s.add(review);s.flush()
        main.log(s,actor,'risk.acceptance.expired',candidate.id,{'risk_id':risk.id,'review_event_id':review.id,'expires_at':data['expires_at']})
        if old['version']!=risk.version:
            main.log(s,actor,'risk.update',risk.id,{'before':old,'after':main.risk_dict(risk),'source':'risk_acceptance_expiry','acceptance_id':candidate.id},
                operation_details={'source':'risk_acceptance_expiry','acceptance_id':candidate.id,'before_version':old['version'],'version':risk.version,'status':risk.status})
            from .risk_mail_automation import queue_risk_change
            queue_risk_change(s,risk,'acceptance expiry scheduler','acceptance expired',old)
        count+=1
    return count


def scan_all(session_factory=None):
    factory=session_factory or main.SessionLocal
    with factory() as s:tenants=s.scalars(select(main.Tenant.id).order_by(main.Tenant.id)).all()
    count=0
    for tenant in tenants:
        with factory() as s:
            try:
                if s.bind.dialect.name=='postgresql':s.execute(text("SELECT set_config('app.tenant_id',:tenant,true)"),{'tenant':tenant})
                expired=expire_tenant(s,tenant);s.commit();count+=expired
            except Exception as exc:
                s.rollback()
                main.emit_event('system','risk.acceptance.tenant_scan.failed',outcome='error',tenant_id=tenant,error_type=type(exc).__name__)
    return count


def worker(stop:threading.Event):
    while not stop.wait(60):
        try:scan_all()
        except Exception as exc:
            main.emit_event('system','risk.acceptance.scan.failed',outcome='error',error_type=type(exc).__name__)
