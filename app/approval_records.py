"""Durable approval and remediation workflows. Author: Shahryar Jahangir, Aniza Inc."""
from datetime import date
from fastapi import Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import Column, String, Integer, Text, DateTime, ForeignKey, select, update
from sqlalchemy.orm import Session
from .main import Base, app, db, User, Risk, principal, permit, uid, utc, log, get_risk
from .governance_records import Finding, Policy, owned

class Approval(Base):
    __tablename__='approvals'
    id=Column(String(36),primary_key=True,default=uid)
    tenant_id=Column(String(36),ForeignKey('tenants.id'),nullable=False,index=True)
    object_type=Column(String(20),nullable=False)
    object_id=Column(String(36),nullable=False,index=True)
    reason=Column(Text,nullable=False)
    requester_id=Column(String(36),nullable=False)
    approver_id=Column(String(36),nullable=True)
    decision_note=Column(Text,nullable=True)
    state=Column(String(20),nullable=False,default='pending')
    version=Column(Integer,nullable=False,default=1)
    target_version=Column(Integer,nullable=True)
    created_at=Column(DateTime(timezone=True),nullable=False,default=utc)
    decided_at=Column(DateTime(timezone=True),nullable=True)

class Remediation(Base):
    __tablename__='remediations'
    id=Column(String(36),primary_key=True,default=uid)
    tenant_id=Column(String(36),ForeignKey('tenants.id'),nullable=False,index=True)
    finding_id=Column(String(36),ForeignKey('control_findings.id'),nullable=False,index=True)
    description=Column(Text,nullable=False)
    owner=Column(String(200),nullable=False)
    due_date=Column(String(10),nullable=False)
    state=Column(String(20),nullable=False,default='open')
    closure_note=Column(Text,nullable=True)
    version=Column(Integer,nullable=False,default=1)
    created_at=Column(DateTime(timezone=True),nullable=False,default=utc)

class ApprovalIn(BaseModel):
    object_type:str=Field(pattern='^(risk|policy|finding)$')
    object_id:str
    reason:str=Field(min_length=5,max_length=5000)
class DecisionIn(BaseModel):
    version:int=Field(ge=1)
    decision:str=Field(pattern='^(approved|rejected)$')
    note:str=Field(min_length=5,max_length=5000)
class RemediationIn(BaseModel):
    finding_id:str
    description:str=Field(min_length=5,max_length=10000)
    owner:str=Field(min_length=1,max_length=200)
    due_date:date
class RemediationTransition(BaseModel):
    version:int=Field(ge=1)
    state:str=Field(pattern='^(in_progress|blocked|ready_for_review|closed|reopened)$')
    note:str=Field(min_length=5,max_length=5000)
    retest_id:str|None=Field(default=None,max_length=36)
    evidence_ids:list[str]=Field(default_factory=list,max_length=5)

def asdict(x,keys):return {k:getattr(x,k) for k in keys}
AK=('target_version','id','object_type','object_id','reason','requester_id','approver_id','decision_note','state','version','created_at','decided_at')
RK=('id','finding_id','description','owner','due_date','state','closure_note','version','created_at')
def target(s,tenant,kind,obj):
    if kind=='risk':get_risk(s,obj,tenant)
    elif kind=='policy':owned(s,Policy,obj,tenant)
    else:owned(s,Finding,obj,tenant)

@app.post('/api/approvals',status_code=201)
def request_approval(body:ApprovalIn,u:User=Depends(permit('tenant_admin','risk_manager','risk_editor')),s:Session=Depends(db)):
    from . import approval_binding
    record,snapshot_sha=approval_binding.target(s,u.tenant_id,body.object_type,body.object_id,True)
    existing=s.scalar(select(Approval.id).where(Approval.tenant_id==u.tenant_id,Approval.object_type==body.object_type,Approval.object_id==body.object_id,Approval.state=='pending'))
    if existing:raise HTTPException(409,'Pending approval already exists')
    policy_version=getattr(record,'version',None)
    a=Approval(tenant_id=u.tenant_id,requester_id=u.id,target_version=policy_version,**body.model_dump())
    s.add(a);s.flush();log(s,u,'approval.request',a.id,body.model_dump()|{'requester_id':u.id,'target_snapshot_sha256':snapshot_sha},operation_details={'object_type':body.object_type,'object_id':body.object_id,'target_snapshot_sha256':snapshot_sha});s.commit();return asdict(a,AK)|{'binding_status':'current'}

@app.get('/api/approvals')
def approvals(state:str|None=None,u:User=Depends(principal),s:Session=Depends(db)):
    from . import approval_binding
    q=select(Approval).where(Approval.tenant_id==u.tenant_id)
    if state:q=q.where(Approval.state==state)
    return [asdict(a,AK)|{'binding_status':approval_binding.status(s,a)} for a in s.scalars(q.order_by(Approval.created_at.desc()).limit(500))]

@app.post('/api/approvals/{aid}/decision')
def decide(aid:str,body:DecisionIn,u:User=Depends(permit('tenant_admin','risk_manager','auditor')),s:Session=Depends(db)):
    a=owned(s,Approval,aid,u.tenant_id)
    if a.requester_id==u.id:raise HTTPException(403,'Requester cannot approve own request')
    if a.state!='pending':raise HTTPException(409,'Approval already decided')
    if body.decision=='approved':
        from . import approval_binding
        approval_binding.require_independent(s,a,u)
        if approval_binding.status(s,a,True)!='current':raise HTTPException(409,'Reviewed content changed or approval provenance is unavailable; reject this request and request a fresh review')
    changed=s.execute(update(Approval).where(Approval.id==aid,Approval.tenant_id==u.tenant_id,Approval.version==body.version,Approval.state=='pending').values(state=body.decision,decision_note=body.note,approver_id=u.id,decided_at=utc(),version=Approval.version+1))
    if changed.rowcount!=1:s.rollback();raise HTTPException(409,'Version conflict')
    log(s,u,'approval.decision',aid,body.model_dump(),operation_details={'decision':body.decision,'version':body.version})
    s.refresh(a)
    response=asdict(a,AK)
    s.commit()
    return response

@app.post('/api/remediations',status_code=201)
def create_remediation(body:RemediationIn,u:User=Depends(permit('tenant_admin','risk_manager')),s:Session=Depends(db)):
    owned(s,Finding,body.finding_id,u.tenant_id)
    r=Remediation(tenant_id=u.tenant_id,**(body.model_dump()|{'due_date':body.due_date.isoformat()}))
    s.add(r);s.flush();log(s,u,'remediation.create',r.id,body.model_dump(mode='json'));s.commit();return asdict(r,RK)

@app.get('/api/remediations')
def remediations(u:User=Depends(principal),s:Session=Depends(db)):
    return [asdict(r,RK) for r in s.scalars(select(Remediation).where(Remediation.tenant_id==u.tenant_id).order_by(Remediation.created_at.desc()).limit(500))]

@app.post('/api/remediations/{rid}/transition')
def transition(rid:str,body:RemediationTransition,u:User=Depends(permit('tenant_admin','risk_manager','auditor')),s:Session=Depends(db)):
    r=owned(s,Remediation,rid,u.tenant_id)
    allowed={'open':{'in_progress','blocked'},'in_progress':{'blocked','ready_for_review'},'blocked':{'in_progress'},'ready_for_review':{'closed','in_progress'},'closed':{'reopened'},'reopened':{'in_progress'}}
    if body.state not in allowed[r.state]:raise HTTPException(422,'Invalid state transition')
    if body.state=='closed' and u.role not in ('auditor','tenant_admin','platform_admin'):raise HTTPException(403,'Independent closure reviewer required')
    closure_proof=None
    if body.state=='closed':
        from .remediation_review import validate_closure
        closure_proof=validate_closure(s,u,r,body)
    changed=s.execute(update(Remediation).where(Remediation.id==rid,Remediation.tenant_id==u.tenant_id,Remediation.version==body.version,Remediation.state==r.state).values(state=body.state,closure_note=body.note if body.state=='closed' else r.closure_note,version=Remediation.version+1))
    if changed.rowcount!=1:s.rollback();raise HTTPException(409,'Version conflict')
    log(s,u,'remediation.transition',rid,body.model_dump()|({'closure_proof':closure_proof} if closure_proof else {}))
    s.refresh(r)
    response=asdict(r,RK)
    s.commit()
    return response
