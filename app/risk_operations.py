"""LexiGrid enterprise risk lifecycle. Author: Shahryar Jahangir, Aniza Inc."""
from datetime import datetime, timezone
import uuid, json
from fastapi import Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import Column, String, Integer, DateTime, Text, ForeignKey, UniqueConstraint, select, func, update
from sqlalchemy.orm import Session
from .main import Base, app, db, principal, permit, Risk, User, log, utc, uid, get_risk

class Assessment(Base):
    __tablename__='risk_assessments'
    id=Column(String(36),primary_key=True,default=uid)
    tenant_id=Column(String(36),ForeignKey('tenants.id'),nullable=False,index=True)
    risk_id=Column(String(36),ForeignKey('risks.id'),nullable=False,index=True)
    kind=Column(String(20),nullable=False)
    likelihood=Column(Integer,nullable=False)
    impact=Column(Integer,nullable=False)
    rationale=Column(Text,nullable=False)
    assessor_id=Column(String(36),nullable=False)
    assessed_at=Column(DateTime(timezone=True),nullable=False,default=utc)
class Treatment(Base):
    __tablename__='risk_treatments'
    id=Column(String(36),primary_key=True,default=uid)
    tenant_id=Column(String(36),ForeignKey('tenants.id'),nullable=False,index=True)
    risk_id=Column(String(36),ForeignKey('risks.id'),nullable=False,index=True)
    strategy=Column(String(20),nullable=False)
    description=Column(Text,nullable=False)
    owner=Column(String(200),nullable=False)
    due_date=Column(String(10),nullable=False)
    status=Column(String(20),nullable=False,default='planned')
    version=Column(Integer,nullable=False,default=1)
    created_at=Column(DateTime(timezone=True),nullable=False,default=utc)
class RiskLink(Base):
    __tablename__='risk_links'
    id=Column(String(36),primary_key=True,default=uid)
    tenant_id=Column(String(36),ForeignKey('tenants.id'),nullable=False,index=True)
    source_id=Column(String(36),ForeignKey('risks.id'),nullable=False)
    target_id=Column(String(36),ForeignKey('risks.id'),nullable=False)
    relation=Column(String(30),nullable=False)
    __table_args__=(UniqueConstraint('tenant_id','source_id','target_id','relation'),)
class RiskComment(Base):
    __tablename__='risk_comments'
    id=Column(String(36),primary_key=True,default=uid)
    tenant_id=Column(String(36),ForeignKey('tenants.id'),nullable=False,index=True)
    risk_id=Column(String(36),ForeignKey('risks.id'),nullable=False,index=True)
    author_id=Column(String(36),nullable=False)
    body=Column(Text,nullable=False)
    created_at=Column(DateTime(timezone=True),nullable=False,default=utc)

class AssessmentIn(BaseModel):
    kind:str=Field(pattern='^(inherent|residual|target)$')
    likelihood:int=Field(ge=1,le=5)
    impact:int=Field(ge=1,le=5)
    rationale:str=Field(min_length=5,max_length=10000)
class TreatmentIn(BaseModel):
    strategy:str=Field(pattern='^(mitigate|accept|avoid|transfer|monitor)$')
    description:str=Field(min_length=5,max_length=10000)
    owner:str=Field(min_length=1,max_length=200)
    due_date:str=Field(pattern=r'^\d{4}-\d{2}-\d{2}$')
class TreatmentUpdate(BaseModel):
    version:int=Field(ge=1)
    status:str=Field(pattern='^(planned|in_progress|blocked|completed|cancelled)$')
class LinkIn(BaseModel):
    target_id:str
    relation:str=Field(pattern='^(depends_on|contributes_to|duplicates|related_to)$')
class CommentIn(BaseModel):
    body:str=Field(min_length=1,max_length=10000)

def assessment_out(a):
    return {'id':a.id,'risk_id':a.risk_id,'kind':a.kind,'likelihood':a.likelihood,'impact':a.impact,'score':a.likelihood*a.impact,'rationale':a.rationale,'assessor_id':a.assessor_id,'assessed_at':a.assessed_at}
def treatment_out(t):
    return {k:getattr(t,k) for k in ('id','risk_id','strategy','description','owner','due_date','status','version','created_at')}

@app.post('/api/risks/{rid}/assessments',status_code=201)
def add_assessment(rid:str,body:AssessmentIn,u:User=Depends(permit('tenant_admin','risk_manager','risk_editor')),s:Session=Depends(db)):
    get_risk(s,rid,u.tenant_id)
    a=Assessment(tenant_id=u.tenant_id,risk_id=rid,assessor_id=u.id,**body.model_dump())
    s.add(a);s.flush();log(s,u,'assessment.create',a.id,{'risk_id':rid,**body.model_dump()});s.commit()
    return assessment_out(a)
@app.get('/api/risks/{rid}/assessments')
def list_assessments(rid:str,u:User=Depends(principal),s:Session=Depends(db)):
    get_risk(s,rid,u.tenant_id)
    return [assessment_out(a) for a in s.scalars(select(Assessment).where(Assessment.tenant_id==u.tenant_id,Assessment.risk_id==rid).order_by(Assessment.assessed_at.desc(),Assessment.id.desc()))]
@app.get('/api/risks/{rid}/profile')
def risk_profile(rid:str,u:User=Depends(principal),s:Session=Depends(db)):
    r=get_risk(s,rid,u.tenant_id)
    rows=s.scalars(select(Assessment).where(Assessment.tenant_id==u.tenant_id,Assessment.risk_id==rid).order_by(Assessment.assessed_at.desc(),Assessment.id.desc())).all()
    latest={}
    for a in rows:
        if a.kind not in latest:latest[a.kind]=assessment_out(a)
    return {'risk_id':rid,'title':r.title,'baseline_score':r.likelihood*r.impact,'latest_assessments':latest,'treatments':s.scalar(select(func.count()).select_from(Treatment).where(Treatment.tenant_id==u.tenant_id,Treatment.risk_id==rid))}
@app.post('/api/risks/{rid}/treatments',status_code=201)
def add_treatment(rid:str,body:TreatmentIn,u:User=Depends(permit('tenant_admin','risk_manager','risk_editor')),s:Session=Depends(db)):
    get_risk(s,rid,u.tenant_id)
    try: datetime.strptime(body.due_date,'%Y-%m-%d')
    except ValueError: raise HTTPException(422,'Invalid due date')
    t=Treatment(tenant_id=u.tenant_id,risk_id=rid,**body.model_dump());s.add(t);s.flush();log(s,u,'treatment.create',t.id,{'risk_id':rid,**body.model_dump()});s.commit();return treatment_out(t)
@app.get('/api/risks/{rid}/treatments')
def list_treatments(rid:str,u:User=Depends(principal),s:Session=Depends(db)):
    get_risk(s,rid,u.tenant_id)
    return [treatment_out(t) for t in s.scalars(select(Treatment).where(Treatment.tenant_id==u.tenant_id,Treatment.risk_id==rid).order_by(Treatment.created_at.desc()))]
@app.patch('/api/treatments/{tid}')
def change_treatment(tid:str,body:TreatmentUpdate,u:User=Depends(permit('tenant_admin','risk_manager','risk_editor')),s:Session=Depends(db)):
    # Atomic compare-and-swap, preventing lost updates under concurrent transactions.
    result=s.execute(update(Treatment).where(Treatment.id==tid,Treatment.tenant_id==u.tenant_id,Treatment.version==body.version).values(status=body.status,version=Treatment.version+1))
    if result.rowcount!=1:
        exists=s.scalar(select(Treatment.id).where(Treatment.id==tid,Treatment.tenant_id==u.tenant_id))
        s.rollback();raise HTTPException(409 if exists else 404,'Version conflict' if exists else 'Treatment not found')
    t=s.scalar(select(Treatment).where(Treatment.id==tid,Treatment.tenant_id==u.tenant_id));log(s,u,'treatment.update',tid,{'status':body.status,'version':t.version});s.commit();return treatment_out(t)
@app.post('/api/risks/{rid}/links',status_code=201)
def add_link(rid:str,body:LinkIn,u:User=Depends(permit('tenant_admin','risk_manager','risk_editor')),s:Session=Depends(db)):
    get_risk(s,rid,u.tenant_id);get_risk(s,body.target_id,u.tenant_id)
    if rid==body.target_id:raise HTTPException(422,'Self-links are not allowed')
    existing=s.scalar(select(RiskLink).where(RiskLink.tenant_id==u.tenant_id,RiskLink.source_id==rid,RiskLink.target_id==body.target_id,RiskLink.relation==body.relation))
    if existing:raise HTTPException(409,'Relationship exists')
    link=RiskLink(tenant_id=u.tenant_id,source_id=rid,**body.model_dump());s.add(link);s.flush();log(s,u,'risk.link',link.id,{'source_id':rid,**body.model_dump()});s.commit();return {'id':link.id,'source_id':rid,**body.model_dump()}
@app.get('/api/risks/{rid}/links')
def list_links(rid:str,u:User=Depends(principal),s:Session=Depends(db)):
    get_risk(s,rid,u.tenant_id)
    return [{'id':l.id,'source_id':l.source_id,'target_id':l.target_id,'relation':l.relation} for l in s.scalars(select(RiskLink).where(RiskLink.tenant_id==u.tenant_id,RiskLink.source_id==rid))]
@app.post('/api/risks/{rid}/comments',status_code=201)
def add_comment(rid:str,body:CommentIn,u:User=Depends(permit('tenant_admin','risk_manager','risk_editor')),s:Session=Depends(db)):
    get_risk(s,rid,u.tenant_id)
    c=RiskComment(tenant_id=u.tenant_id,risk_id=rid,author_id=u.id,body=body.body);s.add(c);s.flush();log(s,u,'risk.comment',c.id,{'risk_id':rid});s.commit();return {'id':c.id,'body':c.body,'author_id':c.author_id,'created_at':c.created_at}
@app.get('/api/risks/{rid}/comments')
def list_comments(rid:str,u:User=Depends(principal),s:Session=Depends(db)):
    get_risk(s,rid,u.tenant_id)
    return [{'id':c.id,'body':c.body,'author_id':c.author_id,'created_at':c.created_at} for c in s.scalars(select(RiskComment).where(RiskComment.tenant_id==u.tenant_id,RiskComment.risk_id==rid).order_by(RiskComment.created_at.desc()))]
@app.get('/api/analytics/heatmap')
def heatmap(u:User=Depends(principal),s:Session=Depends(db)):
    cells={(l,i):0 for l in range(1,6) for i in range(1,6)}
    for l,i,count in s.execute(select(Risk.likelihood,Risk.impact,func.count()).where(Risk.tenant_id==u.tenant_id).group_by(Risk.likelihood,Risk.impact)):
        cells[(l,i)]=count
    return {'cells':[{'likelihood':l,'impact':i,'count':cells[(l,i)],'score':l*i} for l in range(1,6) for i in range(1,6)],'total':sum(cells.values())}
@app.get('/api/analytics/categories')
def categories(u:User=Depends(principal),s:Session=Depends(db)):
    return [{'category':category,'count':count} for category,count in s.execute(select(Risk.category,func.count()).where(Risk.tenant_id==u.tenant_id).group_by(Risk.category).order_by(func.count().desc()))]
