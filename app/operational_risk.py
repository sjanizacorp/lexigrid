"""LexiGrid third-party and operational risk. Shahryar Jahangir, Aniza Inc."""
from datetime import date
from fastapi import Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import Column, String, Integer, Text, DateTime, ForeignKey, select, update, UniqueConstraint
from sqlalchemy.orm import Session
from .main import Base, app, db, User, Risk, principal, permit, uid, utc, log, get_risk
from .governance_records import owned

class Vendor(Base):
    __tablename__='vendors'
    id=Column(String(36),primary_key=True,default=uid)
    tenant_id=Column(String(36),ForeignKey('tenants.id'),nullable=False,index=True)
    name=Column(String(200),nullable=False)
    service=Column(String(300),nullable=False)
    criticality=Column(String(20),nullable=False)
    owner=Column(String(200),nullable=False)
    status=Column(String(20),nullable=False,default='onboarding')
    version=Column(Integer,nullable=False,default=1)
    created_at=Column(DateTime(timezone=True),nullable=False,default=utc)
    __table_args__=(UniqueConstraint('tenant_id','name'),)
class VendorAssessment(Base):
    __tablename__='vendor_assessments'
    id=Column(String(36),primary_key=True,default=uid)
    tenant_id=Column(String(36),ForeignKey('tenants.id'),nullable=False,index=True)
    vendor_id=Column(String(36),ForeignKey('vendors.id'),nullable=False,index=True)
    assessed_by=Column(String(36),nullable=False)
    security_score=Column(Integer,nullable=False)
    privacy_score=Column(Integer,nullable=False)
    resilience_score=Column(Integer,nullable=False)
    findings=Column(Text,nullable=False)
    assessed_at=Column(DateTime(timezone=True),nullable=False,default=utc)
class BusinessService(Base):
    __tablename__='business_services'
    id=Column(String(36),primary_key=True,default=uid)
    tenant_id=Column(String(36),ForeignKey('tenants.id'),nullable=False,index=True)
    name=Column(String(200),nullable=False)
    owner=Column(String(200),nullable=False)
    criticality=Column(String(20),nullable=False)
    recovery_time_hours=Column(Integer,nullable=False)
    recovery_point_hours=Column(Integer,nullable=False)
    __table_args__=(UniqueConstraint('tenant_id','name'),)
class ServiceDependency(Base):
    __tablename__='service_dependencies'
    id=Column(String(36),primary_key=True,default=uid)
    tenant_id=Column(String(36),ForeignKey('tenants.id'),nullable=False,index=True)
    service_id=Column(String(36),ForeignKey('business_services.id'),nullable=False,index=True)
    vendor_id=Column(String(36),ForeignKey('vendors.id'),nullable=True)
    risk_id=Column(String(36),ForeignKey('risks.id'),nullable=True)
    __table_args__=(UniqueConstraint('tenant_id','service_id','vendor_id','risk_id'),)
class LossEvent(Base):
    __tablename__='loss_events'
    id=Column(String(36),primary_key=True,default=uid)
    tenant_id=Column(String(36),ForeignKey('tenants.id'),nullable=False,index=True)
    service_id=Column(String(36),ForeignKey('business_services.id'),nullable=False,index=True)
    risk_id=Column(String(36),ForeignKey('risks.id'),nullable=True)
    title=Column(String(200),nullable=False)
    occurred_on=Column(String(10),nullable=False)
    loss_cents=Column(Integer,nullable=False)
    description=Column(Text,nullable=False)
    created_by=Column(String(36),nullable=False)
    created_at=Column(DateTime(timezone=True),nullable=False,default=utc)

class VendorIn(BaseModel):
    name:str=Field(min_length=2,max_length=200)
    service:str=Field(min_length=2,max_length=300)
    criticality:str=Field(pattern='^(low|medium|high|critical)$')
    owner:str=Field(min_length=1,max_length=200)
class VendorTransition(BaseModel):
    version:int=Field(ge=1)
    status:str=Field(pattern='^(onboarding|active|suspended|offboarded)$')
    reason:str=Field(min_length=5,max_length=2000)
class VendorAssessmentIn(BaseModel):
    security_score:int=Field(ge=1,le=5)
    privacy_score:int=Field(ge=1,le=5)
    resilience_score:int=Field(ge=1,le=5)
    findings:str=Field(min_length=5,max_length=10000)
class ServiceIn(BaseModel):
    name:str=Field(min_length=2,max_length=200)
    owner:str=Field(min_length=1,max_length=200)
    criticality:str=Field(pattern='^(low|medium|high|critical)$')
    recovery_time_hours:int=Field(ge=0,le=8760)
    recovery_point_hours:int=Field(ge=0,le=8760)
class DependencyIn(BaseModel):
    vendor_id:str|None=None
    risk_id:str|None=None
class LossIn(BaseModel):
    service_id:str
    risk_id:str|None=None
    title:str=Field(min_length=3,max_length=200)
    occurred_on:date
    loss_cents:int=Field(ge=0,le=10**13)
    description:str=Field(min_length=5,max_length=10000)

def show(x,keys):return {k:getattr(x,k) for k in keys}
VK=('id','name','service','criticality','owner','status','version','created_at')
AK=('id','vendor_id','assessed_by','security_score','privacy_score','resilience_score','findings','assessed_at')
SK=('id','name','owner','criticality','recovery_time_hours','recovery_point_hours')
DK=('id','service_id','vendor_id','risk_id')
LK=('id','service_id','risk_id','title','occurred_on','loss_cents','description','created_by','created_at')

@app.post('/api/vendors',status_code=201)
def create_vendor(body:VendorIn,u:User=Depends(permit('tenant_admin','risk_manager')),s:Session=Depends(db)):
    if s.scalar(select(Vendor.id).where(Vendor.tenant_id==u.tenant_id,Vendor.name==body.name)):raise HTTPException(409,'Vendor already exists')
    v=Vendor(tenant_id=u.tenant_id,**body.model_dump());s.add(v);s.flush();log(s,u,'vendor.create',v.id,body.model_dump());s.commit();return show(v,VK)
@app.get('/api/vendors')
def vendors(u:User=Depends(principal),s:Session=Depends(db)):
    return [show(v,VK) for v in s.scalars(select(Vendor).where(Vendor.tenant_id==u.tenant_id).order_by(Vendor.name).limit(500))]
@app.post('/api/vendors/{vendor_id}/transition')
def vendor_transition(vendor_id:str,body:VendorTransition,u:User=Depends(permit('tenant_admin','risk_manager')),s:Session=Depends(db)):
    v=owned(s,Vendor,vendor_id,u.tenant_id)
    allowed={'onboarding':{'active','offboarded'},'active':{'suspended','offboarded'},'suspended':{'active','offboarded'},'offboarded':set()}
    if body.status not in allowed[v.status]:raise HTTPException(422,'Invalid vendor state transition')
    result=s.execute(update(Vendor).where(Vendor.id==v.id,Vendor.tenant_id==u.tenant_id,Vendor.version==body.version).values(status=body.status,version=Vendor.version+1))
    if result.rowcount!=1:s.rollback();raise HTTPException(409,'Version conflict')
    log(s,u,'vendor.transition',v.id,body.model_dump())
    s.refresh(v)
    response=show(v,VK)
    s.commit()
    return response
@app.post('/api/vendors/{vendor_id}/assessments',status_code=201)
def assess_vendor(vendor_id:str,body:VendorAssessmentIn,u:User=Depends(permit('tenant_admin','risk_manager','auditor')),s:Session=Depends(db)):
    owned(s,Vendor,vendor_id,u.tenant_id)
    a=VendorAssessment(tenant_id=u.tenant_id,vendor_id=vendor_id,assessed_by=u.id,**body.model_dump())
    s.add(a);s.flush();log(s,u,'vendor.assess',a.id,{'vendor_id':vendor_id,**body.model_dump()});s.commit();return show(a,AK)
@app.get('/api/vendors/{vendor_id}/assessments')
def vendor_assessments(vendor_id:str,u:User=Depends(principal),s:Session=Depends(db)):
    owned(s,Vendor,vendor_id,u.tenant_id)
    return [show(a,AK) for a in s.scalars(select(VendorAssessment).where(VendorAssessment.tenant_id==u.tenant_id,VendorAssessment.vendor_id==vendor_id).order_by(VendorAssessment.assessed_at.desc()).limit(500))]
@app.post('/api/business-services',status_code=201)
def create_service(body:ServiceIn,u:User=Depends(permit('tenant_admin','risk_manager')),s:Session=Depends(db)):
    if s.scalar(select(BusinessService.id).where(BusinessService.tenant_id==u.tenant_id,BusinessService.name==body.name)):raise HTTPException(409,'Service already exists')
    x=BusinessService(tenant_id=u.tenant_id,**body.model_dump());s.add(x);s.flush();log(s,u,'service.create',x.id,body.model_dump());s.commit();return show(x,SK)
@app.get('/api/business-services')
def services(u:User=Depends(principal),s:Session=Depends(db)):
    return [show(x,SK) for x in s.scalars(select(BusinessService).where(BusinessService.tenant_id==u.tenant_id).order_by(BusinessService.name).limit(500))]
@app.post('/api/business-services/{service_id}/dependencies',status_code=201)
def link_dependency(service_id:str,body:DependencyIn,u:User=Depends(permit('tenant_admin','risk_manager')),s:Session=Depends(db)):
    owned(s,BusinessService,service_id,u.tenant_id)
    if (body.vendor_id is None)==(body.risk_id is None):raise HTTPException(422,'Specify exactly one vendor_id or risk_id')
    if body.vendor_id:owned(s,Vendor,body.vendor_id,u.tenant_id)
    if body.risk_id:get_risk(s,body.risk_id,u.tenant_id)
    if s.scalar(select(ServiceDependency.id).where(ServiceDependency.tenant_id==u.tenant_id,ServiceDependency.service_id==service_id,ServiceDependency.vendor_id==body.vendor_id,ServiceDependency.risk_id==body.risk_id)):raise HTTPException(409,'Dependency exists')
    x=ServiceDependency(tenant_id=u.tenant_id,service_id=service_id,**body.model_dump());s.add(x);s.flush();log(s,u,'service.dependency',x.id,show(x,DK));s.commit();return show(x,DK)
@app.get('/api/business-services/{service_id}/dependencies')
def dependencies(service_id:str,u:User=Depends(principal),s:Session=Depends(db)):
    owned(s,BusinessService,service_id,u.tenant_id)
    return [show(x,DK) for x in s.scalars(select(ServiceDependency).where(ServiceDependency.tenant_id==u.tenant_id,ServiceDependency.service_id==service_id))]
@app.post('/api/loss-events',status_code=201)
def create_loss(body:LossIn,u:User=Depends(permit('tenant_admin','risk_manager')),s:Session=Depends(db)):
    owned(s,BusinessService,body.service_id,u.tenant_id)
    if body.risk_id:get_risk(s,body.risk_id,u.tenant_id)
    x=LossEvent(tenant_id=u.tenant_id,created_by=u.id,**(body.model_dump(mode='json')));s.add(x);s.flush();log(s,u,'loss.create',x.id,body.model_dump(mode='json'));s.commit();return show(x,LK)
@app.get('/api/loss-events')
def losses(u:User=Depends(principal),s:Session=Depends(db)):
    return [show(x,LK) for x in s.scalars(select(LossEvent).where(LossEvent.tenant_id==u.tenant_id).order_by(LossEvent.created_at.desc()).limit(500))]
@app.get('/api/operational-risk/summary')
def operational_summary(u:User=Depends(principal),s:Session=Depends(db)):
    vendors=s.scalars(select(Vendor).where(Vendor.tenant_id==u.tenant_id)).all()
    services=s.scalars(select(BusinessService).where(BusinessService.tenant_id==u.tenant_id)).all()
    losses=s.scalars(select(LossEvent).where(LossEvent.tenant_id==u.tenant_id)).all()
    return {'vendor_count':len(vendors),'critical_vendors':sum(v.criticality=='critical' for v in vendors),'service_count':len(services),'critical_services':sum(v.criticality=='critical' for v in services),'loss_event_count':len(losses),'total_loss_cents':sum(x.loss_cents for x in losses)}
