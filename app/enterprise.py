"""Configurable, tenant-isolated enterprise IRM work items. Author: Shahryar Jahangir, Aniza Inc."""
import json
from datetime import date
from fastapi import Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import Column, String, Integer, Text, DateTime, ForeignKey, UniqueConstraint, select, func, update
from sqlalchemy.orm import Session
from .main import Base, app, db, principal, permit, User, uid, utc, log

# Domain types are intentionally explicit: unknown types cannot bypass governance validation.
KINDS={
 'asset':('draft','active','retired'), 'business_impact':('draft','review','approved'),
 'continuity_plan':('draft','review','approved','exercised'),
 'control_test':('planned','in_progress','passed','failed','closed'),
 'obligation':('draft','active','superseded'), 'regulatory_change':('identified','assessing','implemented','closed'),
 'vendor_assessment':('draft','sent','review','approved','rejected'),
 'questionnaire':('draft','issued','received','reviewed','closed'),
 'audit_engagement':('planned','fieldwork','reporting','closed'),
 'audit_workpaper':('draft','review','approved'),
 'finding':('open','remediating','validation','closed'),
 'exception':('requested','approved','rejected','expired'),
 'risk_indicator':('draft','active','retired'),
 'notification_rule':('draft','active','disabled'),
 'integration':('draft','active','disabled'),
 'data_retention':('draft','active','retired'),
 'ai_recommendation':('proposed','accepted','rejected'),
 'resilience_exercise':('planned','executing','completed','reviewed'),
 'contract':('draft','active','expired','terminated'),
 'risk_appetite':('draft','approved','retired'),
 'policy_attestation':('pending','attested','overdue'),
 'service_dependency':('draft','active','retired'),
 'evidence_review':('pending','accepted','rejected'),
 'workflow_definition':('draft','active','retired'),
 'workflow_instance':('open','pending','completed','cancelled'),
}
REQUIRED={
 'asset':('name','owner','classification'), 'business_impact':('service_id','rto_hours','rpo_hours'),
 'continuity_plan':('service_id','owner','recovery_steps'),
 'control_test':('control_id','tester','method','scheduled_on'),
 'obligation':('citation','owner','requirement'), 'regulatory_change':('source','owner','effective_date'),
 'vendor_assessment':('vendor_id','assessor','due_date'),
 'questionnaire':('vendor_id','owner','questions'),
 'audit_engagement':('scope','lead','start_date'), 'audit_workpaper':('engagement_id','procedure','conclusion'),
 'finding':('source_id','owner','severity','due_date'), 'exception':('object_id','reason','expires_on','approver'),
 'risk_indicator':('name','owner','threshold','current_value'),
 'notification_rule':('event','recipient','channel'), 'integration':('name','endpoint','owner'),
 'data_retention':('record_type','retention_days','owner'),
 'ai_recommendation':('object_id','recommendation','evidence_refs'),
 'resilience_exercise':('plan_id','owner','exercise_date'),
 'contract':('vendor_id','owner','end_date'), 'risk_appetite':('category','threshold','owner'),
 'policy_attestation':('policy_id','user_id','due_date'),
 'service_dependency':('service_id','depends_on','owner'),
 'evidence_review':('evidence_id','reviewer','decision_reason'),
 'workflow_definition':('name','steps','owner'), 'workflow_instance':('definition_id','object_id','owner'),
}
class EnterpriseRecord(Base):
 __tablename__='enterprise_records'
 id=Column(String(36),primary_key=True,default=uid)
 tenant_id=Column(String(36),ForeignKey('tenants.id'),nullable=False,index=True)
 kind=Column(String(50),nullable=False,index=True)
 title=Column(String(200),nullable=False)
 state=Column(String(40),nullable=False)
 owner=Column(String(200),nullable=False)
 data=Column(Text,nullable=False)
 version=Column(Integer,nullable=False,default=1)
 created_by=Column(String(36),nullable=False)
 created_at=Column(DateTime(timezone=True),nullable=False,default=utc)
 updated_at=Column(DateTime(timezone=True),nullable=False,default=utc)
class EnterpriseRelation(Base):
 __tablename__='enterprise_relations'
 id=Column(String(36),primary_key=True,default=uid)
 tenant_id=Column(String(36),ForeignKey('tenants.id'),nullable=False,index=True)
 source_id=Column(String(36),ForeignKey('enterprise_records.id'),nullable=False)
 target_id=Column(String(36),ForeignKey('enterprise_records.id'),nullable=False)
 relation=Column(String(40),nullable=False)
 __table_args__=(UniqueConstraint('tenant_id','source_id','target_id','relation'),)
class RecordIn(BaseModel):
 kind:str
 title:str=Field(min_length=2,max_length=200)
 owner:str=Field(min_length=2,max_length=200)
 data:dict=Field(default_factory=dict)
 @field_validator('data')
 @classmethod
 def bounded(cls,value):
  if len(json.dumps(value,allow_nan=False))>30000:raise ValueError('Record data too large')
  return value
class TransitionIn(BaseModel):
 version:int=Field(ge=1)
 state:str
 note:str=Field(min_length=5,max_length=2000)
class RelationIn(BaseModel):
 target_id:str
 relation:str=Field(pattern='^(supports|satisfies|tests|depends_on|remediates|evidences|applies_to|related_to)$')

def validate_record(kind,data):
 if kind not in KINDS:raise HTTPException(422,'Unsupported record type')
 missing=[key for key in REQUIRED[kind] if key not in data or data[key] is None or data[key]=='']
 if missing:raise HTTPException(422,{'missing_required_fields':missing})
 for k,v in data.items():
  if k.endswith('_date') or k.endswith('_on') or k=='expires_on':
   if isinstance(v,str):
    try:date.fromisoformat(v)
    except ValueError:raise HTTPException(422,'Invalid ISO date: '+k)

def out(r):return {'id':r.id,'kind':r.kind,'title':r.title,'owner':r.owner,'state':r.state,'data':json.loads(r.data),'version':r.version,'created_by':r.created_by,'created_at':r.created_at,'updated_at':r.updated_at}

def get(s,tenant,record_id):
 r=s.scalar(select(EnterpriseRecord).where(EnterpriseRecord.id==record_id,EnterpriseRecord.tenant_id==tenant))
 if r is None:raise HTTPException(404,'Record not found')
 return r

@app.get('/api/enterprise/schema')
def schema(u:User=Depends(principal)):
 return {k:{'states':list(states),'required_fields':list(REQUIRED[k])} for k,states in KINDS.items()}

@app.post('/api/enterprise/records',status_code=201)
def create_record(body:RecordIn,u:User=Depends(permit('tenant_admin','risk_manager','risk_editor')),s:Session=Depends(db)):
 if body.kind=='ai_recommendation':raise HTTPException(403,'AI proposals must be created through risk assessment')
 validate_record(body.kind,body.data)
 r=EnterpriseRecord(tenant_id=u.tenant_id,kind=body.kind,title=body.title,owner=body.owner,data=json.dumps(body.data,sort_keys=True,allow_nan=False),state=KINDS[body.kind][0],created_by=u.id)
 s.add(r);s.flush();log(s,u,'enterprise.create',r.id,{'kind':r.kind,'title':r.title});s.commit();return out(r)

@app.get('/api/enterprise/records')
def list_records(kind:str|None=None,state:str|None=None,limit:int=Query(100,ge=1,le=500),offset:int=Query(0,ge=0),u:User=Depends(principal),s:Session=Depends(db)):
 q=select(EnterpriseRecord).where(EnterpriseRecord.tenant_id==u.tenant_id)
 if kind:
  if kind not in KINDS:raise HTTPException(422,'Unsupported record type')
  q=q.where(EnterpriseRecord.kind==kind)
 if state:q=q.where(EnterpriseRecord.state==state)
 total=s.scalar(select(func.count()).select_from(q.subquery()))
 return {'total':total,'items':[out(r) for r in s.scalars(q.order_by(EnterpriseRecord.created_at.desc(),EnterpriseRecord.id.desc()).offset(offset).limit(limit))]}

@app.get('/api/enterprise/records/{record_id}')
def record_detail(record_id:str,u:User=Depends(principal),s:Session=Depends(db)):
 return out(get(s,u.tenant_id,record_id))

@app.patch('/api/enterprise/records/{record_id}')
def edit_record(record_id:str,body:RecordIn,version:int=Query(ge=1),u:User=Depends(permit('tenant_admin','risk_manager','risk_editor')),s:Session=Depends(db)):
 existing=get(s,u.tenant_id,record_id)
 if existing.kind!=body.kind:raise HTTPException(422,'Record type is immutable')
 if existing.kind=='ai_recommendation':raise HTTPException(403,'AI proposal payloads cannot be edited')
 validate_record(body.kind,body.data)
 result=s.execute(update(EnterpriseRecord).where(EnterpriseRecord.id==record_id,EnterpriseRecord.tenant_id==u.tenant_id,EnterpriseRecord.version==version).values(title=body.title,owner=body.owner,data=json.dumps(body.data,sort_keys=True,allow_nan=False),version=EnterpriseRecord.version+1,updated_at=utc()))
 if result.rowcount!=1:s.rollback();raise HTTPException(409,'Version conflict')
 log(s,u,'enterprise.update',record_id,{'version':version+1})
 s.refresh(existing)
 response=out(existing)
 s.commit()
 return response

@app.post('/api/enterprise/records/{record_id}/transition')
def transition_record(record_id:str,body:TransitionIn,u:User=Depends(permit('tenant_admin','risk_manager','risk_editor','auditor')),s:Session=Depends(db)):
 r=get(s,u.tenant_id,record_id)
 if r.kind=='ai_recommendation':raise HTTPException(403,'Review this proposal from its risk assessment panel; use Keep current assessment or Apply AI assessment')
 if r.kind not in KINDS:raise HTTPException(422,'This record has no generic lifecycle transitions')
 states=KINDS[r.kind]
 if body.state not in states:raise HTTPException(422,'Unsupported state')
 if states.index(body.state)!=states.index(r.state)+1:raise HTTPException(409,'Transition must follow configured lifecycle order')
 if u.role=='auditor' and r.kind not in ('audit_engagement','audit_workpaper','control_test','evidence_review'):raise HTTPException(403,'Forbidden')
 # Critical lifecycle decisions require a completed, target-specific approval workflow.
 # This applies to all IRM families that expose a governed lifecycle state.
 governed={'approved','active','closed','accepted','attested','completed','implemented','exercised','reviewed','passed','failed','retired','superseded','terminated'}
 authorization=None
 if body.state in governed and r.kind not in ('workflow_definition','workflow_instance'):
  from .workflows import WorkflowRun, record_digest
  authorization=s.scalar(select(WorkflowRun).where(WorkflowRun.tenant_id==u.tenant_id,WorkflowRun.object_id==record_id,WorkflowRun.target_state==body.state,WorkflowRun.state=='approved',WorkflowRun.consumed_at.is_(None)).order_by(WorkflowRun.finished_at.desc()))
  if authorization is None:raise HTTPException(409,'An approved workflow for this record and target state is required')
  if authorization.object_version!=r.version or authorization.object_digest!=record_digest(r):
   raise HTTPException(409,'Approved record has changed; a new independent approval is required')
 result=s.execute(update(EnterpriseRecord).where(EnterpriseRecord.id==record_id,EnterpriseRecord.tenant_id==u.tenant_id,EnterpriseRecord.version==body.version).values(state=body.state,version=EnterpriseRecord.version+1,updated_at=utc()))
 if result.rowcount!=1:s.rollback();raise HTTPException(409,'Version conflict')
 if authorization is not None:
  consumed=s.execute(update(WorkflowRun).where(WorkflowRun.id==authorization.id,WorkflowRun.tenant_id==u.tenant_id,WorkflowRun.consumed_at.is_(None),WorkflowRun.state=='approved').values(consumed_at=utc()))
  if consumed.rowcount!=1:s.rollback();raise HTTPException(409,'Approval was already consumed')
 log(s,u,'enterprise.transition',record_id,{'to':body.state,'note':body.note})
 s.refresh(r)
 response=out(r)
 s.commit()
 return response

@app.post('/api/enterprise/records/{record_id}/relations',status_code=201)
def relate(record_id:str,body:RelationIn,u:User=Depends(permit('tenant_admin','risk_manager','risk_editor')),s:Session=Depends(db)):
 get(s,u.tenant_id,record_id);get(s,u.tenant_id,body.target_id)
 if record_id==body.target_id:raise HTTPException(422,'Self-link forbidden')
 if s.scalar(select(EnterpriseRelation.id).where(EnterpriseRelation.tenant_id==u.tenant_id,EnterpriseRelation.source_id==record_id,EnterpriseRelation.target_id==body.target_id,EnterpriseRelation.relation==body.relation)):raise HTTPException(409,'Duplicate relation')
 relation=EnterpriseRelation(tenant_id=u.tenant_id,source_id=record_id,target_id=body.target_id,relation=body.relation)
 s.add(relation);s.flush();log(s,u,'enterprise.relate',relation.id,{'source':record_id,'target':body.target_id,'relation':body.relation});s.commit()
 return {'id':relation.id,'source_id':record_id,'target_id':body.target_id,'relation':body.relation}

@app.get('/api/enterprise/records/{record_id}/relations')
def list_relations(record_id:str,u:User=Depends(principal),s:Session=Depends(db)):
 get(s,u.tenant_id,record_id)
 return [{'id':r.id,'source_id':r.source_id,'target_id':r.target_id,'relation':r.relation} for r in s.scalars(select(EnterpriseRelation).where(EnterpriseRelation.tenant_id==u.tenant_id,EnterpriseRelation.source_id==record_id))]

@app.get('/api/enterprise/metrics')
def enterprise_metrics(u:User=Depends(principal),s:Session=Depends(db)):
 rows=s.execute(select(EnterpriseRecord.kind,EnterpriseRecord.state,func.count()).where(EnterpriseRecord.tenant_id==u.tenant_id).group_by(EnterpriseRecord.kind,EnterpriseRecord.state))
 return {'counts':[{'kind':kind,'state':state,'count':count} for kind,state,count in rows]}
