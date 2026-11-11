"""Persisted approval workflows with step assignment and decision history.
Author: Shahryar Jahangir, Aniza Inc.
"""
import json
import hashlib
from datetime import date, datetime, timezone
from fastapi import Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import Column, String, Integer, Text, DateTime, ForeignKey, ForeignKeyConstraint, CheckConstraint, Index, select, update, UniqueConstraint
from sqlalchemy.orm import Session
from .main import Base, app, db, principal, permit, User, uid, utc, log
from .enterprise import EnterpriseRecord, get as get_record

class WorkflowRun(Base):
    __tablename__='workflow_runs'
    id=Column(String(36),primary_key=True,default=uid)
    tenant_id=Column(String(36),ForeignKey('tenants.id'),nullable=False,index=True)
    definition_id=Column(String(36),ForeignKey('enterprise_records.id'),nullable=False)
    object_id=Column(String(36),ForeignKey('enterprise_records.id'),nullable=False)
    initiated_by=Column(String(36),ForeignKey('users.id'),nullable=False)
    state=Column(String(20),nullable=False,default='pending')
    step_index=Column(Integer,nullable=False,default=0)
    version=Column(Integer,nullable=False,default=1)
    steps_snapshot=Column(Text,nullable=False)
    started_at=Column(DateTime(timezone=True),nullable=False,default=utc)
    finished_at=Column(DateTime(timezone=True),nullable=True)
    target_state=Column(String(40),nullable=True)
    consumed_at=Column(DateTime(timezone=True),nullable=True)
    object_version=Column(Integer,nullable=True)
    object_digest=Column(String(64),nullable=True)

class WorkflowDecision(Base):
    __tablename__='workflow_decisions'
    id=Column(String(36),primary_key=True,default=uid)
    tenant_id=Column(String(36),ForeignKey('tenants.id'),nullable=False,index=True)
    run_id=Column(String(36),ForeignKey('workflow_runs.id'),nullable=False,index=True)
    step_index=Column(Integer,nullable=False)
    actor_id=Column(String(36),ForeignKey('users.id'),nullable=False)
    decision=Column(String(20),nullable=False)
    note=Column(Text,nullable=False)
    at=Column(DateTime(timezone=True),nullable=False,default=utc)

class WorkflowNotification(Base):
    """Tenant-isolated durable in-app notification; unique event key prevents duplicate delivery."""
    __tablename__='workflow_notifications'
    id=Column(String(36),primary_key=True,default=uid)
    tenant_id=Column(String(36),ForeignKey('tenants.id'),nullable=False,index=True)
    recipient_id=Column(String(36),ForeignKey('users.id'),nullable=False,index=True)
    run_id=Column(String(36),ForeignKey('workflow_runs.id'),nullable=False)
    event_key=Column(String(160),nullable=False)
    message=Column(String(500),nullable=False)
    created_at=Column(DateTime(timezone=True),nullable=False,default=utc)
    read_at=Column(DateTime(timezone=True),nullable=True)
    webhook_sent_at=Column(DateTime(timezone=True),nullable=True)
    email_sent_at=Column(DateTime(timezone=True),nullable=True)
    __table_args__=(
        UniqueConstraint('tenant_id','event_key','recipient_id',name='uq_workflow_notification_event'),
        Index('uq_workflow_notification_id_tenant', 'id', 'tenant_id', unique=True),
    )

class WorkflowDelivery(Base):
    __tablename__ = 'workflow_deliveries'
    notification_id = Column(String(36), primary_key=True)
    channel = Column(String(10), primary_key=True)
    tenant_id = Column(String(36), ForeignKey('tenants.id'), nullable=False, index=True)
    status = Column(String(24), nullable=False, default='queued')
    attempts = Column(Integer, nullable=False, default=0)
    next_attempt_at = Column(DateTime(timezone=True), nullable=False, default=utc)
    lease_token = Column(String(36), nullable=True)
    last_error = Column(String(100), nullable=True)
    delivered_at = Column(DateTime(timezone=True), nullable=True)
    __table_args__ = (
        ForeignKeyConstraint(['notification_id','tenant_id'],
                             ['workflow_notifications.id','workflow_notifications.tenant_id']),
        CheckConstraint("channel IN ('webhook','email')", name='ck_workflow_delivery_channel'),
        CheckConstraint('attempts >= 0', name='ck_workflow_delivery_attempts'),
    )


def delivery_view(delivery):
    return {name:getattr(delivery,name) for name in (
        'notification_id','channel','status','attempts','next_attempt_at','last_error','delivered_at')}


def notify(s,run,recipient,event_key,message):
    s.add(WorkflowNotification(tenant_id=run.tenant_id,run_id=run.id,recipient_id=recipient,event_key=event_key,message=message))

def due_step(run):
    if run.state!='pending':return None
    raw=json.loads(run.steps_snapshot)[run.step_index].get('due_date')
    return date.fromisoformat(raw) if raw else None

class StartWorkflow(BaseModel):
    definition_id:str
    object_id:str
    target_state:str|None=None
class DecideWorkflow(BaseModel):
    version:int=Field(ge=1)
    decision:str=Field(pattern='^(approved|rejected)$')
    note:str=Field(min_length=5,max_length=2000)

def valid_steps(raw):
    if not isinstance(raw,list) or not 1<=len(raw)<=12:raise HTTPException(422,'Workflow must have 1 to 12 approval steps')
    steps=[]
    for step in raw:
        if not isinstance(step,dict):raise HTTPException(422,'Invalid workflow step')
        approver=step.get('approver_user_id')
        if not isinstance(approver,str) or not approver.strip():raise HTTPException(422,'Each step requires approver_user_id')
        if set(step)-{'approver_user_id','label','due_date'}:raise HTTPException(422,'Unsupported step properties')
        label=step.get('label','Approval')
        if not isinstance(label,str) or not 1<=len(label)<=100:raise HTTPException(422,'Invalid step label')
        due=step.get('due_date')
        if due is not None:
            try:date.fromisoformat(due)
            except (ValueError,TypeError):raise HTTPException(422,'Invalid due_date')
        steps.append({'approver_user_id':approver,'label':label,'due_date':due})
    return steps

def record_digest(record):
    """Canonical SHA-256 digest of the material content under review."""
    payload={'kind':record.kind,'title':record.title,'owner':record.owner,
             'data':json.loads(record.data),'state':record.state}
    canonical=json.dumps(payload,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


def independent_record_reviewer(s,record,user):
    from .main import Audit
    from .risk_history import revision
    events=s.scalars(select(Audit).where(Audit.tenant_id==record.tenant_id,Audit.object_id==record.id,
        Audit.action.in_(('enterprise.create','enterprise.update')))).all()
    if any(revision(event,None)['integrity'] in ('invalid','not_verified') for event in events):
        raise HTTPException(409,'Record authorship history cannot be verified')
    authors={record.created_by}|{event.actor_id for event in events}
    if user.id in authors or record.owner.strip().casefold() in (user.id.casefold(),user.email.casefold()):
        raise HTTPException(403,'Record creators, editors and identified owners cannot approve their own workflow')

def view(run):
    steps=json.loads(run.steps_snapshot)
    return {'id':run.id,'definition_id':run.definition_id,'object_id':run.object_id,'initiated_by':run.initiated_by,'state':run.state,'step_index':run.step_index,'version':run.version,'current_step':steps[run.step_index] if run.state=='pending' else None,'steps':steps,'started_at':run.started_at,'finished_at':run.finished_at,'target_state':run.target_state,'consumed_at':run.consumed_at,'object_version':run.object_version,'object_digest':run.object_digest}

@app.post('/api/workflows/runs',status_code=201)
def start(body:StartWorkflow,u:User=Depends(permit('tenant_admin','risk_manager','risk_editor')),s:Session=Depends(db)):
    definition=get_record(s,u.tenant_id,body.definition_id)
    target=s.scalar(select(EnterpriseRecord).where(EnterpriseRecord.id==body.object_id,
        EnterpriseRecord.tenant_id==u.tenant_id).with_for_update().execution_options(populate_existing=True))
    if target is None:raise HTTPException(404,'Record not found')
    if definition.kind!='workflow_definition' or definition.state!='active':raise HTTPException(409,'Workflow definition must be active')
    if target.kind in ('workflow_definition','workflow_instance'):raise HTTPException(422,'Invalid workflow target')
    if body.target_state is not None:
        from .enterprise import KINDS
        if target.kind not in KINDS:raise HTTPException(422,'This internal record has no generic lifecycle transitions')
        states=KINDS[target.kind]
        if body.target_state not in states or states.index(body.target_state)<=states.index(target.state):raise HTTPException(422,'Invalid target lifecycle state')
    steps=valid_steps(json.loads(definition.data).get('steps'))
    for step in steps:
        approver=s.scalar(select(User).where(User.id==step['approver_user_id'],User.tenant_id==u.tenant_id,User.active==1))
        if not approver:raise HTTPException(422,'Approver must be an active user in this tenant')
        if approver.id==u.id:raise HTTPException(422,'Requester cannot approve their own workflow')
        independent_record_reviewer(s,target,approver)
    existing=s.scalar(select(WorkflowRun.id).where(WorkflowRun.tenant_id==u.tenant_id,WorkflowRun.object_id==target.id,WorkflowRun.state=='pending'))
    if existing:raise HTTPException(409,'Target already has a pending workflow')
    run=WorkflowRun(tenant_id=u.tenant_id,definition_id=definition.id,object_id=target.id,initiated_by=u.id,steps_snapshot=json.dumps(steps,sort_keys=True),target_state=body.target_state,object_version=target.version,object_digest=record_digest(target))
    s.add(run);s.flush();notify(s,run,steps[0]['approver_user_id'],f'{run.id}:step:0','Approval requested: '+steps[0]['label']);log(s,u,'workflow.started',run.id,{'definition_id':definition.id,'object_id':target.id});s.commit()
    return view(run)

@app.get('/api/workflows/runs')
def list_runs(u:User=Depends(principal),s:Session=Depends(db)):
    runs=s.scalars(select(WorkflowRun).where(WorkflowRun.tenant_id==u.tenant_id).order_by(WorkflowRun.started_at.desc()).limit(250))
    return [view(r) for r in runs]

@app.get('/api/workflows/runs/{run_id}')
def detail(run_id:str,u:User=Depends(principal),s:Session=Depends(db)):
    run=s.scalar(select(WorkflowRun).where(WorkflowRun.id==run_id,WorkflowRun.tenant_id==u.tenant_id))
    if not run:raise HTTPException(404,'Workflow not found')
    decisions=s.scalars(select(WorkflowDecision).where(WorkflowDecision.tenant_id==u.tenant_id,WorkflowDecision.run_id==run_id).order_by(WorkflowDecision.at))
    return {**view(run),'history':[{'step_index':d.step_index,'actor_id':d.actor_id,'decision':d.decision,'note':d.note,'at':d.at} for d in decisions]}

@app.post('/api/workflows/runs/{run_id}/decision')
def decide(run_id:str,body:DecideWorkflow,u:User=Depends(principal),s:Session=Depends(db)):
    run=s.scalar(select(WorkflowRun).where(WorkflowRun.id==run_id,WorkflowRun.tenant_id==u.tenant_id))
    if not run:raise HTTPException(404,'Workflow not found')
    if run.state!='pending':raise HTTPException(409,'Workflow already resolved')
    steps=json.loads(run.steps_snapshot)
    decided_step = run.step_index
    if steps[decided_step]['approver_user_id']!=u.id:raise HTTPException(403,'Only assigned approver can decide')
    if run.initiated_by==u.id:raise HTTPException(403,'Separation of duties violation')
    if body.decision=='approved':
        target=s.scalar(select(EnterpriseRecord).where(EnterpriseRecord.id==run.object_id,
            EnterpriseRecord.tenant_id==u.tenant_id).with_for_update().execution_options(populate_existing=True))
        if target is None:raise HTTPException(404,'Workflow target not found')
        independent_record_reviewer(s,target,u)
        if run.object_version!=target.version or run.object_digest!=record_digest(target):
            raise HTTPException(409,'Reviewed record changed; reject the stale workflow and start a fresh review')
    next_index=decided_step+1 if body.decision=='approved' else decided_step
    new_state='rejected' if body.decision=='rejected' else ('approved' if next_index==len(steps) else 'pending')
    result=s.execute(update(WorkflowRun).where(WorkflowRun.id==run_id,WorkflowRun.tenant_id==u.tenant_id,WorkflowRun.version==body.version,WorkflowRun.state=='pending',WorkflowRun.step_index==decided_step).values(version=WorkflowRun.version+1,step_index=next_index,state=new_state,finished_at=utc() if new_state!='pending' else None))
    if result.rowcount!=1:s.rollback();raise HTTPException(409,'Workflow version conflict')
    s.add(WorkflowDecision(tenant_id=u.tenant_id,run_id=run_id,step_index=decided_step,actor_id=u.id,decision=body.decision,note=body.note))
    if new_state=='pending':
        notify(s,run,steps[next_index]['approver_user_id'],f'{run.id}:step:{next_index}','Approval requested: '+steps[next_index]['label'])
    else:
        notify(s,run,run.initiated_by,f'{run.id}:resolved','Workflow '+new_state)
    log(s,u,'workflow.decision',run_id,{'decision':body.decision,'step_index':decided_step,'note':body.note},operation_details={'decision':body.decision,'step_index':decided_step})
    s.refresh(run)
    response = view(run)
    s.commit()
    return response

@app.get('/api/workflows/notifications')
def list_notifications(u:User=Depends(principal),s:Session=Depends(db)):
    rows=s.scalars(select(WorkflowNotification).where(WorkflowNotification.tenant_id==u.tenant_id,WorkflowNotification.recipient_id==u.id).order_by(WorkflowNotification.created_at.desc()).limit(200)).all()
    delivery_rows = s.scalars(select(WorkflowDelivery).where(
        WorkflowDelivery.tenant_id == u.tenant_id,
        WorkflowDelivery.notification_id.in_([row.id for row in rows]),
    ).order_by(WorkflowDelivery.channel)) if rows else []
    deliveries = {}
    for delivery in delivery_rows:
        deliveries.setdefault(delivery.notification_id,[]).append(delivery_view(delivery))
    return [{'id':n.id,'run_id':n.run_id,'message':n.message,'created_at':n.created_at,
             'read_at':n.read_at,'delivery':deliveries.get(n.id,[])} for n in rows]

@app.get('/api/workflows/notifications/delivery')
def list_delivery(status: str | None = None, limit: int = Query(100, ge=1, le=500),
                  u: User = Depends(permit('tenant_admin','risk_manager')),
                  s: Session = Depends(db)):
    states = ('queued','sending','retry','failed','retry_requested','delivered')
    if status is not None and status not in states:
        raise HTTPException(422, 'Invalid delivery status')
    query = select(WorkflowDelivery).where(WorkflowDelivery.tenant_id == u.tenant_id)
    if status is not None:
        query = query.where(WorkflowDelivery.status == status)
    return [delivery_view(row) for row in s.scalars(query.order_by(
        WorkflowDelivery.next_attempt_at, WorkflowDelivery.notification_id,
        WorkflowDelivery.channel).limit(limit))]


class RetryDelivery(BaseModel):
    expected_attempts: int = Field(ge=0)
    reason: str = Field(min_length=10, max_length=1000)


@app.post('/api/workflows/notifications/{notification_id}/delivery/{channel}/retry')
def retry_delivery(notification_id: str, channel: str, body: RetryDelivery,
                   u: User = Depends(permit('tenant_admin','risk_manager')),
                   s: Session = Depends(db)):
    if channel not in ('email','webhook'):
        raise HTTPException(404, 'Delivery channel not found')
    notification = s.scalar(select(WorkflowNotification).where(
        WorkflowNotification.id == notification_id, WorkflowNotification.tenant_id == u.tenant_id))
    if notification is None:
        raise HTTPException(404, 'Notification not found')
    recipient = s.scalar(select(User.id).where(
        User.id == notification.recipient_id, User.tenant_id == u.tenant_id, User.active == 1))
    if recipient is None:
        raise HTTPException(409, 'Recipient is inactive or no longer available')
    reason = body.reason.strip()
    if len(reason) < 10:
        raise HTTPException(422, 'Retry reason must contain at least 10 characters after trimming')
    changed = s.scalar(update(WorkflowDelivery).where(
        WorkflowDelivery.notification_id == notification_id, WorkflowDelivery.channel == channel,
        WorkflowDelivery.tenant_id == u.tenant_id, WorkflowDelivery.status == 'failed',
        WorkflowDelivery.attempts == body.expected_attempts,
    ).values(status='retry_requested', next_attempt_at=utc(), lease_token=None)
      .returning(WorkflowDelivery.notification_id))
    if changed is None:
        s.rollback()
        raise HTTPException(409, 'Delivery changed or is not failed; refresh before retrying')
    log(s,u,'workflow.notification.retry_requested',notification_id,{
        'channel':channel,'previous_attempts':body.expected_attempts,'reason':reason,
        'additional_attempts':1})
    s.commit()
    return {'notification_id':notification_id,'channel':channel,
            'status':'retry_requested','additional_attempts':1}


@app.post('/api/workflows/notifications/{notification_id}/read')
def mark_notification_read(notification_id:str,u:User=Depends(principal),s:Session=Depends(db)):
    n=s.scalar(select(WorkflowNotification).where(WorkflowNotification.id==notification_id,WorkflowNotification.tenant_id==u.tenant_id,WorkflowNotification.recipient_id==u.id))
    if not n:raise HTTPException(404,'Notification not found')
    if not n.read_at:n.read_at=utc();s.commit()
    return {'id':n.id,'read_at':n.read_at}

@app.post('/api/workflows/escalations/run')
def run_escalations(u:User=Depends(permit('tenant_admin')),s:Session=Depends(db)):
    """Tenant administrator triggers idempotent overdue notifications; schedule via an authenticated job."""
    today=utc().date()
    pending=s.scalars(select(WorkflowRun).where(WorkflowRun.tenant_id==u.tenant_id,WorkflowRun.state=='pending').limit(1000)).all()
    created=0
    for run in pending:
        due=due_step(run)
        if due is None or due>=today:continue
        key=f'{run.id}:overdue:{run.step_index}:{due.isoformat()}'
        exists=s.scalar(select(WorkflowNotification.id).where(WorkflowNotification.tenant_id==u.tenant_id,WorkflowNotification.event_key==key))
        if exists:continue
        steps=json.loads(run.steps_snapshot)
        notify(s,run,steps[run.step_index]['approver_user_id'],key,f'Overdue approval since {due.isoformat()}')
        created+=1
    if created:log(s,u,'workflow.escalations',u.tenant_id,{'created':created})
    s.commit()
    return {'created':created,'checked':len(pending)}
