"""Tenant-scoped risk stakeholders and opt-in email notifications."""
import re, smtplib
from email.message import EmailMessage
from datetime import datetime, timezone
from fastapi import Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, UniqueConstraint, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from .notification_delivery import send_smtp
from .main import Base, app, uid, utc, db, User, Risk, principal, permit, get_risk, log

ROLES={'owner','watcher','approver','auditor','reviewer'}
EMAIL_RE=re.compile(r'^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$')

class RiskContact(Base):
    __tablename__='risk_contacts'
    id=Column(String(36),primary_key=True,default=uid)
    tenant_id=Column(String(36),ForeignKey('tenants.id'),nullable=False,index=True)
    risk_id=Column(String(36),ForeignKey('risks.id'),nullable=False,index=True)
    email=Column(String(320),nullable=False)
    role=Column(String(30),nullable=False)
    notify=Column(Integer,nullable=False,default=0)
    created_at=Column(DateTime(timezone=True),nullable=False,default=utc)
    __table_args__=(UniqueConstraint('tenant_id','risk_id','email','role'),)

class ContactInput(BaseModel):
    email:str=Field(min_length=5,max_length=320)
    role:str=Field(pattern='^(owner|watcher|approver|auditor|reviewer)$')
    notify:bool=False

class NotificationInput(BaseModel):
    message:str=Field(min_length=1,max_length=2000)

def normalize_email(value):
    value=value.strip().lower()
    if not EMAIL_RE.fullmatch(value):raise HTTPException(422,'Valid email address required')
    return value

def as_dict(c):
    return {'id':c.id,'email':c.email,'role':c.role,'notify':bool(c.notify),'created_at':c.created_at}

@app.get('/api/risks/{rid}/contacts')
def list_contacts(rid:str,u:User=Depends(principal),s:Session=Depends(db)):
    get_risk(s,rid,u.tenant_id)
    return [as_dict(c) for c in s.scalars(select(RiskContact).where(RiskContact.tenant_id==u.tenant_id,RiskContact.risk_id==rid).order_by(RiskContact.role,RiskContact.email))]

@app.post('/api/risks/{rid}/contacts',status_code=201)
def add_contact(rid:str,body:ContactInput,u:User=Depends(permit('tenant_admin','risk_manager','risk_editor')),s:Session=Depends(db)):
    get_risk(s,rid,u.tenant_id)
    email=normalize_email(body.email)
    c=RiskContact(tenant_id=u.tenant_id,risk_id=rid,email=email,role=body.role,notify=int(body.notify))
    try:
        s.add(c)
        s.flush()
        log(s,u,'risk.contact.add',rid,{'contact_id':c.id,'email':email,'role':body.role,'notify':body.notify})
        s.commit()
    except IntegrityError as exc:
        s.rollback()
        raise HTTPException(409, 'Contact assignment conflicts with existing records') from exc
    return as_dict(c)

@app.put('/api/risks/{rid}/contacts/{cid}')
def update_contact(rid:str,cid:str,body:ContactInput,u:User=Depends(permit('tenant_admin','risk_manager','risk_editor')),s:Session=Depends(db)):
    get_risk(s,rid,u.tenant_id)
    c=s.scalar(select(RiskContact).where(RiskContact.id==cid,RiskContact.tenant_id==u.tenant_id,RiskContact.risk_id==rid))
    if not c:raise HTTPException(404,'Contact not found')
    email=normalize_email(body.email)
    before=as_dict(c)
    c.email=email;c.role=body.role;c.notify=int(body.notify)
    try:
        log(s,u,'risk.contact.update',rid,{'before':before,'after':as_dict(c)})
        s.commit()
    except IntegrityError as exc:
        s.rollback()
        raise HTTPException(409, 'Contact assignment conflicts with existing records') from exc
    return as_dict(c)

@app.delete('/api/risks/{rid}/contacts/{cid}')
def delete_contact(rid:str,cid:str,u:User=Depends(permit('tenant_admin','risk_manager','risk_editor')),s:Session=Depends(db)):
    get_risk(s,rid,u.tenant_id)
    c=s.scalar(select(RiskContact).where(RiskContact.id==cid,RiskContact.tenant_id==u.tenant_id,RiskContact.risk_id==rid))
    if not c:raise HTTPException(404,'Contact not found')
    old=as_dict(c);s.delete(c);log(s,u,'risk.contact.remove',rid,old);s.commit();return {'removed':True}

@app.post('/api/risks/{rid}/notify')
def notify_contacts(rid:str,body:NotificationInput,u:User=Depends(permit('tenant_admin','risk_manager')),s:Session=Depends(db)):
    risk=get_risk(s,rid,u.tenant_id)
    recipients=sorted({c.email for c in s.scalars(select(RiskContact).where(RiskContact.tenant_id==u.tenant_id,RiskContact.risk_id==rid,RiskContact.notify==1))})
    if not recipients:raise HTTPException(409,'No opted-in recipients for this risk')
    from .mail_configuration import require_smtp
    config = require_smtp()
    sender = config.sender
    # Message contains only the explicitly supplied update and minimal risk context.
    msg=EmailMessage();msg['From']=sender;msg['To']=sender
    msg['Subject']='LexiGrid risk update: '+risk.id
    msg.set_content('Risk: '+risk.title+'\nRisk ID: '+risk.id+'\nStatus: '+risk.status+'\n\nUpdate from '+u.email+':\n'+body.message+'\n\nSign in to LexiGrid for full details.\n')
    # Each recipient is an envelope recipient; do not expose their addresses to others.
    # Send before committing an audit result; SMTP failures never claim success.
    try:
        refused = send_smtp(config, recipients, msg)
        accepted=[e for e in recipients if e not in refused]
        log(s,u,'risk.notify',rid,{'recipient_count':len(recipients),'accepted_count':len(accepted),'refused_count':len(refused),'message_length':len(body.message)})
        s.commit()
        return {'accepted_count':len(accepted),'refused_count':len(refused),'status':'accepted_by_smtp_not_delivery_confirmed'}
    except (smtplib.SMTPException,OSError,TimeoutError) as exc:
        log(s,u,'risk.notify.failure',rid,{'recipient_count':len(recipients),'error_type':type(exc).__name__});s.commit()
        raise HTTPException(502,'SMTP delivery request failed; see server logs and verify SMTP configuration')
