"""Durable tenant-scoped risk notification outbox, reminders and explicit receipts."""
import uuid
import os, json, smtplib, threading, time, hashlib, secrets, hmac
from datetime import datetime, timezone, timedelta
from email.message import EmailMessage
from fastapi import Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Index, Text, select, func, update, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session
from .main import Base, app, uid, utc, db, User, Tenant, Risk, principal, permit, get_risk, SessionLocal, log
from .risk_contacts import RiskContact
from .notification_delivery import send_smtp

class RiskMail(Base):
    __tablename__='risk_mail'
    id=Column(String(36),primary_key=True,default=uid)
    tenant_id=Column(String(36),ForeignKey('tenants.id'),nullable=False,index=True)
    risk_id=Column(String(36),ForeignKey('risks.id'),nullable=False,index=True)
    email=Column(String(320),nullable=False)
    kind=Column(String(32),nullable=False)
    subject=Column(String(255),nullable=False)
    content=Column(Text,nullable=False)
    status=Column(String(30),nullable=False,default='queued')
    attempts=Column(Integer,nullable=False,default=0)
    due_at=Column(DateTime(timezone=True),nullable=False,default=utc)
    created_at=Column(DateTime(timezone=True),nullable=False,default=utc)
    sent_at=Column(DateTime(timezone=True))
    delivered_at=Column(DateTime(timezone=True))
    read_at=Column(DateTime(timezone=True))
    receipt_hash=Column(String(64),nullable=False)
    provider_message_id=Column(String(255))
    last_error=Column(String(100))

class RiskReminder(Base):
    __tablename__='risk_reminders'
    __table_args__ = (
        Index('uq_risk_reminders_tenant_risk', 'tenant_id', 'risk_id', unique=True),
    )
    id=Column(String(36),primary_key=True,default=uid)
    tenant_id=Column(String(36),ForeignKey('tenants.id'),nullable=False,index=True)
    risk_id=Column(String(36),ForeignKey('risks.id'),nullable=False,index=True)
    enabled=Column(Integer,nullable=False,default=1)
    interval_days=Column(Integer,nullable=False)
    next_due=Column(DateTime(timezone=True),nullable=False)
    created_at=Column(DateTime(timezone=True),nullable=False,default=utc)

class ReminderInput(BaseModel):
    interval_days:int=Field(ge=1,le=365)
    enabled:bool=True

class NotificationSettings(BaseModel):
    auto_email:bool=True

class RiskMailSettings(Base):
    __tablename__='risk_mail_settings'
    tenant_id=Column(String(36),ForeignKey('tenants.id'),primary_key=True)
    auto_email=Column(Integer,nullable=False,default=1)

def queue_risk_change(s, risk, actor_email, event, before=None):
    """Call inside risk write transaction; never send email before commit."""
    setting=s.get(RiskMailSettings,risk.tenant_id)
    if setting and not setting.auto_email:return 0
    contacts=s.scalars(select(RiskContact).where(RiskContact.tenant_id==risk.tenant_id,RiskContact.risk_id==risk.id,RiskContact.notify==1)).all()
    recipients=sorted(set(c.email for c in contacts))
    summary=f'Risk: {risk.title}\nRisk ID: {risk.id}\nEvent: {event}\nStatus: {risk.status}\nScore: {risk.likelihood*risk.impact}\nChanged by: {actor_email}\n'
    if before:
        changes=[]
        for key in ('title','description','category','owner','likelihood','impact','status'):
            old=before.get(key);new=getattr(risk,key,None)
            if old!=new:changes.append(key)
        summary+='Changed fields: '+', '.join(changes)+'\n'
    summary+='\nSign in to LexiGrid to review the authoritative risk record.\n'
    for email in recipients:
        token=secrets.token_urlsafe(32)
        mail=RiskMail(tenant_id=risk.tenant_id,risk_id=risk.id,email=email,kind=event,subject=f'LexiGrid risk {event}: {risk.id}',content=summary,receipt_hash=hashlib.sha256(token.encode()).hexdigest())
        # No token stored in plaintext; explicit read acknowledgments are issued separately.
        s.add(mail)
    return len(recipients)

def _set_mail_tenant(session, tenant_id):
    if session.bind.dialect.name == 'postgresql':
        session.execute(text("SELECT set_config('app.tenant_id', :tenant, true)"),
                        {'tenant': tenant_id})


MAX_MAIL_ATTEMPTS = 5


def _claim_mail(tenant_id):
    """Atomic lease claim, safe for multiple PostgreSQL and SQLite processes.

    Expired leases can cause a duplicate if SMTP succeeded before a crash;
    exactly-once delivery is not guaranteed by SMTP.
    """
    now=utc()
    with SessionLocal.begin() as s:
        _set_mail_tenant(s, tenant_id)
        due = (RiskMail.tenant_id == tenant_id) & (RiskMail.due_at <= now)
        s.execute(update(RiskMail).where(
            due, RiskMail.status == 'sending', RiskMail.attempts >= MAX_MAIL_ATTEMPTS
        ).values(status='failed', last_error='DeliveryLeaseExpired'))
        automatic = RiskMail.status.in_(['queued', 'retry', 'sending']) & (
            RiskMail.attempts < MAX_MAIL_ATTEMPTS)
        eligible = due & (automatic | (RiskMail.status == 'retry_requested'))
        candidates = select(RiskMail.id).where(eligible).order_by(
            RiskMail.created_at, RiskMail.id
        ).limit(1)
        if s.bind.dialect.name == 'postgresql':
            candidates = candidates.with_for_update(skip_locked=True)
        return s.execute(update(RiskMail).where(
            RiskMail.id == candidates.scalar_subquery(), eligible
        ).values(
            status='sending', attempts=RiskMail.attempts + 1,
            due_at=now + timedelta(minutes=10)
        ).returning(RiskMail.id, RiskMail.attempts)).one_or_none()


def _finish_mail(tenant_id, mail_id, attempt, **values):
    with SessionLocal.begin() as s:
        _set_mail_tenant(s, tenant_id)
        s.execute(update(RiskMail).where(
            RiskMail.tenant_id == tenant_id, RiskMail.id == mail_id,
            RiskMail.status == 'sending', RiskMail.attempts == attempt
        ).values(**values))


def _claim_reminder(tenant_id):
    now=utc()
    with SessionLocal.begin() as s:
        _set_mail_tenant(s, tenant_id)
        query=select(RiskReminder).where(RiskReminder.tenant_id==tenant_id,RiskReminder.enabled==1,RiskReminder.next_due<=now).order_by(RiskReminder.next_due)
        if s.bind.dialect.name=='postgresql':
            reminder=s.scalar(query.with_for_update(skip_locked=True).limit(1))
            if not reminder:return False
            reminder.next_due=now+timedelta(days=reminder.interval_days)
        else:
            candidate=s.scalar(query.limit(1))
            if not candidate:return False
            changed=s.execute(update(RiskReminder).where(RiskReminder.id==candidate.id,RiskReminder.next_due==candidate.next_due).values(next_due=now+timedelta(days=candidate.interval_days)))
            if changed.rowcount!=1:return False
            reminder=candidate
        risk=s.scalar(select(Risk).where(Risk.id==reminder.risk_id,Risk.tenant_id==reminder.tenant_id))
        if risk and risk.status!='closed':queue_risk_change(s,risk,'scheduled reminder','reminder')
    return True

def dispatch_due(limit=30):
    with SessionLocal() as s:
        tenant_ids = s.scalars(select(Tenant.id).order_by(Tenant.id)).all()
    for tenant_id in tenant_ids:
        _dispatch_tenant(tenant_id, limit)


def _dispatch_tenant(tenant_id, limit):
    for _ in range(100):
        if not _claim_reminder(tenant_id):break
    for _ in range(limit):
        claim = _claim_mail(tenant_id)
        if claim is None: break
        mail_id, attempt = claim
        try:
            from .mail_configuration import require_smtp
            config=require_smtp()
            with SessionLocal() as s:
                _set_mail_tenant(s, tenant_id)
                row=s.scalar(select(RiskMail).where(RiskMail.id==mail_id, RiskMail.tenant_id==tenant_id,
                                                     RiskMail.status=='sending', RiskMail.attempts==attempt))
                if row is None: continue
                msg=EmailMessage();msg['From']=config.sender;msg['To']=row.email;msg['Subject']=row.subject
                msg['Message-ID']=f'<{row.id}@lexigrid.local>'
                msg['X-LexiGrid-Tenant-ID'] = tenant_id
                msg.set_content(row.content+'\nRead receipt: sign in to LexiGrid and select Acknowledge Read.\n')
                email=row.email
            refused = send_smtp(config, [email], msg)
            if refused:
                raise smtplib.SMTPRecipientsRefused(refused)
        except Exception as exc:
            _finish_mail(tenant_id, mail_id, attempt,
                         last_error=type(exc).__name__,
                         status='failed' if attempt >= MAX_MAIL_ATTEMPTS else 'retry',
                         due_at=utc() + timedelta(minutes=min(60, 2**attempt)))
            continue
        _finish_mail(tenant_id, mail_id, attempt, status='smtp_accepted',
                     sent_at=utc(), provider_message_id=msg['Message-ID'],
                     last_error=None)


def worker(stop):
    while not stop.wait(60):
        try:dispatch_due()
        except Exception:
            import logging;logging.getLogger(__name__).exception('Risk mail worker iteration failed')

@app.get('/api/risks/{rid}/mail')
def mail_history(rid:str,u:User=Depends(principal),s:Session=Depends(db)):
    get_risk(s,rid,u.tenant_id)
    rows=s.scalars(select(RiskMail).where(RiskMail.tenant_id==u.tenant_id,RiskMail.risk_id==rid).order_by(RiskMail.created_at.desc()).limit(200)).all()
    return [{'id':m.id,'email':m.email,'kind':m.kind,'status':m.status,'attempts':m.attempts,'created_at':m.created_at,'sent_at':m.sent_at,'delivered_at':m.delivered_at,'read_at':m.read_at,'last_error':m.last_error} for m in rows]

class RetryMail(BaseModel):
    expected_attempts: int = Field(ge=0)
    reason: str = Field(min_length=10, max_length=1000)


@app.post('/api/risks/{rid}/mail/{mid}/retry')
def retry_failed_mail(rid: str, mid: str, body: RetryMail,
                      u: User = Depends(permit('tenant_admin', 'risk_manager')),
                      s: Session = Depends(db)):
    get_risk(s, rid, u.tenant_id)
    row = s.scalar(select(RiskMail).where(
        RiskMail.id == mid, RiskMail.risk_id == rid, RiskMail.tenant_id == u.tenant_id))
    if row is None:
        raise HTTPException(404, 'Notification not found')
    reason = body.reason.strip()
    if len(reason) < 10:
        raise HTTPException(422, 'Retry reason must contain at least 10 characters after trimming')
    opted_in = s.scalar(select(RiskContact.id).where(
        RiskContact.tenant_id == u.tenant_id, RiskContact.risk_id == rid,
        RiskContact.email == row.email, RiskContact.notify == 1))
    if opted_in is None:
        raise HTTPException(409, 'Recipient is no longer opted in to notifications for this risk')
    changed = s.scalar(update(RiskMail).where(
        RiskMail.id == mid, RiskMail.risk_id == rid, RiskMail.tenant_id == u.tenant_id,
        RiskMail.status == 'failed', RiskMail.attempts == body.expected_attempts,
    ).values(status='retry_requested', due_at=utc()).returning(RiskMail.id))
    if changed is None:
        s.rollback()
        raise HTTPException(409, 'Notification changed or is not failed; refresh before retrying')
    log(s, u, 'risk.mail.retry_requested', rid, {
        'mail_id': mid, 'previous_attempts': body.expected_attempts,
        'reason': reason, 'additional_attempts': 1,
    })
    s.commit()
    return {'id': mid, 'status': 'retry_requested', 'additional_attempts': 1}


@app.post('/api/risks/{rid}/mail/{mid}/read')
def acknowledge_read(rid:str,mid:str,u:User=Depends(principal),s:Session=Depends(db)):
    get_risk(s,rid,u.tenant_id)
    recipient = (RiskMail.id == mid, RiskMail.risk_id == rid,
                 RiskMail.tenant_id == u.tenant_id, RiskMail.email == u.email.lower())
    read_at = s.scalar(update(RiskMail).where(
        *recipient, RiskMail.read_at.is_(None)
    ).values(read_at=utc()).returning(RiskMail.read_at))
    if read_at is not None:
        log(s,u,'risk.mail.read',rid,{'mail_id':mid})
        s.commit()
    else:
        read_at = s.scalar(select(RiskMail.read_at).where(*recipient))
        if read_at is None:
            raise HTTPException(404,'Notification not found for your account')
    return {'read_at':read_at,'receipt_type':'explicit_authenticated_acknowledgement'}

@app.get('/api/risks/{rid}/reminders')
def get_reminders(rid:str,u:User=Depends(principal),s:Session=Depends(db)):
    get_risk(s,rid,u.tenant_id)
    return [{'id':x.id,'interval_days':x.interval_days,'enabled':bool(x.enabled),'next_due':x.next_due} for x in s.scalars(select(RiskReminder).where(RiskReminder.tenant_id==u.tenant_id,RiskReminder.risk_id==rid))]

@app.post('/api/risks/{rid}/reminders')
def set_reminder(rid:str,body:ReminderInput,u:User=Depends(permit('tenant_admin','risk_manager')),s:Session=Depends(db)):
    get_risk(s,rid,u.tenant_id)
    next_due = utc() + timedelta(days=body.interval_days)
    values = {'interval_days': body.interval_days, 'enabled': int(body.enabled),
              'next_due': next_due}
    insert = pg_insert if s.bind.dialect.name == 'postgresql' else sqlite_insert
    statement = insert(RiskReminder).values(tenant_id=u.tenant_id, risk_id=rid, **values)
    s.execute(statement.on_conflict_do_update(
        index_elements=[RiskReminder.tenant_id, RiskReminder.risk_id],
        set_=values,
    ))
    log(s,u,'risk.reminder.configure',rid,body.model_dump())
    s.commit()
    return {**body.model_dump(), 'next_due': next_due}

@app.get('/api/notifications/settings')
def get_settings(u:User=Depends(principal),s:Session=Depends(db)):
    setting=s.get(RiskMailSettings,u.tenant_id)
    return {'auto_email':bool(setting.auto_email) if setting else True}

@app.put('/api/notifications/settings')
def put_settings(body:NotificationSettings,u:User=Depends(permit('tenant_admin')),s:Session=Depends(db)):
    auto_email = int(body.auto_email)
    insert = pg_insert if s.bind.dialect.name == 'postgresql' else sqlite_insert
    statement = insert(RiskMailSettings).values(tenant_id=u.tenant_id, auto_email=auto_email)
    s.execute(statement.on_conflict_do_update(
        index_elements=[RiskMailSettings.tenant_id],
        set_={'auto_email': auto_email},
    ))
    log(s,u,'risk.mail.settings',u.tenant_id,body.model_dump())
    s.commit()
    return body.model_dump()

@app.post('/api/notifications/provider-events')
async def provider_delivery_event(request:Request):
    """Optional provider adapter: HMAC-SHA256 over timestamp + '.' + raw JSON body.

    The signed JSON must include tenant_id, notification_id and event.
    """
    secret=os.getenv('LEXIGRID_MAIL_WEBHOOK_SECRET','')
    if len(secret)<32:raise HTTPException(503,'Provider webhook is not configured')
    stamp=request.headers.get('x-lexigrid-timestamp','')
    signature=request.headers.get('x-lexigrid-signature','')
    try:
        if abs(time.time()-int(stamp))>300:raise ValueError('expired')
    except ValueError:raise HTTPException(401,'Invalid event timestamp')
    raw = bytearray()
    async for chunk in request.stream():
        if len(raw) + len(chunk) > 8192:
            raise HTTPException(413, 'Event too large')
        raw.extend(chunk)
    expected=hmac.new(secret.encode(),stamp.encode()+b'.'+raw,hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected.encode(),signature.encode()):
        raise HTTPException(401,'Invalid signature')
    try:
        payload=json.loads(raw)
        tenant_id=str(uuid.UUID(payload['tenant_id']))
        mail_id=str(uuid.UUID(payload['notification_id']))
        event=payload['event']
        if event not in ('delivered','bounced'):raise ValueError('unsupported event')
    except (ValueError,TypeError,KeyError,AttributeError):raise HTTPException(422,'Invalid delivery event')
    with SessionLocal.begin() as s:
        _set_mail_tenant(s, tenant_id)
        notification = (RiskMail.id == mail_id, RiskMail.tenant_id == tenant_id)
        if event == 'delivered':
            states = ('smtp_accepted', 'delivered')
            values = {'status': 'delivered', 'delivered_at': func.coalesce(RiskMail.delivered_at, utc())}
        else:
            states = ('smtp_accepted', 'delivered', 'bounced')
            values = {'status': 'bounced', 'last_error': 'provider_bounced'}
        processed = s.scalar(update(RiskMail).where(
            *notification, RiskMail.status.in_(states),
        ).values(**values).returning(RiskMail.id))
        if processed is None:
            status = s.scalar(select(RiskMail.status).where(*notification))
            if status is None:
                raise HTTPException(404, 'Notification not found')
            if status in ('queued', 'sending', 'retry', 'retry_requested'):
                raise HTTPException(409, 'SMTP acceptance not recorded; retry later')
            raise HTTPException(409, 'Delivery event conflicts with current status')
    return {'processed':True}

@app.get('/api/admin/mail/configuration')
def mail_configuration_status(u:User=Depends(permit('tenant_admin','platform_admin'))):
    from .mail_configuration import public_status
    return public_status()

class MailConfigEdit(BaseModel):
    revision:int=Field(ge=0)
    host:str=Field(max_length=253)
    port:int=Field(ge=1,le=65535)
    security:str
    sender:str=Field(max_length=320)
    username:str=Field(default='',max_length=320)
    password:str|None=None
    clear_password:bool=False

@app.put('/api/admin/mail/configuration')
def edit_mail_configuration(body:MailConfigEdit,u:User=Depends(permit('platform_admin')),s:Session=Depends(db)):
    from .mail_configuration import save_runtime_settings
    if body.security not in ('ssl','starttls'):raise HTTPException(422,'Invalid SMTP security mode')
    if body.password is not None and body.clear_password:raise HTTPException(422,'Conflicting password instructions')
    values={'LEXIGRID_SMTP_HOST':body.host,'LEXIGRID_SMTP_PORT':str(body.port),
            'LEXIGRID_SMTP_SECURITY':body.security,'LEXIGRID_SMTP_FROM':body.sender,
            'LEXIGRID_SMTP_USERNAME':body.username}
    if body.password is not None:values['LEXIGRID_SMTP_PASSWORD']=body.password
    if body.clear_password:values['LEXIGRID_SMTP_PASSWORD']=''
    try:
        revision = save_runtime_settings(s, values, body.revision)
    except ValueError as exc:
        s.rollback()
        raise HTTPException(409, str(exc)) from exc
    log(s,u,'mail.config.update','global',{'revision':revision,'fields':list(values),'secret_changed':body.password is not None or body.clear_password});s.commit()
    return {'saved':True,'revision':revision,'secrets_returned':False}

@app.post('/api/admin/mail/test-connection')
def mail_test_connection(u:User=Depends(permit('tenant_admin','platform_admin')),s:Session=Depends(db)):
    from .mail_configuration import probe_smtp
    try:
        outcome=probe_smtp()
        log(s,u,'mail.config.test',u.tenant_id,{'result':'success','message_sent':False});s.commit()
        return outcome
    except Exception as exc:
        log(s,u,'mail.config.test',u.tenant_id,{'result':'failed','error_type':type(exc).__name__});s.commit()
        # No raw exception text: SMTP server replies can contain sensitive information.
        raise HTTPException(502,'SMTP connectivity/authentication test failed; inspect restricted server logs')
