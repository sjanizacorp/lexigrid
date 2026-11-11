"""LexiGrid enterprise foundation. Author: Shahryar Jahangir, Aniza Inc."""
import os, uuid, csv, io, hashlib, json, hmac, time, threading
from collections import deque
from pathlib import Path
from datetime import datetime, timezone, timedelta
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, Header, Response, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import text as sql_text, create_engine, Column, String, Integer, DateTime, ForeignKey, Text, UniqueConstraint, select, func, event
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from sqlalchemy.exc import IntegrityError
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
import jwt

APP_VERSION = (Path(__file__).resolve().parent.parent / 'VERSION').read_text().strip()

from .database_identity import validate_database_identity
DATABASE_URL=validate_database_identity(os.getenv('DATABASE_URL','sqlite:////tmp/lexigrid-stage2.db'))
JWT_SECRET=os.getenv('JWT_SECRET','')
BOOTSTRAP_PASSWORD=os.getenv('BOOTSTRAP_PASSWORD','')
BOOTSTRAP_EMAIL=os.getenv('BOOTSTRAP_EMAIL','admin@local.invalid')
if not JWT_SECRET or len(JWT_SECRET)<48: raise RuntimeError('JWT_SECRET must be at least 48 characters')
engine=create_engine(DATABASE_URL,pool_pre_ping=True,connect_args={'check_same_thread':False} if DATABASE_URL.startswith('sqlite:') else {})
if DATABASE_URL.startswith('sqlite:'):
    @event.listens_for(engine,'connect')
    def sqlite_fk(conn,record): conn.execute('PRAGMA foreign_keys=ON')
SessionLocal=sessionmaker(bind=engine,expire_on_commit=False)
Base=declarative_base()
ph=PasswordHasher()
DUMMY_PASSWORD_HASH=ph.hash('lexigrid-invalid-account-verification-sentinel')
def uid(): return str(uuid.uuid4())
def utc(): return datetime.now(timezone.utc)
class Tenant(Base):
    __tablename__='tenants'
    id=Column(String(36),primary_key=True,default=uid); name=Column(String(200),nullable=False,unique=True)
class User(Base):
    __tablename__='users'
    id=Column(String(36),primary_key=True,default=uid); tenant_id=Column(String(36),ForeignKey('tenants.id'),nullable=False,index=True)
    email=Column(String(320),nullable=False); password_hash=Column(Text,nullable=False); role=Column(String(30),nullable=False)
    active=Column(Integer,nullable=False,default=1); token_version=Column(Integer,nullable=False,default=1)
    saml_subject=Column(String(512),nullable=True)
    oidc_issuer=Column(String(512),nullable=True); oidc_subject=Column(String(512),nullable=True)
    mfa_secret=Column(Text,nullable=True); mfa_pending=Column(Text,nullable=True)
    mfa_last_counter=Column(Integer,nullable=False,default=-1)
    __table_args__=(UniqueConstraint('tenant_id','email'),)
class Risk(Base):
    __tablename__='risks'
    id=Column(String(36),primary_key=True,default=uid); tenant_id=Column(String(36),ForeignKey('tenants.id'),nullable=False,index=True)
    title=Column(String(200),nullable=False); description=Column(Text,nullable=False); category=Column(String(100),nullable=False)
    owner=Column(String(200),nullable=False); likelihood=Column(Integer,nullable=False); impact=Column(Integer,nullable=False)
    status=Column(String(20),nullable=False); version=Column(Integer,nullable=False,default=1)
    created_at=Column(DateTime(timezone=True),nullable=False,default=utc); updated_at=Column(DateTime(timezone=True),nullable=False,default=utc)
class Audit(Base):
    __tablename__='audit'
    id=Column(String(36),primary_key=True,default=uid); tenant_id=Column(String(36),ForeignKey('tenants.id'),nullable=False,index=True)
    at=Column(DateTime(timezone=True),nullable=False,default=utc); actor_id=Column(String(36),nullable=False)
    action=Column(String(80),nullable=False); object_id=Column(String(36),nullable=False); details=Column(Text,nullable=False)
    integrity_mac=Column(String(64),nullable=True)

from .rate_limit import install_model, enforce_login_limit
from .logging_config import emit as emit_event, configure as configure_logging
LoginThrottle = install_model(Base)

MFA_ENROLLMENT_AUDIENCE = 'lexigrid:mfa-enrollment'
MFA_ENROLLMENT_PATHS = {'/api/auth/mfa/enroll', '/api/auth/mfa/confirm', '/api/auth/mfa/cancel'}


def _decode_session(token, *, allow_mfa_enrollment=False):
    required = ['exp', 'iat', 'sub', 'tenant', 'ver']
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=['HS256'],
                          options={'require': required})
    except jwt.InvalidAudienceError:
        if not allow_mfa_enrollment:
            raise
        return jwt.decode(token, JWT_SECRET, algorithms=['HS256'],
                          audience=MFA_ENROLLMENT_AUDIENCE,
                          options={'require': [*required, 'aud'], 'strict_aud': True})


def db(request: Request):
    """Set PostgreSQL RLS context within the same transaction as application queries.

    The tenant claim is cryptographically verified before it is used. Login sets
    context separately because it has no bearer token yet.
    """
    with SessionLocal() as s:
        from .logging_config import REQUEST_CONTEXT
        s.info['request_context']=dict(REQUEST_CONTEXT.get())
        if s.bind.dialect.name == 'postgresql':
            bearer = request.headers.get('authorization', '')
            if bearer.startswith('Bearer '):
                try:
                    route = getattr(request.scope.get('route'), 'path', None)
                    claims = _decode_session(
                        bearer[7:], allow_mfa_enrollment=route in MFA_ENROLLMENT_PATHS)
                    tenant = str(uuid.UUID(claims['tenant']))
                except (jwt.PyJWTError, ValueError, KeyError, TypeError):
                    raise HTTPException(401, 'Invalid session')
                s.execute(sql_text("SELECT set_config('app.tenant_id', :tenant, true)"), {'tenant':tenant})
        yield s
@asynccontextmanager
async def lifespan(app):
    configure_logging()
    from .mfa import local_required
    local_required()  # Validate the explicit local policy before serving sign-ins.
    from .kms import provider
    provider()  # Validate write policy before bootstrap or database operations.
    emit_event('system', 'application.start', outcome='success', version=APP_VERSION)
    # dev bootstrap. Production requires externally managed migrations.
    if os.getenv('LEXIGRID_DEV_BOOTSTRAP')=='1':
        if not DATABASE_URL.startswith('sqlite:'):
            raise RuntimeError('Development bootstrap is restricted to SQLite; run alembic upgrade head for PostgreSQL')
        Base.metadata.create_all(engine)
        if BOOTSTRAP_PASSWORD and len(BOOTSTRAP_PASSWORD)>=16:
            with SessionLocal.begin() as s:
                if not s.scalar(select(User.id).limit(1)):
                    t=Tenant(name='Default organization'); s.add(t); s.flush()
                    s.add(User(tenant_id=t.id,email=BOOTSTRAP_EMAIL.lower(),password_hash=ph.hash(BOOTSTRAP_PASSWORD),role='platform_admin'))
    if os.getenv('LEXIGRID_REQUIRE_DB_SECURITY') == '1':
        from .security_checks import assert_postgres_runtime_security
        assert_postgres_runtime_security(engine)
    from .mail_configuration import load_mail_config
    from .logging_config import emit as _mail_emit
    _cfg, _mail_issues=load_mail_config()
    if _mail_issues:
        if _cfg.worker_enabled or os.getenv('LEXIGRID_MAIL_STRICT_STARTUP','0')=='1':
            raise RuntimeError('Mail configuration invalid: '+'; '.join(_mail_issues))
        _mail_emit('system','mail.configuration.warning',outcome='warning',errors=_mail_issues)
    mail_stop=threading.Event()
    mail_thread=None
    acceptance_thread=None
    if os.getenv('LEXIGRID_ACCEPTANCE_WORKER','1')=='1':
        from .risk_acceptance import worker as acceptance_worker
        acceptance_thread=threading.Thread(target=acceptance_worker,args=(mail_stop,),daemon=True,name='risk-acceptance-worker')
        acceptance_thread.start()
    if _cfg.worker_enabled:
        from .risk_mail_automation import worker
        mail_thread=threading.Thread(target=worker,args=(mail_stop,),daemon=True,name='risk-mail-worker')
        mail_thread.start()
    yield
    mail_stop.set()
    if mail_thread:mail_thread.join(timeout=5)
    if acceptance_thread:acceptance_thread.join(timeout=5)
    emit_event('system', 'application.stop', outcome='success')
app=FastAPI(title='LexiGrid IRM',version=APP_VERSION,lifespan=lifespan)
# Per-process limiter is a defense-in-depth control, not a distributed rate limiter.
_login_attempts = {}
_login_lock = threading.Lock()
LOGIN_WINDOW_SECONDS = 300
LOGIN_MAX_ATTEMPTS = 8

def check_login_limit(key):
    now = time.monotonic()
    with _login_lock:
        attempts = _login_attempts.get(key)
        if attempts is None:
            attempts = deque()
            _login_attempts[key] = attempts
        while attempts and attempts[0] <= now - LOGIN_WINDOW_SECONDS:
            attempts.popleft()
        if len(attempts) >= LOGIN_MAX_ATTEMPTS:
            raise HTTPException(429, 'Too many authentication attempts', headers={'Retry-After': '300'})
        attempts.append(now)

from fastapi.exceptions import RequestValidationError
from fastapi.exception_handlers import http_exception_handler
from starlette.exceptions import HTTPException as StarletteHTTPException


@app.exception_handler(RequestValidationError)
async def safe_validation_error(request:Request,exc:RequestValidationError):
    from fastapi.responses import JSONResponse
    from fastapi.encoders import jsonable_encoder
    request.state.error_type='RequestValidationError'
    request.state.validation_error_count=len(exc.errors())
    # Input and ctx may contain submitted passwords or entire document batches.
    errors=[{key:item[key] for key in ('loc','msg','type') if key in item} for item in exc.errors()]
    return JSONResponse({'detail':jsonable_encoder(errors)},status_code=422)


@app.exception_handler(StarletteHTTPException)
async def traced_http_error(request:Request,exc:StarletteHTTPException):
    request.state.error_type=type(exc).__name__
    return await http_exception_handler(request,exc)


@app.middleware('http')
async def security_headers(request: Request, call_next):
    from .logging_config import REQUEST_CONTEXT
    from fastapi.responses import JSONResponse
    import traceback
    request_id=str(uuid.uuid4())
    operation_id=None
    supplied=request.headers.get('X-LexiGrid-Operation-ID','')
    try:
        if supplied:operation_id=str(uuid.UUID(supplied))
    except ValueError:pass
    context={'request_id':request_id,'version':APP_VERSION}
    if operation_id:context['operation_id']=operation_id
    request.state.request_id=request_id
    marker=REQUEST_CONTEXT.set(context)
    started=time.monotonic();error_type=None
    try:
        try:
            response=await call_next(request)
        except Exception as exc:
            error_type=type(exc).__name__
            # Record locations without exception values, SQL parameters, request
            # bodies, credentials or document text. Do not re-raise to an
            # unfiltered web-server traceback logger.
            frames=[{'file':Path(frame.filename).name,'function':frame.name,'line':frame.lineno}
                    for frame in traceback.extract_tb(exc.__traceback__)[-12:]]
            emit_event('system','http.exception',outcome='error',error_type=error_type,frames=frames)
            response=JSONResponse({'detail':'Unexpected server error. Use the request reference when contacting your administrator.',
                                   'request_id':request_id},status_code=500)
        status=response.status_code
        route=getattr(request.scope.get('route'),'path',None) or '/unmatched'
        details={'method':request.method,'path':route,'status':status,
                 'elapsed_ms':round((time.monotonic()-started)*1000)}
        identity=getattr(request.state,'log_identity',{})
        details.update(identity)
        error_type=error_type or getattr(request.state,'error_type',None)
        if error_type:details['error_type']=error_type
        if hasattr(request.state,'validation_error_count'):details['validation_error_count']=request.state.validation_error_count
        if request.url.path.startswith('/api/auth/') and status>=400:
            emit_event('operations','auth.failure',outcome='error',remote_ip=request.client.host if request.client else None,**details)
        if request.url.path!='/health':
            emit_event('system','http.request',outcome='error' if status>=400 else 'success',**details)
        if request.url.path.startswith('/api/') and (request.method in {'POST','PUT','PATCH','DELETE'} or status>=400):
            emit_event('operations','http.transaction',outcome='error' if status>=400 else 'success',phase='response',**details)
        response.headers['X-Request-ID']=request_id
    finally:
        REQUEST_CONTEXT.reset(marker)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers.setdefault('Content-Security-Policy', "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'" if request.url.path != '/ui' else "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Cache-Control'] = 'no-store' if request.url.path.startswith('/api/') else response.headers.get('Cache-Control', 'no-store')
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    return response

class Login(BaseModel):
    email:str; password:str; tenant_id:str; totp_code:str|None=None
class TenantIn(BaseModel): name:str=Field(min_length=2,max_length=200)
class TenantProvision(BaseModel):
    name:str=Field(min_length=2,max_length=200)
    admin_email:str=Field(min_length=3,max_length=320)
    admin_password:str=Field(min_length=16,max_length=200)

class UserIn(BaseModel):
    email:str=Field(min_length=3,max_length=320); password:str=Field(min_length=16,max_length=200)
    role:str=Field(pattern='^(tenant_admin|risk_manager|risk_editor|risk_viewer|auditor)$')
class RiskIn(BaseModel):
    title:str=Field(min_length=1,max_length=200); description:str=Field(min_length=1,max_length=10000)
    category:str=Field(min_length=1,max_length=100); owner:str=Field(min_length=1,max_length=200)
    likelihood:int=Field(ge=1,le=5); impact:int=Field(ge=1,le=5)
    status:str=Field(pattern='^(open|mitigating|accepted|closed)$')
class RiskUpdate(RiskIn): version:int=Field(ge=1)
class RiskClose(BaseModel):
    version:int=Field(ge=1)
    resolution:str=Field(min_length=10,max_length=5000)
class TenantRename(BaseModel):
    name:str=Field(min_length=2,max_length=200)

def _authenticated_user(authorization, s, *, allow_mfa_enrollment=False):
    if not authorization.startswith('Bearer '): raise HTTPException(401,'Authentication required')
    try:
        data = _decode_session(authorization[7:], allow_mfa_enrollment=allow_mfa_enrollment)
        u=s.get(User,data['sub'])
        if not u or not u.active or u.tenant_id!=data['tenant'] or u.token_version!=data['ver']: raise ValueError()
        return u
    except (jwt.PyJWTError,ValueError,KeyError): raise HTTPException(401,'Invalid session')
def principal(authorization: str = Header(default=''), s: Session = Depends(db),request:Request=None):
    user=_authenticated_user(authorization,s)
    identity={'actor_id':user.id,'tenant_id':user.tenant_id}
    s.info['log_identity']=identity
    if request is not None:request.state.log_identity=identity
    return user


def mfa_enrollment_principal(authorization: str = Header(default=''), s: Session = Depends(db)):
    return _authenticated_user(authorization, s, allow_mfa_enrollment=True)


def permit(*roles):
    def check(u:User=Depends(principal)):
        if u.role not in roles and u.role!='platform_admin': raise HTTPException(403,'Forbidden')
        return u
    return check
def log(s,u,action,obj,details,*,operation_details=None):
    payload=json.dumps(details,sort_keys=True,default=str)
    timestamp=utc()
    mac=audit_digest(u.tenant_id,u.id,action,obj,payload,timestamp) if AUDIT_HMAC_KEY else None
    s.add(Audit(tenant_id=u.tenant_id,actor_id=u.id,action=action,object_id=obj,details=payload,at=timestamp,integrity_mac=mac))
    s.info.setdefault('operation_events', []).append(dict(**s.info.get('request_context',{}),outcome='success', tenant_id=u.tenant_id, actor_id=u.id, object_id=obj, details=details if operation_details is None else operation_details, action=action))
@event.listens_for(Session, 'after_commit')
def _committed_operations(session):
    transaction=session.get_nested_transaction() or session.get_transaction()
    if transaction is not None and session.info.get('_logged_commit_transaction') is transaction:return
    session.info['_logged_commit_transaction']=transaction
    from .logging_config import REQUEST_CONTEXT
    operations=session.info.pop('operation_events', [])
    context=session.info.get('request_context') or REQUEST_CONTEXT.get()
    identity=session.info.get('log_identity',{})
    if not identity and operations:identity={k:operations[0][k] for k in ('actor_id','tenant_id')}
    if operations or context:
        emit_event('operations','database.commit',outcome='success',operation_count=len(operations),**identity,**context)
    for operation in operations:
        action=operation.pop('action')
        emit_event('operations',action,**operation)

@event.listens_for(Session, 'after_rollback')
def _discard_operations(session):
    transaction=session.get_nested_transaction() or session.get_transaction()
    if transaction is not None and session.info.get('_logged_rollback_transaction') is transaction:return
    session.info['_logged_rollback_transaction']=transaction
    from .logging_config import REQUEST_CONTEXT
    operations=session.info.pop('operation_events', [])
    context=session.info.get('request_context') or REQUEST_CONTEXT.get()
    identity=session.info.get('log_identity',{})
    if not identity and operations:identity={k:operations[0][k] for k in ('actor_id','tenant_id')}
    if operations or context:
        emit_event('operations','database.rollback',outcome='error',attempted_operation_count=len(operations),**identity,**context)


def risk_dict(r):
    return {k:getattr(r,k) for k in ('id','tenant_id','title','description','category','owner','likelihood','impact','status','version','created_at','updated_at')} | {'score':r.likelihood*r.impact}
# Audit integrity uses an independent HMAC secret. The digest is persisted alongside
# each record; export/anchor digests outside the DB to detect full-history rewriting.
from sqlalchemy import inspect as sa_inspect
AUDIT_HMAC_KEY=os.getenv('AUDIT_HMAC_KEY','')
def audit_digest(tenant_id, actor_id, action, object_id, details, at):
    if len(AUDIT_HMAC_KEY)<48: raise RuntimeError('AUDIT_HMAC_KEY must be at least 48 characters')
    # Stored signatures were generated with UTC timestamps. PostgreSQL may
    # return the same instant in the session timezone; normalize before verifying.
    stamp=at.replace(tzinfo=timezone.utc) if at.tzinfo is None else at.astimezone(timezone.utc)
    payload=json.dumps([tenant_id,actor_id,action,object_id,details,stamp.replace(tzinfo=None).isoformat()],separators=(',',':'),ensure_ascii=False)
    return hmac.new(AUDIT_HMAC_KEY.encode(),payload.encode(),hashlib.sha256).hexdigest()

@app.get('/api/audit/verify-hmac')
def verify_audit_hmac(u:User=Depends(permit('tenant_admin','auditor')),s:Session=Depends(db)):
    if not AUDIT_HMAC_KEY: raise HTTPException(503,'Audit signing not configured')
    rows=s.scalars(select(Audit).where(Audit.tenant_id==u.tenant_id)).all()
    invalid=[r.id for r in rows if not r.integrity_mac or not hmac.compare_digest(r.integrity_mac,audit_digest(r.tenant_id,r.actor_id,r.action,r.object_id,r.details,r.at))]
    return {'verified':len(rows)-len(invalid),'invalid_ids':invalid,'valid':not invalid}

@app.get('/health')
def health(response: Response):
    instance = os.getenv('LEXIGRID_NATIVE_INSTANCE_ID')
    if instance:
        response.headers['X-LexiGrid-Native-Instance'] = instance
    return {'status':'ok','version':APP_VERSION}
@app.post('/api/auth/login')
def login(body:Login,request:Request,s:Session=Depends(db)):
    enforce_login_limit(s, LoginThrottle, (request.client.host if request.client else 'unknown', body.tenant_id, body.email.lower()))
    if s.bind.dialect.name == 'postgresql':
        try: tenant = str(uuid.UUID(body.tenant_id))
        except (ValueError, TypeError): raise HTTPException(422, 'Invalid tenant ID')
        s.execute(sql_text("SELECT set_config('app.tenant_id', :tenant, true)"), {'tenant':tenant})
    u=s.scalar(select(User).where(User.tenant_id==body.tenant_id,User.email==body.email.lower(),User.active==1))
    try:
        if u: ph.verify(u.password_hash,body.password)
        else: ph.verify(DUMMY_PASSWORD_HASH,body.password)
    except (VerifyMismatchError,VerificationError): raise HTTPException(401,'Invalid credentials')
    if not u: raise HTTPException(401,'Invalid credentials')
    from .mfa import unseal, verify, local_required
    if u.mfa_secret:
        counter = verify(unseal(u.mfa_secret,u.id), body.totp_code, last_counter=u.mfa_last_counter)
        if counter is None: raise HTTPException(401,'Invalid credentials or second factor')
        from sqlalchemy import update
        claimed = s.execute(update(User).where(
            User.id == u.id, User.tenant_id == u.tenant_id, User.active == 1,
            User.token_version == u.token_version, User.mfa_secret == u.mfa_secret,
            User.mfa_last_counter < counter,
        ).values(mfa_last_counter=counter))
        if claimed.rowcount != 1:
            s.rollback()
            raise HTTPException(401, 'Invalid credentials or second factor')
    elif local_required():
        now = utc()
        credential = jwt.encode({
            'sub': u.id, 'tenant': u.tenant_id, 'ver': u.token_version,
            'aud': MFA_ENROLLMENT_AUDIENCE, 'iat': now,
            'exp': now + timedelta(minutes=5),
        }, JWT_SECRET, algorithm='HS256')
        log(s, u, 'auth.mfa.enrollment_required', u.id, {})
        s.commit()
        return {'mfa_enrollment_required': True, 'enrollment_token': credential,
                'expires_in': 300, 'tenant_id': u.tenant_id}
    ts=utc(); token=jwt.encode({'sub':u.id,'tenant':u.tenant_id,'ver':u.token_version,'iat':ts,'exp':ts+timedelta(minutes=30)},JWT_SECRET,algorithm='HS256')
    log(s,u,'auth.login',u.id,{});s.commit()
    return {'access_token':token,'token_type':'bearer','expires_in':1800,'tenant_id':u.tenant_id,'role':u.role}
class MFAConfirm(BaseModel):
    code:str=Field(min_length=6,max_length=6)

    @field_validator('code',mode='before')
    @classmethod
    def normalized_code(cls,value):
        from .mfa import normalize_code
        return normalize_code(value)


@app.get('/api/auth/mfa/status')
def mfa_status(u:User=Depends(principal)):
    from .mfa import local_required
    return {'enabled':bool(u.mfa_secret),'setup_pending':bool(u.mfa_pending),
            'required':local_required()}


@app.post('/api/auth/mfa/enroll')
def mfa_enroll(u:User=Depends(mfa_enrollment_principal),s:Session=Depends(db)):
    from .mfa import new_secret,seal,unseal,setup_payload
    from sqlalchemy import update,case
    if u.mfa_secret:raise HTTPException(409,'MFA already enabled')
    candidate=seal(new_secret(),u.id)
    stored=s.execute(update(User).where(
        User.id==u.id,User.tenant_id==u.tenant_id,User.active==1,
        User.token_version==u.token_version,User.mfa_secret.is_(None),
    ).values(mfa_pending=case((User.mfa_pending.is_(None),candidate),else_=User.mfa_pending))
      .returning(User.mfa_pending).execution_options(synchronize_session=False)).scalar_one_or_none()
    if stored is None:raise HTTPException(409,'MFA enrollment changed; sign in again')
    # Repeat opens and concurrent requests return the same pending key.
    payload=setup_payload(unseal(stored,u.id),u.email)
    log(s,u,'auth.mfa.enroll_started' if stored==candidate else 'auth.mfa.enroll_resumed',u.id,{})
    s.commit()
    return payload


@app.post('/api/auth/mfa/cancel')
def mfa_cancel(u:User=Depends(mfa_enrollment_principal),s:Session=Depends(db)):
    from sqlalchemy import update
    changed=s.execute(update(User).where(User.id==u.id,User.tenant_id==u.tenant_id,
        User.active==1,User.token_version==u.token_version,User.mfa_secret.is_(None))
        .values(mfa_pending=None).execution_options(synchronize_session=False))
    if changed.rowcount!=1:raise HTTPException(409,'Account security changed; sign in again')
    log(s,u,'auth.mfa.enroll_cancelled',u.id,{})
    s.commit()
    return {'cancelled':True,'enabled':False}


@app.post('/api/auth/mfa/confirm')
def mfa_confirm(body:MFAConfirm,u:User=Depends(mfa_enrollment_principal),s:Session=Depends(db)):
    from .mfa import unseal,verify
    if not u.mfa_pending or u.mfa_secret:raise HTTPException(409,'No pending MFA enrollment')
    counter=verify(unseal(u.mfa_pending,u.id),body.code)
    if counter is None:
        raise HTTPException(400,'Invalid authenticator code. Enter the current six digits from the matching authenticator entry and check automatic date/time on your phone.')
    from sqlalchemy import update
    next_version=u.token_version+1
    changed=s.execute(update(User).where(
        User.id==u.id,User.tenant_id==u.tenant_id,User.active==1,
        User.token_version==u.token_version,User.mfa_secret.is_(None),User.mfa_pending==u.mfa_pending,
    ).values(mfa_secret=u.mfa_pending,mfa_pending=None,mfa_last_counter=counter,
             token_version=next_version).execution_options(synchronize_session=False))
    if changed.rowcount!=1:raise HTTPException(409,'MFA enrollment changed; sign in again')
    now=utc();access=jwt.encode({'sub':u.id,'tenant':u.tenant_id,'ver':next_version,
        'iat':now,'exp':now+timedelta(minutes=30)},JWT_SECRET,algorithm='HS256')
    log(s,u,'auth.mfa.enabled',u.id,{})
    s.commit()
    # The confirmation has already verified this code. Complete sign-in without
    # asking for the consumed code again; all older sessions remain revoked.
    return {'enabled':True,'sessions_revoked':True,'access_token':access,
            'token_type':'bearer','expires_in':1800,'tenant_id':u.tenant_id,'role':u.role}

@app.post('/api/auth/logout')
def logout(u:User=Depends(principal),s:Session=Depends(db)):
    log(s,u,'auth.logout',u.id,{})
    s.commit()
    return {'logged_out':True}

class PasswordChange(BaseModel):
    current_password:str=Field(min_length=1,max_length=200)
    new_password:str=Field(min_length=16,max_length=200)
    totp_code:str|None=None


@app.post('/api/auth/change-password')
def change_password(body:PasswordChange,u:User=Depends(principal),s:Session=Depends(db)):
    from sqlalchemy import update
    from .mfa import unseal,verify
    try:ph.verify(u.password_hash,body.current_password)
    except (VerifyMismatchError,VerificationError):raise HTTPException(401,'Invalid current credentials')
    if body.current_password==body.new_password:raise HTTPException(422,'Choose a different password')
    counter=None
    if u.mfa_secret:
        counter=verify(unseal(u.mfa_secret,u.id),body.totp_code,last_counter=u.mfa_last_counter)
        if counter is None:raise HTTPException(401,'Invalid current credentials or second factor')
    conditions=[User.id==u.id,User.tenant_id==u.tenant_id,User.active==1,
        User.token_version==u.token_version,User.password_hash==u.password_hash,
        User.mfa_secret==u.mfa_secret if u.mfa_secret else User.mfa_secret.is_(None)]
    if counter is not None:conditions.append(User.mfa_last_counter<counter)
    values={'password_hash':ph.hash(body.new_password),'token_version':User.token_version+1,'mfa_pending':None}
    if counter is not None:values['mfa_last_counter']=counter
    changed=s.execute(update(User).where(*conditions).values(**values))
    if changed.rowcount!=1:
        s.rollback();raise HTTPException(409,'Account security changed; sign in again')
    log(s,u,'auth.password.changed',u.id,{'sessions_revoked':True})
    s.commit()
    return {'changed':True,'sessions_revoked':True}


@app.post('/api/auth/logout-all')
def logout_all(u:User=Depends(principal),s:Session=Depends(db)):
    from sqlalchemy import update
    changed=s.execute(update(User).where(User.id==u.id,User.tenant_id==u.tenant_id,User.active==1).values(token_version=User.token_version+1))
    if changed.rowcount!=1:raise HTTPException(401,'Invalid session')
    log(s,u,'auth.sessions.revoked',u.id,{})
    s.commit()
    return {'revoked':True}

@app.get('/api/me')
def me(u:User=Depends(principal)):
    return {'id':u.id,'tenant_id':u.tenant_id,'email':u.email,'role':u.role}
@app.get('/api/auth/tenants')
def login_tenants(s:Session=Depends(db)):
    # Tenant names are intentionally discoverable for this deployment's login selector.
    # Do not expose IDs for tenant-scoped data access without authentication.
    return [{'id':t.id,'name':t.name} for t in s.scalars(select(Tenant).order_by(Tenant.name)).all()]

@app.get('/api/tenants/current')
def current_tenant(u:User=Depends(principal),s:Session=Depends(db)):
    t=s.get(Tenant,u.tenant_id)
    return {'id':t.id,'name':t.name}

@app.put('/api/tenants/current')
def rename_tenant(body:TenantRename,u:User=Depends(permit('tenant_admin')),s:Session=Depends(db)):
    t=s.get(Tenant,u.tenant_id)
    old=t.name;t.name=body.name.strip()
    try:
        s.flush();log(s,u,'tenant.rename',t.id,{'before':old,'after':t.name});s.commit()
    except IntegrityError:
        s.rollback();raise HTTPException(409,'Tenant name already exists')
    return {'id':t.id,'name':t.name}

@app.post('/api/tenants',status_code=201)
def create_tenant(body:TenantIn,u:User=Depends(permit('platform_admin')),s:Session=Depends(db)):
    t=Tenant(name=body.name);s.add(t)
    try: s.flush();log(s,u,'tenant.create',t.id,{'name':t.name});s.commit()
    except IntegrityError: s.rollback();raise HTTPException(409,'Tenant already exists')
    return {'id':t.id,'name':t.name}
def _set_platform_tenant_context(s: Session, tenant_id: str):
    if s.bind.dialect.name == 'postgresql':
        s.execute(sql_text("SELECT set_config('app.tenant_id', :tenant, true)"),
                  {'tenant': tenant_id})


@app.get('/api/platform/tenants')
def platform_tenants(u:User=Depends(principal),s:Session=Depends(db)):
    if u.role!='platform_admin': raise HTTPException(403,'Platform administrator required')
    tenants=s.scalars(select(Tenant).order_by(Tenant.name)).all()
    result = []
    for tenant in tenants:
        _set_platform_tenant_context(s, tenant.id)
        count = s.scalar(select(func.count()).select_from(User).where(User.tenant_id == tenant.id))
        result.append({'id': tenant.id, 'name': tenant.name, 'user_count': count})
    _set_platform_tenant_context(s, u.tenant_id)
    return result

@app.post('/api/platform/tenants',status_code=201)
def platform_provision_tenant(body:TenantProvision,u:User=Depends(principal),s:Session=Depends(db)):
    if u.role!='platform_admin': raise HTTPException(403,'Platform administrator required')
    name=body.name.strip(); email=body.admin_email.strip().lower()
    if not name or '@' not in email or email.startswith('@') or email.endswith('@'):
        raise HTTPException(422,'Valid organization name and administrator email required')
    t=Tenant(name=name);s.add(t)
    try:
        s.flush()
        admin=User(tenant_id=t.id,email=email,password_hash=ph.hash(body.admin_password),role='tenant_admin')
        _set_platform_tenant_context(s, t.id)
        s.add(admin)
        s.flush()
        _set_platform_tenant_context(s, u.tenant_id)
        log(s,u,'tenant.provision',t.id,{'name':name,'initial_admin_id':admin.id,'initial_admin_email':email})
        s.commit()
    except IntegrityError:
        s.rollback();raise HTTPException(409,'Tenant name or administrator already exists')
    return {'id':t.id,'name':t.name,'initial_admin':{'id':admin.id,'email':email,'role':'tenant_admin'}}

@app.get('/api/users')
def list_tenant_users(u:User=Depends(principal),s:Session=Depends(db)):
    if u.role not in ('tenant_admin','platform_admin'): raise HTTPException(403,'Administrator required')
    rows=s.scalars(select(User).where(User.tenant_id==u.tenant_id).order_by(User.email)).all()
    return [{'id':x.id,'email':x.email,'role':x.role,'active':bool(x.active),'security_revision':x.token_version} for x in rows]

@app.post('/api/users',status_code=201)
def create_user(body:UserIn,u:User=Depends(permit('tenant_admin')),s:Session=Depends(db)):
    v=User(tenant_id=u.tenant_id,email=body.email.lower(),password_hash=ph.hash(body.password),role=body.role);s.add(v)
    try: s.flush();log(s,u,'user.create',v.id,{'role':v.role});s.commit()
    except IntegrityError: s.rollback();raise HTTPException(409,'User already exists')
    return {'id':v.id,'tenant_id':v.tenant_id,'email':v.email,'role':v.role}
class UserAccessChange(BaseModel):
    role:str=Field(pattern='^(tenant_admin|risk_manager|risk_editor|risk_viewer|auditor)$')
    active:bool
    security_revision:int=Field(ge=1)


@app.patch('/api/users/{user_id}')
def update_user_access(user_id:str,body:UserAccessChange,u:User=Depends(permit('tenant_admin')),s:Session=Depends(db)):
    from sqlalchemy import update
    actor_id,tenant_id,actor_version=u.id,u.tenant_id,u.token_version
    # Serialize administrative access changes within the organization. Refresh
    # actor security after the lock so a concurrent revoked administrator cannot act.
    s.execute(select(Tenant.id).where(Tenant.id==tenant_id).with_for_update()).scalar_one()
    actor=s.execute(select(User.active,User.token_version).where(User.id==actor_id,User.tenant_id==tenant_id)).one()
    if not actor.active or actor.token_version!=actor_version:raise HTTPException(401,'Administrator session changed; sign in again')
    target=s.scalar(select(User).where(User.id==user_id,User.tenant_id==tenant_id).execution_options(populate_existing=True))
    if not target:raise HTTPException(404,'User not found')
    if user_id==actor_id:raise HTTPException(403,'Another administrator must change your access')
    if target.role=='platform_admin':raise HTTPException(403,'Platform administrator access requires privileged owner administration')
    if target.token_version!=body.security_revision:raise HTTPException(409,'User access changed; refresh before retrying')
    if target.role=='tenant_admin' and target.active and (body.role!='tenant_admin' or not body.active):
        admins=s.scalar(select(func.count()).select_from(User).where(User.tenant_id==tenant_id,User.active==1,User.role.in_(['tenant_admin','platform_admin'])))
        if admins<=1:raise HTTPException(409,'An active organization administrator must remain')
    before={'role':target.role,'active':bool(target.active)}
    changed=s.execute(update(User).where(User.id==user_id,User.tenant_id==tenant_id,User.token_version==body.security_revision).values(role=body.role,active=int(body.active),token_version=User.token_version+1).execution_options(synchronize_session=False))
    if changed.rowcount!=1:s.rollback();raise HTTPException(409,'User access changed; refresh before retrying')
    log(s,u,'user.access.changed',user_id,{'before':before,'after':{'role':body.role,'active':body.active},'sessions_revoked':True})
    s.commit()
    return {'id':user_id,'role':body.role,'active':body.active,'security_revision':body.security_revision+1}


@app.post('/api/risks',status_code=201)
def create_risk(body:RiskIn,u:User=Depends(permit('tenant_admin','risk_manager','risk_editor')),s:Session=Depends(db)):
    if body.status=='accepted':raise HTTPException(422,'Create the risk as open or mitigating, then request independent acceptance with an expiry')
    if body.status == 'closed':
        raise HTTPException(422, 'Create the risk before using Resolve & Close with a resolution justification')
    r=Risk(tenant_id=u.tenant_id,**body.model_dump());s.add(r);s.flush();log(s,u,'risk.create',r.id,body.model_dump(),operation_details={'version':r.version,'status':r.status});s.commit();return risk_dict(r)
@app.get('/api/risks')
def list_risks(limit:int=100,offset:int=0,u:User=Depends(principal),s:Session=Depends(db)):
    if not 1<=limit<=500 or offset<0: raise HTTPException(422,'Invalid pagination')
    q=select(Risk).where(Risk.tenant_id==u.tenant_id)
    return {'total':s.scalar(select(func.count()).select_from(Risk).where(Risk.tenant_id==u.tenant_id)), 'items':[risk_dict(r) for r in s.scalars(q.order_by(Risk.created_at.desc()).limit(limit).offset(offset))]}
def get_risk(s,rid,tenant):
    r=s.scalar(select(Risk).where(Risk.id==rid,Risk.tenant_id==tenant))
    if not r: raise HTTPException(404,'Risk not found')
    return r
@app.get('/api/risks/{rid}')
def read_risk(rid:str,u:User=Depends(principal),s:Session=Depends(db)): return risk_dict(get_risk(s,rid,u.tenant_id))
@app.put('/api/risks/{rid}')
def update_risk(rid:str,body:RiskUpdate,u:User=Depends(permit('tenant_admin','risk_manager','risk_editor')),s:Session=Depends(db)):
    r=get_risk(s,rid,u.tenant_id)
    from sqlalchemy import update as sql_update
    old=risk_dict(r)
    values=body.model_dump(exclude={'version'})
    if values['status']=='accepted':
        if r.status!='accepted' or any(values[k]!=getattr(r,k) for k in values):
            raise HTTPException(422,'Use independent acceptance review; change an accepted risk to open or mitigating before editing its content')
        if body.version!=r.version:raise HTTPException(409,'Version conflict')
        return risk_dict(r)
    if values['status']=='closed' and r.status!='closed':
        raise HTTPException(422,'Use the Resolve & Close action with a resolution justification')
    result=s.execute(sql_update(Risk).where(Risk.id==rid,Risk.tenant_id==u.tenant_id,Risk.version==body.version).values(**values,version=Risk.version+1,updated_at=utc()))
    if result.rowcount!=1:
        s.rollback()
        raise HTTPException(409,'Version conflict')
    s.expire_all();r=get_risk(s,rid,u.tenant_id)
    log(s,u,'risk.update',rid,{'before':old,'after':risk_dict(r)},operation_details={'before_version':old['version'],'version':r.version,'status':r.status})
    from .risk_mail_automation import queue_risk_change
    queue_risk_change(s,r,u.email,'updated',old)
    s.commit();return risk_dict(r)

@app.post('/api/risks/{rid}/close')
def close_risk(rid:str,body:RiskClose,u:User=Depends(permit('tenant_admin','risk_manager')),s:Session=Depends(db)):
    from sqlalchemy import update as sql_update
    r=get_risk(s,rid,u.tenant_id)
    if r.status=='closed': raise HTTPException(409,'Risk already closed')
    resolution = body.resolution.strip()
    if len(resolution) < 10:
        raise HTTPException(422, 'Resolution must contain at least 10 characters after trimming')
    before=risk_dict(r)
    result=s.execute(sql_update(Risk).where(Risk.id==rid,Risk.tenant_id==u.tenant_id,Risk.version==body.version,Risk.status!='closed').values(status='closed',version=Risk.version+1,updated_at=utc()))
    if result.rowcount!=1:
        s.rollback();raise HTTPException(409,'Risk changed; refresh and retry')
    s.expire_all();r=get_risk(s,rid,u.tenant_id)
    log(s,u,'risk.resolve_close',rid,{'before':before,'after':risk_dict(r),'resolution':resolution},operation_details={'before_version':before['version'],'version':r.version,'status':r.status})
    from .risk_mail_automation import queue_risk_change
    queue_risk_change(s,r,u.email,'closed',before)
    s.commit()
    return risk_dict(r)

@app.get('/api/reports/risks')
def risk_report(status:str|None=None,category:str|None=None,owner:str|None=None,u:User=Depends(principal),s:Session=Depends(db)):
    q=select(Risk).where(Risk.tenant_id==u.tenant_id)
    if status: q=q.where(Risk.status==status)
    if category: q=q.where(Risk.category==category)
    if owner: q=q.where(Risk.owner==owner)
    risks=s.scalars(q.order_by(Risk.created_at.desc(),Risk.id)).all()
    statuses=('open','mitigating','accepted','closed')
    ratings=('low','medium','high','critical')
    def rating(r):
        n=r.likelihood*r.impact
        return 'low' if n<=4 else 'medium' if n<=9 else 'high' if n<=16 else 'critical'
    # Attribution is derived from committed audit events, not the risk owner field.
    # Direct risk approval decisions are stored on their approval records.
    from .approval_records import Approval
    risk_ids=[r.id for r in risks]
    history={rid:[] for rid in risk_ids}
    decisions={rid:[] for rid in risk_ids}
    approvals=[]
    if risk_ids:
        audit_rows=s.scalars(select(Audit).where(Audit.tenant_id==u.tenant_id,Audit.object_id.in_(risk_ids)).order_by(Audit.at,Audit.id)).all()
        approvals=s.scalars(select(Approval).where(Approval.tenant_id==u.tenant_id,Approval.object_type=='risk',Approval.object_id.in_(risk_ids)).order_by(Approval.created_at,Approval.id)).all()
        for ev in audit_rows: history[ev.object_id].append(ev)
        from . import approval_binding
        for a in approvals:
            decisions[a.object_id].append({'binding_status':approval_binding.status(s,a),'state':a.state,'requested_by_id':a.requester_id,'approved_by_id':a.approver_id if a.state=='approved' else None,'decided_by_id':a.approver_id,'requested_at':a.created_at,'decided_at':a.decided_at,'decision_note':a.decision_note,'approval_id':a.id})
    actor_ids={e.actor_id for events in history.values() for e in events}
    actor_ids.update(a.requester_id for a in approvals)
    actor_ids.update(a.approver_id for a in approvals if a.approver_id)
    actors={x.id:x.email for x in s.scalars(select(User).where(User.tenant_id==u.tenant_id,User.id.in_(actor_ids)))} if actor_ids else {}
    def attributed(r):
        events=history[r.id]
        created=next((e for e in events if e.action=='risk.create'),None)
        changes=[e for e in events if e.action in ('risk.update','risk.resolve_close')]
        last=changes[-1] if changes else None
        closed=next((e for e in reversed(events) if e.action=='risk.resolve_close'),None) if r.status=='closed' else None
        approval_list=decisions[r.id]
        approved=[a for a in approval_list if a['state']=='approved' and a['binding_status']=='current']
        last_approved=approved[-1] if approved else None
        return risk_dict(r)|{'created_by':actors.get(created.actor_id,created.actor_id) if created else None,
            'updated_by':actors.get(last.actor_id,last.actor_id) if last else None,
            'closed_by':actors.get(closed.actor_id,closed.actor_id) if closed else None,
            'approved_by':actors.get(last_approved['approved_by_id'],last_approved['approved_by_id']) if last_approved else None,
            'approval_status':(approval_list[-1]['state'] if approval_list[-1]['state']!='approved' or approval_list[-1]['binding_status']=='current' else 'approved_'+approval_list[-1]['binding_status']) if approval_list else 'not_requested',
            'approval_count':len(approval_list),
            'approvals':[{**a,'requested_by':actors.get(a['requested_by_id'],a['requested_by_id']),
                          'decided_by':actors.get(a['decided_by_id'],a['decided_by_id']) if a['decided_by_id'] else None} for a in approval_list],
            'activity_history':[{'at':e.at,'action':e.action,'actor':actors.get(e.actor_id,e.actor_id),'details':json.loads(e.details)} for e in events]}
    return {'total':len(risks),'by_status':{k:sum(r.status==k for r in risks) for k in statuses},'by_rating':{k:sum(rating(r)==k for r in risks) for k in ratings},'by_category':{k:sum(r.category==k for r in risks) for k in sorted({r.category for r in risks})},'items':[attributed(r) for r in risks]}

@app.get('/api/reports/risks.csv')
def risk_report_csv(status:str|None=None,category:str|None=None,owner:str|None=None,u:User=Depends(principal),s:Session=Depends(db)):
    report=risk_report(status,category,owner,u,s)
    out=io.StringIO();w=csv.writer(out)
    columns=['id','title','description','category','owner','likelihood','impact','score','status','version','created_at','updated_at','created_by','updated_by','approved_by','approval_status','approval_count','closed_by']
    w.writerow(columns)
    for r in report['items']:
        w.writerow([("'"+str(r[k]) if isinstance(r[k],str) and r[k].lstrip().startswith(('=','+','-','@','\t','\r')) else r[k]) for k in columns])
    return Response(out.getvalue(),media_type='text/csv',headers={'Content-Disposition':'attachment; filename="lexigrid-risk-report.csv"','Cache-Control':'no-store'})

@app.get('/api/audit')
def audit(limit:int=100,u:User=Depends(permit('tenant_admin','auditor')),s:Session=Depends(db)):
    if not 1<=limit<=1000: raise HTTPException(422,'Invalid limit')
    return [{'id':a.id,'at':a.at,'actor_id':a.actor_id,'action':a.action,'object_id':a.object_id,'details':json.loads(a.details)} for a in s.scalars(select(Audit).where(Audit.tenant_id==u.tenant_id).order_by(Audit.at.desc()).limit(limit))]
@app.get('/api/dashboard/summary')
def dashboard(u:User=Depends(principal),s:Session=Depends(db)):
    risks=s.scalars(select(Risk).where(Risk.tenant_id==u.tenant_id)).all();return {'total':len(risks),'by_status':{k:sum(r.status==k for r in risks) for k in ('open','mitigating','accepted','closed')},'by_rating':{k:sum((('low' if r.likelihood*r.impact<=4 else 'medium' if r.likelihood*r.impact<=9 else 'high' if r.likelihood*r.impact<=16 else 'critical')==k) for r in risks) for k in ('low','medium','high','critical')}}
@app.get('/api/exports/risks.csv')
def export(u:User=Depends(principal),s:Session=Depends(db)):
    out=io.StringIO();w=csv.writer(out);w.writerow(['id','title','category','owner','likelihood','impact','status'])
    for r in s.scalars(select(Risk).where(Risk.tenant_id==u.tenant_id)):
        vals=[r.id,r.title,r.category,r.owner,r.likelihood,r.impact,r.status]
        w.writerow(["'"+v if isinstance(v,str) and v.lstrip().startswith(('=','+','-','@','\t','\r')) else v for v in vals])
    return Response(out.getvalue(),media_type='text/csv',headers={'Content-Disposition':'attachment; filename="lexigrid-risks.csv"','Cache-Control':'no-store'})


@app.get('/api/exports/risks.json')
def export_risks_json(u:User=Depends(principal),s:Session=Depends(db)):
    items=[risk_dict(r) for r in s.scalars(select(Risk).where(Risk.tenant_id==u.tenant_id).order_by(Risk.created_at,Risk.id))]
    return Response(json.dumps({'schema':'lexigrid.risks.v1','count':len(items),'items':items},default=str),
                    media_type='application/json',headers={'Content-Disposition':'attachment; filename="lexigrid-risks.json"','Cache-Control':'no-store'})

@app.get('/api/exports/audit.csv')
def export_audit_csv(u:User=Depends(permit('tenant_admin','auditor')),s:Session=Depends(db)):
    out=io.StringIO(); writer=csv.writer(out)
    writer.writerow(['id','timestamp_utc','actor_id','action','object_id','details_json','integrity_mac'])
    for a in s.scalars(select(Audit).where(Audit.tenant_id==u.tenant_id).order_by(Audit.at,Audit.id)):
        writer.writerow([a.id,a.at.isoformat() if a.at else '',a.actor_id,a.action,a.object_id,a.details,a.integrity_mac])
    return Response(out.getvalue(),media_type='text/csv',headers={'Content-Disposition':'attachment; filename="lexigrid-audit.csv"','Cache-Control':'no-store'})

# routes and models must register before the application lifespan starts.
from . import risk_operations  # noqa: E402,F401
from . import governance_records  # noqa: E402,F401
from . import approval_records  # noqa: E402,F401
from . import operational_risk  # noqa: E402,F401

from fastapi.responses import FileResponse
@app.get('/', include_in_schema=False)
def root():
    return RedirectResponse('/ui')


@app.get('/ui',include_in_schema=False)
def user_interface():
    return FileResponse(Path(__file__).resolve().parent.parent / 'web' / 'index.html',headers={'Cache-Control':'no-store','Content-Security-Policy':"default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",'X-Content-Type-Options':'nosniff'})

# Enterprise OIDC sign-in: only pre-provisioned accounts, no role auto-assignment.
# Works with customer-hosted identity providers in isolated networks.
@app.get('/api/auth/providers')
def sso_providers():
    from .sso import providers
    return providers()


@app.get('/api/auth/oidc/start')
def oidc_start(tenant_id: str, ui: bool = False):
    from .oidc import begin
    from fastapi.responses import RedirectResponse
    try: tenant_id=str(uuid.UUID(tenant_id))
    except (ValueError,TypeError): raise HTTPException(422,'Invalid tenant ID')
    url,state=begin(tenant_id,JWT_SECRET,browser=ui)
    result=RedirectResponse(url,status_code=302)
    result.set_cookie('lexigrid_oidc_state',state,max_age=300,httponly=True,secure=True,samesite='lax',path='/api/auth/oidc/callback')
    return result

@app.get('/api/auth/oidc/callback')
def oidc_callback(request: Request,code: str,state: str,s:Session=Depends(db)):
    from .oidc import parse_state,exchange_with_verifier
    cookie=request.cookies.get('lexigrid_oidc_state','')
    if not cookie or not hmac.compare_digest(cookie,state):
        raise HTTPException(401,'OIDC login state mismatch')
    values=parse_state(state,JWT_SECRET)
    claims=exchange_with_verifier(code,values['verifier'],values['nonce'])
    # An explicit tenant-bound user provisioning decision must precede SSO.
    if s.bind.dialect.name=='postgresql':
        s.execute(sql_text("SELECT set_config('app.tenant_id', :tenant, true)"),{'tenant':values['tenant']})
    # Email/UPN may be absent or reassigned. Only the immutable, explicitly
    # provisioned issuer and subject may select a local account.
    users=s.scalars(select(User).where(
        User.tenant_id==values['tenant'],User.oidc_issuer==claims['iss'],
        User.oidc_subject==claims['sub'],User.active==1).limit(2)).all()
    if len(users)!=1:
        raise HTTPException(403,'Federated identity has not been uniquely bound by an administrator')
    user=users[0]
    ts=utc()
    token=jwt.encode({'sub':user.id,'tenant':user.tenant_id,'ver':user.token_version,'iat':ts,'exp':ts+timedelta(minutes=30)},JWT_SECRET,algorithm='HS256')
    log(s,user,'auth.oidc.login',user.id,{'issuer':claims['iss'],'subject':claims['sub']})
    s.commit()
    from .sso import login_response
    result=login_response({'access_token':token,'token_type':'bearer','expires_in':1800,
                           'tenant_id':user.tenant_id,'role':user.role},user.tenant_id,values.get('browser') is True)
    result.delete_cookie('lexigrid_oidc_state',path='/api/auth/oidc/callback',secure=True,httponly=True,samesite='lax')
    result.headers['Cache-Control']='no-store'
    return result

# SAML federation: pre-provisioned, tenant-bound identities only.
from fastapi import Form
from fastapi.responses import RedirectResponse
from .saml_sso import saml_auth, validate_response
class SamlReplay(Base):
    __tablename__='saml_replays'
    id=Column(String(512),primary_key=True)
    tenant_id=Column(String(36),nullable=False,index=True)
    at=Column(DateTime(timezone=True),nullable=False,default=utc)

@app.get('/api/auth/saml/start')
def saml_start(request:Request,tenant_id:str,ui:bool=False):
    try: tenant_id=str(uuid.UUID(tenant_id))
    except ValueError: raise HTTPException(422,'Invalid tenant')
    from itsdangerous import URLSafeTimedSerializer
    auth=saml_auth(request)
    destination=auth.login()
    request_id=auth.get_last_request_id()
    if not request_id: raise HTTPException(503,'SAML request could not be initiated')
    state=URLSafeTimedSerializer(JWT_SECRET,salt='saml-request').dumps({'tenant':tenant_id,'request_id':request_id,'browser':ui})
    response=RedirectResponse(destination)
    response.set_cookie('lexigrid_saml_state',state,secure=True,httponly=True,samesite='none',max_age=300,path='/api/auth/saml/acs')
    return response

@app.post('/api/auth/saml/acs')
def saml_acs(request:Request,SAMLResponse:str=Form(...),RelayState:str=Form(default=''),s:Session=Depends(db)):
    from itsdangerous import URLSafeTimedSerializer,BadSignature,SignatureExpired
    cookie=request.cookies.get('lexigrid_saml_state','')
    try: values=URLSafeTimedSerializer(JWT_SECRET,salt='saml-request').loads(cookie,max_age=300)
    except (BadSignature,SignatureExpired): raise HTTPException(401,'Invalid or expired SAML login state')
    if s.bind.dialect.name=='postgresql':
        s.execute(sql_text("SELECT set_config('app.tenant_id', :tenant, true)"),{'tenant':values['tenant']})
    auth=saml_auth(request,{'SAMLResponse':SAMLResponse,'RelayState':RelayState})
    verified=validate_response(auth,values['request_id'])
    replay_id=verified['response_id']
    if s.get(SamlReplay,replay_id): raise HTTPException(401,'Replayed SAML response')
    users=s.scalars(select(User).where(User.tenant_id==values['tenant'],User.saml_subject==verified['subject'],User.active==1).limit(2)).all()
    if len(users)!=1: raise HTTPException(403,'SAML identity has not been uniquely provisioned')
    user=users[0]
    s.add(SamlReplay(id=replay_id,tenant_id=values['tenant']))
    now=utc()
    token=jwt.encode({'sub':user.id,'tenant':user.tenant_id,'ver':user.token_version,'iat':now,'exp':now+timedelta(minutes=30)},JWT_SECRET,algorithm='HS256')
    log(s,user,'auth.saml.login',user.id,{'assertion_id':verified['assertion_id']})
    try: s.commit()
    except IntegrityError: s.rollback();raise HTTPException(401,'Replayed SAML response')
    from .sso import login_response
    result=login_response({'access_token':token,'token_type':'bearer','expires_in':1800},
                          user.tenant_id,values.get('browser') is True)
    result.delete_cookie('lexigrid_saml_state',path='/api/auth/saml/acs',secure=True,httponly=True,samesite='none')
    result.headers['Cache-Control']='no-store'
    return result

from . import enterprise  # noqa: E402,F401 - enterprise IRM models and routes
from . import workflows  # noqa: E402,F401 - executable multi-step approval workflows

from . import ai_risk  # noqa: E402,F401 - AI-assisted proposals

from . import document_ingest  # noqa: E402,F401

from . import risk_contacts  # noqa: E402,F401 - risk stakeholders and SMTP updates

from . import risk_mail_automation  # noqa: E402,F401 - durable risk mail and reminders

from . import report_exports  # noqa: E402,F401

from . import client_events  # noqa: E402,F401

from . import risk_methods  # noqa: E402,F401 - methodology-based advisory reports

from . import risk_governance  # noqa: E402,F401 - automatic advisory governance applicability

from . import compliance_audit  # noqa: E402,F401 - evidence-based compliance audit workflow

from . import risk_history  # noqa: E402,F401 - read-only committed risk revision view

from . import remediation_review  # noqa: E402,F401 - independent evidence-backed closure

from . import risk_acceptance  # noqa: E402,F401 - independently approved, expiring acceptance
