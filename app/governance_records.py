"""LexiGrid governance and compliance APIs. Author: Shahryar Jahangir, Aniza Inc."""
import json, os, hashlib, base64, csv, io
from pydantic import ValidationError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import File, UploadFile, Response, Form
from fastapi import Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import Column, String, Integer, Text, DateTime, ForeignKey, UniqueConstraint, select, func, update, LargeBinary
from sqlalchemy.orm import Session
from .main import Base, app, db, principal, permit, User, uid, utc, log, get_risk

class Control(Base):
    __tablename__='controls'
    id=Column(String(36),primary_key=True,default=uid); tenant_id=Column(String(36),ForeignKey('tenants.id'),nullable=False,index=True)
    code=Column(String(60),nullable=False); title=Column(String(200),nullable=False); description=Column(Text,nullable=False)
    owner=Column(String(200),nullable=False); status=Column(String(30),nullable=False,default='planned'); version=Column(Integer,nullable=False,default=1)
    __table_args__=(UniqueConstraint('tenant_id','code'),)
class Framework(Base):
    __tablename__='frameworks'
    id=Column(String(36),primary_key=True,default=uid);tenant_id=Column(String(36),ForeignKey('tenants.id'),nullable=False,index=True)
    name=Column(String(200),nullable=False);revision=Column(String(80),nullable=False)
    __table_args__=(UniqueConstraint('tenant_id','name','revision'),)
class Requirement(Base):
    __tablename__='requirements'
    id=Column(String(36),primary_key=True,default=uid);tenant_id=Column(String(36),ForeignKey('tenants.id'),nullable=False,index=True)
    framework_id=Column(String(36),ForeignKey('frameworks.id'),nullable=False);reference=Column(String(120),nullable=False);text=Column(Text,nullable=False)
    __table_args__=(UniqueConstraint('tenant_id','framework_id','reference'),)
class ControlLink(Base):
    __tablename__='control_links'
    id=Column(String(36),primary_key=True,default=uid);tenant_id=Column(String(36),ForeignKey('tenants.id'),nullable=False,index=True)
    control_id=Column(String(36),ForeignKey('controls.id'),nullable=False);risk_id=Column(String(36),ForeignKey('risks.id'),nullable=True)
    requirement_id=Column(String(36),ForeignKey('requirements.id'),nullable=True)
class ControlTest(Base):
    __tablename__='control_tests'
    id=Column(String(36),primary_key=True,default=uid);tenant_id=Column(String(36),ForeignKey('tenants.id'),nullable=False,index=True)
    control_id=Column(String(36),ForeignKey('controls.id'),nullable=False);result=Column(String(25),nullable=False)
    procedure=Column(Text,nullable=False);notes=Column(Text,nullable=False);tester_id=Column(String(36),nullable=False);tested_at=Column(DateTime(timezone=True),default=utc,nullable=False)
class Evidence(Base):
    __tablename__='evidence'
    id=Column(String(36),primary_key=True,default=uid);tenant_id=Column(String(36),ForeignKey('tenants.id'),nullable=False,index=True)
    control_id=Column(String(36),ForeignKey('controls.id'),nullable=False);title=Column(String(200),nullable=False)
    uri=Column(Text,nullable=False);sha256=Column(String(64),nullable=False);submitted_by=Column(String(36),nullable=False)
    submitted_at=Column(DateTime(timezone=True),default=utc,nullable=False)
class EvidenceBlob(Base):
    __tablename__='evidence_blobs'
    id=Column(String(36),primary_key=True,default=uid)
    tenant_id=Column(String(36),ForeignKey('tenants.id'),nullable=False,index=True)
    control_id=Column(String(36),ForeignKey('controls.id'),nullable=False)
    filename=Column(String(200),nullable=False)
    content_type=Column(String(100),nullable=False)
    sha256=Column(String(64),nullable=False)
    nonce=Column(LargeBinary,nullable=False)
    ciphertext=Column(LargeBinary,nullable=False)
    submitted_by=Column(String(36),nullable=False)
    submitted_at=Column(DateTime(timezone=True),default=utc,nullable=False)

def evidence_key():
    raw=os.getenv('EVIDENCE_ENCRYPTION_KEY','').strip()
    try:
        key = bytes.fromhex(raw) if len(raw) == 64 else base64.b64decode(raw, validate=True)
    except (ValueError, TypeError):
        key = b''
    if len(key) != 32:
        raise HTTPException(503, 'Evidence encryption key must be 32 bytes encoded as base64 or 64 hexadecimal characters')
    return key

@app.post('/api/controls/{cid}/evidence-files',status_code=201)
async def upload_evidence_file(cid:str,file:UploadFile=File(...),u:User=Depends(permit('tenant_admin','risk_manager','auditor')),s:Session=Depends(db)):
    owned(s,Control,cid,u.tenant_id)
    from .kms import encrypt_evidence, provider, TransitError
    from .conjur_kms import ConjurError
    try:
        selected=provider()
    except TransitError as exc:
        raise HTTPException(503,'Evidence encryption configuration is unavailable') from exc
    key=evidence_key() if selected=='local' else None
    data=await file.read(10*1024*1024+1)
    if not data or len(data)>10*1024*1024: raise HTTPException(413,'Evidence must be 1 byte to 10 MiB')
    name=(file.filename or 'evidence.bin').replace('\\','/').split('/')[-1][:200]
    if not name: name='evidence.bin'
    record=EvidenceBlob(id=uid(),tenant_id=u.tenant_id,control_id=cid,filename=name,content_type=(file.content_type or 'application/octet-stream')[:100],sha256=hashlib.sha256(data).hexdigest(),nonce=os.urandom(12),submitted_by=u.id)
    aad=f'{u.tenant_id}:{cid}:{record.id}'.encode()
    try:
        record.nonce,record.ciphertext=encrypt_evidence(data,aad,key)
    except (TransitError,ConjurError) as exc:
        raise HTTPException(503,'Evidence encryption provider is unavailable; no evidence was saved') from exc
    saved(s,u,record,'evidence.file_upload',{'sha256':record.sha256,'control_id':cid,'filename':name})
    return {'id':record.id,'sha256':record.sha256,'filename':name,'size':len(data)}

@app.get('/api/evidence-files/{eid}')
def download_evidence_file(eid:str,u:User=Depends(principal),s:Session=Depends(db)):
    record=owned(s,EvidenceBlob,eid,u.tenant_id)
    from .kms import decrypt_evidence, TransitError
    from .conjur_kms import ConjurUnavailable
    key=evidence_key() if record.nonce!=b'VAULT1' and not record.nonce.startswith(b'CJ1') else None
    aad=f'{u.tenant_id}:{record.control_id}:{record.id}'.encode()
    try: data=decrypt_evidence(record.nonce,record.ciphertext,aad,key)
    except (TransitError,ConjurUnavailable) as exc:
        raise HTTPException(503,'Evidence decryption provider is unavailable; try again after service recovery') from exc
    except Exception as exc:
        raise HTTPException(409,'Evidence integrity verification failed') from exc
    if hashlib.sha256(data).hexdigest()!=record.sha256: raise HTTPException(409,'Evidence hash mismatch')
    return Response(content=data,media_type='application/octet-stream',headers={'Content-Disposition':f'attachment; filename="{record.id}.bin"','X-Content-SHA256':record.sha256})

class Policy(Base):
    __tablename__='policies'
    id=Column(String(36),primary_key=True,default=uid);tenant_id=Column(String(36),ForeignKey('tenants.id'),nullable=False,index=True)
    code=Column(String(60),nullable=False);title=Column(String(200),nullable=False);body=Column(Text,nullable=False)
    owner=Column(String(200),nullable=False);status=Column(String(20),nullable=False,default='draft');version=Column(Integer,nullable=False,default=1)
    __table_args__=(UniqueConstraint('tenant_id','code'),)
class Finding(Base):
    __tablename__='control_findings'
    id=Column(String(36),primary_key=True,default=uid);tenant_id=Column(String(36),ForeignKey('tenants.id'),nullable=False,index=True)
    control_id=Column(String(36),ForeignKey('controls.id'),nullable=False);title=Column(String(200),nullable=False)
    severity=Column(String(20),nullable=False);remediation=Column(Text,nullable=False);status=Column(String(20),nullable=False,default='open')

class ControlIn(BaseModel):
    code:str=Field(min_length=2,max_length=60);title:str=Field(min_length=2,max_length=200)
    description:str=Field(min_length=5,max_length=2000000);owner:str=Field(min_length=1,max_length=200)
    status:str=Field(default='planned',pattern='^(planned|implemented|retired)$')
class ControlUpdate(BaseModel):
    version:int=Field(ge=1);status:str=Field(pattern='^(planned|implemented|retired)$')
class FrameworkIn(BaseModel):
    name:str=Field(min_length=2,max_length=200);revision:str=Field(min_length=1,max_length=80)
class RequirementIn(BaseModel):
    reference:str=Field(min_length=1,max_length=120);text:str=Field(min_length=5,max_length=2000000)
class LinkIn(BaseModel):
    risk_id:str|None=None;requirement_id:str|None=None
class TestIn(BaseModel):
    result:str=Field(pattern='^(pass|fail|not_tested|not_applicable)$');procedure:str=Field(min_length=5,max_length=10000)
    notes:str=Field(default='',max_length=10000)
class EvidenceIn(BaseModel):
    title:str=Field(min_length=2,max_length=200);uri:str=Field(min_length=3,max_length=2048)
    sha256:str=Field(pattern='^[a-fA-F0-9]{64}$')
class PolicyIn(BaseModel):
    code:str=Field(min_length=2,max_length=60);title:str=Field(min_length=2,max_length=200)
    body:str=Field(min_length=5,max_length=2000000);owner:str=Field(min_length=1,max_length=200)
class PolicyUpdate(BaseModel):
    version:int=Field(ge=1);status:str=Field(pattern='^(draft|in_review|approved|retired)$')
class FindingIn(BaseModel):
    title:str=Field(min_length=2,max_length=200);severity:str=Field(pattern='^(low|medium|high|critical)$')
    remediation:str=Field(min_length=5,max_length=10000)

def owned(s,model,id,tenant):
    item=s.scalar(select(model).where(model.id==id,model.tenant_id==tenant))
    if item is None:raise HTTPException(404,'Resource not found')
    return item
def output(obj,*keys):return {key:getattr(obj,key) for key in keys}
def saved(s,u,entity,action,detail):
    s.add(entity);s.flush();log(s,u,action,entity.id,detail);s.commit()

@app.post('/api/controls',status_code=201)
def create_control(body:ControlIn,u:User=Depends(permit('tenant_admin','risk_manager')),s:Session=Depends(db)):
    if s.scalar(select(Control.id).where(Control.tenant_id==u.tenant_id,Control.code==body.code)):raise HTTPException(409,'Control code exists')
    c=Control(tenant_id=u.tenant_id,**body.model_dump());saved(s,u,c,'control.create',body.model_dump());return output(c,'id','code','title','description','owner','status','version')
@app.get('/api/controls')
def controls(u:User=Depends(principal),s:Session=Depends(db)):
    return [output(c,'id','code','title','description','owner','status','version') for c in s.scalars(select(Control).where(Control.tenant_id==u.tenant_id).order_by(Control.code))]
@app.patch('/api/controls/{cid}')
def update_control(cid:str,body:ControlUpdate,u:User=Depends(permit('tenant_admin','risk_manager')),s:Session=Depends(db)):
    result=s.execute(update(Control).where(Control.id==cid,Control.tenant_id==u.tenant_id,Control.version==body.version).values(status=body.status,version=Control.version+1))
    if result.rowcount!=1:
        exists=s.scalar(select(Control.id).where(Control.id==cid,Control.tenant_id==u.tenant_id));s.rollback()
        raise HTTPException(409 if exists else 404,'Version conflict' if exists else 'Control not found')
    c=owned(s,Control,cid,u.tenant_id);log(s,u,'control.update',cid,body.model_dump());s.commit();return output(c,'id','status','version')
def content_version(record,fields):
    payload={key:getattr(record,key) for key in ('id','tenant_id',*fields)}
    return hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()


def framework_view(record):
    return {**output(record,'id','name','revision'),'version':content_version(record,('name','revision'))}


def requirement_view(record):
    return {**output(record,'id','framework_id','reference','text'),
            'version':content_version(record,('framework_id','reference','text'))}


@app.post('/api/frameworks',status_code=201)
def create_framework(body:FrameworkIn,u:User=Depends(permit('tenant_admin','risk_manager')),s:Session=Depends(db)):
    if s.scalar(select(Framework.id).where(Framework.tenant_id==u.tenant_id,Framework.name==body.name,Framework.revision==body.revision)):raise HTTPException(409,'Framework exists')
    f=Framework(tenant_id=u.tenant_id,**body.model_dump());saved(s,u,f,'framework.create',body.model_dump());return framework_view(f)
@app.get('/api/frameworks')
def frameworks(u:User=Depends(principal),s:Session=Depends(db)):
    return [framework_view(f) for f in s.scalars(select(Framework).where(Framework.tenant_id==u.tenant_id))]
class ControlDetailsUpdate(BaseModel):
    version:int=Field(ge=1)
    code:str=Field(min_length=2,max_length=60)
    title:str=Field(min_length=2,max_length=200)
    description:str=Field(min_length=1,max_length=2000000)
    owner:str=Field(min_length=1,max_length=200)
    status:str=Field(pattern='^(planned|implemented|retired)$')

class CheckedEdit(BaseModel):
    @field_validator('*',mode='before')
    @classmethod
    def checked_text(cls,value):
        if isinstance(value,str):
            if '\x00' in value:raise ValueError('NUL characters are not allowed')
            return value.strip()
        return value

class FrameworkDetailsUpdate(CheckedEdit):
    version:str=Field(pattern=r'^[0-9a-f]{64}$')
    name:str=Field(min_length=1,max_length=200)
    revision:str=Field(min_length=1,max_length=80)

class RequirementDetailsUpdate(CheckedEdit):
    version:str=Field(pattern=r'^[0-9a-f]{64}$')
    reference:str=Field(min_length=1,max_length=120)
    text:str=Field(min_length=5,max_length=2000000)

class PolicyDetailsUpdate(BaseModel):
    version:int=Field(ge=1)
    code:str=Field(min_length=2,max_length=60)
    title:str=Field(min_length=2,max_length=200)
    body:str=Field(min_length=5,max_length=2000000)
    owner:str=Field(min_length=1,max_length=200)

@app.patch('/api/controls/{cid}/details')
def edit_control_details(cid:str,body:ControlDetailsUpdate,u:User=Depends(permit('tenant_admin','risk_manager')),s:Session=Depends(db)):
    c=owned(s,Control,cid,u.tenant_id)
    if c.version!=body.version:raise HTTPException(409,'Version conflict; refresh and retry')
    before=output(c,'code','title','description','owner','status','version')
    data=body.model_dump(exclude={'version'})
    if data['code']!=c.code and s.scalar(select(Control.id).where(Control.tenant_id==u.tenant_id,Control.code==data['code'])):raise HTTPException(409,'Control code already exists')
    result=s.execute(update(Control).where(Control.id==cid,Control.tenant_id==u.tenant_id,Control.version==body.version).values(**data,version=Control.version+1))
    if result.rowcount!=1:s.rollback();raise HTTPException(409,'Version conflict')
    s.expire_all();c=owned(s,Control,cid,u.tenant_id);log(s,u,'control.details_update',cid,{'before':before,'after':output(c,'code','title','description','owner','status','version')});s.commit()
    return output(c,'id','code','title','description','owner','status','version')

@app.patch('/api/frameworks/{fid}')
def edit_framework(fid:str,body:FrameworkDetailsUpdate,u:User=Depends(permit('tenant_admin','risk_manager')),s:Session=Depends(db)):
    f=owned(s,Framework,fid,u.tenant_id)
    if content_version(f,('name','revision'))!=body.version:
        raise HTTPException(409,'Framework changed; refresh before editing')
    before=output(f,'name','revision');data=body.model_dump(exclude={'version'})
    try:
        changed=s.execute(update(Framework).where(Framework.id==fid,Framework.tenant_id==u.tenant_id,
            Framework.name==before['name'],Framework.revision==before['revision']).values(**data))
        if changed.rowcount!=1:
            s.rollback();raise HTTPException(409,'Framework changed; refresh before editing')
        s.expire_all();f=owned(s,Framework,fid,u.tenant_id)
        result=framework_view(f)
        log(s,u,'framework.update',fid,{'before':before,'after':data});s.commit()
    except IntegrityError as exc:
        s.rollback();raise HTTPException(409,'Framework name/revision already exists') from exc
    return result

@app.patch('/api/frameworks/{fid}/requirements/{rid}')
def edit_requirement(fid:str,rid:str,body:RequirementDetailsUpdate,u:User=Depends(permit('tenant_admin','risk_manager')),s:Session=Depends(db)):
    owned(s,Framework,fid,u.tenant_id)
    r=owned(s,Requirement,rid,u.tenant_id)
    if r.framework_id!=fid:raise HTTPException(404,'Requirement not found in framework')
    if content_version(r,('framework_id','reference','text'))!=body.version:
        raise HTTPException(409,'Requirement changed; refresh before editing')
    before=output(r,'reference','text');data=body.model_dump(exclude={'version'})
    try:
        changed=s.execute(update(Requirement).where(Requirement.id==rid,Requirement.framework_id==fid,
            Requirement.tenant_id==u.tenant_id,Requirement.reference==before['reference'],
            Requirement.text==before['text']).values(**data))
        if changed.rowcount!=1:
            s.rollback();raise HTTPException(409,'Requirement changed; refresh before editing')
        s.expire_all();r=owned(s,Requirement,rid,u.tenant_id);result=requirement_view(r)
        log(s,u,'requirement.update',rid,{'before':before,'after':data,'framework_id':fid});s.commit()
    except IntegrityError as exc:
        s.rollback();raise HTTPException(409,'Requirement reference already exists') from exc
    return result

@app.patch('/api/policies/{pid}/details')
def edit_policy_details(pid:str,body:PolicyDetailsUpdate,u:User=Depends(permit('tenant_admin','risk_manager')),s:Session=Depends(db)):
    p=owned(s,Policy,pid,u.tenant_id)
    if p.version!=body.version:raise HTTPException(409,'Version conflict; refresh and retry')
    if p.status!='draft':raise HTTPException(409,'Only draft policies can be edited; use governed revision process for approved policies')
    if p.code!=body.code and s.scalar(select(Policy.id).where(Policy.tenant_id==u.tenant_id,Policy.code==body.code)):raise HTTPException(409,'Policy code already exists')
    before=output(p,'code','title','body','owner','version')
    data=body.model_dump(exclude={'version'})
    result=s.execute(update(Policy).where(Policy.id==pid,Policy.tenant_id==u.tenant_id,Policy.version==body.version,Policy.status=='draft').values(**data,version=Policy.version+1))
    if result.rowcount!=1:s.rollback();raise HTTPException(409,'Version conflict')
    s.expire_all();p=owned(s,Policy,pid,u.tenant_id);log(s,u,'policy.details_update',pid,{'before':before,'after':output(p,'code','title','body','owner','version')});s.commit()
    return output(p,'id','code','title','body','owner','status','version')

@app.post('/api/frameworks/{fid}/requirements',status_code=201)
def create_requirement(fid:str,body:RequirementIn,u:User=Depends(permit('tenant_admin','risk_manager')),s:Session=Depends(db)):
    owned(s,Framework,fid,u.tenant_id)
    if s.scalar(select(Requirement.id).where(Requirement.tenant_id==u.tenant_id,Requirement.framework_id==fid,Requirement.reference==body.reference)):raise HTTPException(409,'Requirement exists')
    r=Requirement(tenant_id=u.tenant_id,framework_id=fid,**body.model_dump());saved(s,u,r,'requirement.create',{'framework_id':fid,**body.model_dump()});return requirement_view(r)
@app.get('/api/frameworks/{fid}/requirements')
def requirements(fid:str,u:User=Depends(principal),s:Session=Depends(db)):
    owned(s,Framework,fid,u.tenant_id)
    return [requirement_view(r) for r in s.scalars(select(Requirement).where(Requirement.tenant_id==u.tenant_id,Requirement.framework_id==fid))]
@app.get('/api/requirements')
def list_requirements(framework_id:str|None=None,q:str=Query('',max_length=200),limit:int=Query(100,ge=1,le=500),offset:int=Query(0,ge=0),u:User=Depends(principal),s:Session=Depends(db)):
    """Search all requirements in the authenticated workspace, with their framework identity."""
    query=select(Requirement,Framework).join(Framework,Requirement.framework_id==Framework.id).where(Requirement.tenant_id==u.tenant_id,Framework.tenant_id==u.tenant_id)
    if framework_id:
        owned(s,Framework,framework_id,u.tenant_id)
        query=query.where(Requirement.framework_id==framework_id)
    if q.strip():
        from sqlalchemy import or_
        value='%'+q.strip().replace('!','!!').replace('%','!%').replace('_','!_')+'%'
        query=query.where(or_(Requirement.reference.ilike(value,escape='!'),Requirement.text.ilike(value,escape='!'),Framework.name.ilike(value,escape='!')))
    total=s.scalar(select(func.count()).select_from(query.subquery()))
    return {'total':total,'limit':limit,'offset':offset,'items':[{**requirement_view(row),'framework_name':framework.name,'framework_revision':framework.revision} for row,framework in s.execute(query.order_by(Framework.name,Framework.revision,Requirement.reference,Requirement.id).offset(offset).limit(limit))]}

@app.get('/api/requirements/{rid}')
def requirement_detail(rid:str,u:User=Depends(principal),s:Session=Depends(db)):
    row=owned(s,Requirement,rid,u.tenant_id);framework=owned(s,Framework,row.framework_id,u.tenant_id)
    return {**requirement_view(row),'framework_name':framework.name,'framework_revision':framework.revision}

@app.post('/api/controls/{cid}/links',status_code=201)
def link_control(cid:str,body:LinkIn,u:User=Depends(permit('tenant_admin','risk_manager')),s:Session=Depends(db)):
    owned(s,Control,cid,u.tenant_id)
    if (body.risk_id is None)==(body.requirement_id is None):raise HTTPException(422,'Specify exactly one target')
    if body.risk_id:
        risk=get_risk(s,body.risk_id,u.tenant_id)
        s.refresh(risk,with_for_update=True)
    if body.requirement_id:owned(s,Requirement,body.requirement_id,u.tenant_id)
    if s.scalar(select(ControlLink.id).where(ControlLink.tenant_id==u.tenant_id,ControlLink.control_id==cid,ControlLink.risk_id==body.risk_id,ControlLink.requirement_id==body.requirement_id)):raise HTTPException(409,'Link exists')
    link=ControlLink(tenant_id=u.tenant_id,control_id=cid,**body.model_dump());saved(s,u,link,'control.link',body.model_dump());return output(link,'id','control_id','risk_id','requirement_id')
@app.get('/api/controls/{cid}/links')
def control_links(cid:str,u:User=Depends(principal),s:Session=Depends(db)):
    owned(s,Control,cid,u.tenant_id)
    return [output(x,'id','control_id','risk_id','requirement_id') for x in s.scalars(select(ControlLink).where(ControlLink.tenant_id==u.tenant_id,ControlLink.control_id==cid))]
@app.post('/api/controls/{cid}/tests',status_code=201)
def create_test(cid:str,body:TestIn,u:User=Depends(permit('tenant_admin','risk_manager','auditor')),s:Session=Depends(db)):
    owned(s,Control,cid,u.tenant_id)
    t=ControlTest(tenant_id=u.tenant_id,control_id=cid,tester_id=u.id,**body.model_dump());saved(s,u,t,'control.test',body.model_dump());return output(t,'id','control_id','result','procedure','notes','tester_id','tested_at')
@app.get('/api/controls/{cid}/tests')
def tests(cid:str,u:User=Depends(principal),s:Session=Depends(db)):
    owned(s,Control,cid,u.tenant_id)
    return [output(t,'id','result','procedure','notes','tester_id','tested_at') for t in s.scalars(select(ControlTest).where(ControlTest.tenant_id==u.tenant_id,ControlTest.control_id==cid).order_by(ControlTest.tested_at.desc()))]
@app.post('/api/controls/{cid}/evidence',status_code=201)
def add_evidence(cid:str,body:EvidenceIn,u:User=Depends(permit('tenant_admin','risk_manager','auditor')),s:Session=Depends(db)):
    owned(s,Control,cid,u.tenant_id)
    e=Evidence(tenant_id=u.tenant_id,control_id=cid,submitted_by=u.id,**body.model_dump());saved(s,u,e,'evidence.register',body.model_dump());return output(e,'id','control_id','title','uri','sha256','submitted_by','submitted_at')
@app.get('/api/controls/{cid}/evidence')
def evidence(cid:str,u:User=Depends(principal),s:Session=Depends(db)):
    owned(s,Control,cid,u.tenant_id)
    return [output(e,'id','title','uri','sha256','submitted_by','submitted_at') for e in s.scalars(select(Evidence).where(Evidence.tenant_id==u.tenant_id,Evidence.control_id==cid))]
@app.post('/api/policies',status_code=201)
def create_policy(body:PolicyIn,u:User=Depends(permit('tenant_admin','risk_manager')),s:Session=Depends(db)):
    if s.scalar(select(Policy.id).where(Policy.tenant_id==u.tenant_id,Policy.code==body.code)):raise HTTPException(409,'Policy code exists')
    p=Policy(tenant_id=u.tenant_id,**body.model_dump());saved(s,u,p,'policy.create',{'code':body.code});return output(p,'id','code','title','body','owner','status','version')
@app.get('/api/policies')
def policies(u:User=Depends(principal),s:Session=Depends(db)):
    return [output(p,'id','code','title','body','owner','status','version') for p in s.scalars(select(Policy).where(Policy.tenant_id==u.tenant_id))]
@app.patch('/api/policies/{pid}')
def update_policy(pid:str,body:PolicyUpdate,u:User=Depends(permit('tenant_admin','risk_manager')),s:Session=Depends(db)):
    p=owned(s,Policy,pid,u.tenant_id)
    transitions={'draft':{'in_review'},'in_review':{'draft','approved'},'approved':{'retired'},'retired':set()}
    if body.status not in transitions[p.status]:raise HTTPException(422,'Invalid policy transition')
    if body.status=='approved':
        from .approval_records import Approval
        approved=s.scalar(select(Approval.id).where(Approval.tenant_id==u.tenant_id,Approval.object_type=='policy',Approval.object_id==pid,Approval.state=='approved',Approval.target_version==p.version,Approval.requester_id!=Approval.approver_id))
        if not approved:raise HTTPException(409,'Independent approved decision required before policy publication')
        from . import approval_binding
        approval=owned(s,Approval,approved,u.tenant_id)
        if approval_binding.status(s,approval,True)!='current':raise HTTPException(409,'Approved policy content or provenance changed; request a fresh independent review')
    result=s.execute(update(Policy).where(Policy.id==pid,Policy.tenant_id==u.tenant_id,Policy.version==body.version).values(status=body.status,version=Policy.version+1))
    if result.rowcount!=1:s.rollback();raise HTTPException(409,'Version conflict')
    s.expire_all();p=owned(s,Policy,pid,u.tenant_id);log(s,u,'policy.transition',pid,body.model_dump());s.commit();return output(p,'id','status','version')
@app.post('/api/controls/{cid}/findings',status_code=201)
def create_finding(cid:str,body:FindingIn,u:User=Depends(permit('tenant_admin','risk_manager','auditor')),s:Session=Depends(db)):
    owned(s,Control,cid,u.tenant_id)
    f=Finding(tenant_id=u.tenant_id,control_id=cid,**body.model_dump());saved(s,u,f,'finding.create',body.model_dump());return output(f,'id','control_id','title','severity','remediation','status')
@app.get('/api/controls/{cid}/findings')
def findings(cid:str,u:User=Depends(principal),s:Session=Depends(db)):
    owned(s,Control,cid,u.tenant_id)
    return [output(f,'id','control_id','title','severity','remediation','status') for f in s.scalars(select(Finding).where(Finding.tenant_id==u.tenant_id,Finding.control_id==cid))]
@app.get('/api/compliance/coverage')
def coverage(u:User=Depends(principal),s:Session=Depends(db)):
    total=s.scalar(select(func.count()).select_from(Requirement).where(Requirement.tenant_id==u.tenant_id))
    mapped=s.scalar(select(func.count(func.distinct(ControlLink.requirement_id))).where(ControlLink.tenant_id==u.tenant_id,ControlLink.requirement_id.is_not(None)))
    return {'requirements':total,'mapped_requirements':mapped,'unmapped_requirements':total-mapped,'coverage_percent':round(mapped*100/total,2) if total else None}


# Bulk governance imports: strict CSV schema, dry-run preview, tenant isolation, atomic commit.
BULK_SCHEMAS = {
    'controls': (ControlIn, Control, ('code','title','description','owner','status')),
    'policies': (PolicyIn, Policy, ('code','title','body','owner')),
    'frameworks': (FrameworkIn, Framework, ('name','revision')),
    'requirements': (RequirementIn, Requirement, ('framework_name','framework_revision','reference','text')),
}

BULK_SAMPLES = {
    'controls':('EXAMPLE-CTRL-001','Example account review','Review privileged access every quarter.','Example Security Team','planned'),
    'policies':('EXAMPLE-POL-001','Example access policy','Grant access by role, and review it quarterly.','Example Security Team'),
    'frameworks':('Example Security Framework','2026.1'),
    'requirements':('Example Security Framework','2026.1','EXAMPLE-REQ-001','Review privileged access every quarter.'),
}
BULK_LABELS={'controls':'Controls','policies':'Policies','frameworks':'Frameworks','requirements':'Framework requirements'}
BULK_FIELD_HELP={
    'code':'Unique code within this organization.', 'title':'Record title.',
    'description':'Control description.', 'owner':'Accountable person or team. Blank cells use Default accountable owner when supplied; a row owner overrides it.',
    'status':'Control lifecycle status.', 'body':'Full policy text; new policies start as draft.',
    'name':'Framework name; this does not import its controls or requirements.',
    'revision':'Framework revision / edition, treated as text.',
    'framework_name':'Exact name of an existing framework in this organization.',
    'framework_revision':'Exact revision of that existing framework, treated as text.',
    'reference':'Unique requirement reference within the target framework.',
    'text':'Requirement text.',
}


def bulk_template_csv(kind):
    out=io.StringIO();writer=csv.writer(out)
    writer.writerow(BULK_SCHEMAS[kind][2]);writer.writerow(BULK_SAMPLES[kind])
    return out.getvalue()


def bulk_schema_description(kind):
    model,_,names=BULK_SCHEMAS[kind]
    properties=model.model_json_schema()['properties']
    framework_properties=FrameworkIn.model_json_schema()['properties']
    columns=[]
    for name in names:
        rule=framework_properties[{'framework_name':'name','framework_revision':'revision'}[name]] if name in {'framework_name','framework_revision'} else properties[name]
        column={'name':name,'required':True,'description':BULK_FIELD_HELP[name]}
        for key in ['minLength','maxLength','pattern']:
            if key in rule and not (key=='minLength' and name in {'framework_name','framework_revision'}):column[key]=rule[key]
        if 'pattern' in rule:
            column['allowed_values']=rule['pattern'].removeprefix('^(').removesuffix(')$').split('|')
        columns.append(column)
    notes={
      'controls':'Import controls separately from frameworks. Existing control codes and repeated CSV rows are skipped without overwriting records. Supply an owner per row or a Default accountable owner for blank cells. Status must use a listed value.',
      'policies':'New policies are created in draft state. CSV import does not approve a policy.',
      'frameworks':'Two columns are correct for framework identities. Use the other record types for controls, policies and framework requirements.',
      'requirements':'Import frameworks first. Framework name and revision must exactly match an existing framework in this organization.',
    }
    return {'kind':kind,'label':BULK_LABELS[kind],'columns':columns,
            'example_csv':bulk_template_csv(kind),'template_filename':f'lexigrid_{kind}_template.csv',
            'note':notes[kind],'max_file_bytes':2000000,'max_rows':None}


@app.get('/api/bulk/schemas')
def bulk_schemas(u:User=Depends(principal)):
    # This describes the actual importer and static fictional examples, never existing records.
    return {kind:bulk_schema_description(kind) for kind in BULK_SCHEMAS}


@app.get('/api/bulk/templates/{kind}')
def bulk_template(kind:str,u:User=Depends(principal)):
    if kind not in BULK_SCHEMAS:raise HTTPException(404,'Unsupported import type')
    return Response(bulk_template_csv(kind),media_type='text/csv',
                    headers={'Content-Disposition':f'attachment; filename="lexigrid_{kind}_template.csv"'})

@app.post('/api/bulk/import/{kind}')
async def bulk_import(kind:str,file:UploadFile=File(...),dry_run:bool=True,default_owner:str=Form(default='',max_length=200),u:User=Depends(permit('tenant_admin','risk_manager')),s:Session=Depends(db)):
    if kind not in BULK_SCHEMAS:raise HTTPException(404,'Unsupported import type')
    if '\x00' in default_owner:raise HTTPException(422,'NUL characters are not allowed')
    default_owner=default_owner.strip()
    if default_owner and kind not in ('controls','policies'):raise HTTPException(422,'Default owner applies only to controls and policies')
    if not file.filename or not file.filename.lower().endswith('.csv'):raise HTTPException(415,'Upload a .csv file')
    raw=await file.read(2_000_001)
    if len(raw)>2_000_000:raise HTTPException(413,'CSV exceeds 2 MB limit')
    try:
        csv.field_size_limit(2_000_000)
        content=raw.decode('utf-8-sig');reader=csv.DictReader(io.StringIO(content,newline=''),strict=True)
        cols=BULK_SCHEMAS[kind][2]
        if reader.fieldnames is None or len(reader.fieldnames)!=len(set(reader.fieldnames)) or set(reader.fieldnames)!=set(cols):
            raise HTTPException(422,{'message':'CSV headers must match the template exactly','expected':cols})
        rows=list(reader)
    except (UnicodeDecodeError,csv.Error) as exc:raise HTTPException(422,'Invalid UTF-8 CSV') from exc
    if not rows:raise HTTPException(422,'CSV must contain at least one data row')
    model,entity,_=BULK_SCHEMAS[kind];errors=[];valid=[];seen=set();skipped=[]
    from .control_import import existing_ids,insert_once
    existing_controls=existing_ids(s,u.tenant_id,[row.get('code','').strip() for row in rows if isinstance(row.get('code',''),str)]) if kind=='controls' else {}
    framework_lookup={ (x.name,x.revision):x.id for x in s.scalars(select(Framework).where(Framework.tenant_id==u.tenant_id))} if kind=='requirements' else {}
    for n,row in enumerate(rows,start=2):
        if None in row or any(v is None for v in row.values()):errors.append({'row':n,'error':'Incorrect number of columns'});continue
        if any('\x00' in value for value in row.values()):
            errors.append({'row':n,'error':'NUL characters are not allowed'})
            continue
        row={k:v.strip() for k,v in row.items()}
        if kind=='controls':
            code=row.get('code','')
            if code in existing_controls or (code,) in seen:
                skipped.append({'row':n,'code':code,'reason':'already_exists' if code in existing_controls else 'duplicate_in_batch'});continue
        if kind in ('controls','policies') and not row.get('owner'):row['owner']=default_owner
        try:
            if kind=='requirements':
                fw=framework_lookup.get((row['framework_name'],row['framework_revision']))
                if not fw:raise ValueError('Framework name/revision not found; import frameworks first')
                obj=model.model_validate({'reference':row['reference'],'text':row['text']});key=(fw,obj.reference)
                data={**obj.model_dump(),'framework_id':fw}
            else:
                obj=model.model_validate(row);data=obj.model_dump()
                key=(obj.name,obj.revision) if kind=='frameworks' else (obj.code,)
            if key in seen:raise ValueError('Duplicate key within CSV')
            seen.add(key)
            if kind=='frameworks':existing=s.scalar(select(Framework.id).where(Framework.tenant_id==u.tenant_id,Framework.name==key[0],Framework.revision==key[1]))
            elif kind=='requirements':existing=s.scalar(select(Requirement.id).where(Requirement.tenant_id==u.tenant_id,Requirement.framework_id==key[0],Requirement.reference==key[1]))
            else:existing=False if kind=='controls' else s.scalar(select(entity.id).where(entity.tenant_id==u.tenant_id,entity.code==key[0]))
            if existing:raise ValueError('Record already exists in this tenant')
            valid.append((n,data))
        except (ValidationError,ValueError) as exc:errors.append({'row':n,'error':str(exc)[:400]})
    summary={**({'skipped_count':len(skipped),'skipped':skipped} if kind=='controls' else {}),'type':kind,'dry_run':dry_run,'total':len(rows),'valid':len(valid),'errors':errors[:100],'error_count':len(errors),'created':0}
    from .main import emit_event
    emit_event('operations','document.bulk.validated',outcome='error' if errors else 'success',actor_id=u.id,tenant_id=u.tenant_id,kind=kind,dry_run=dry_run,total=len(rows),valid=len(valid),skipped_count=len(skipped),error_count=len(errors))
    if dry_run or errors:return summary
    try:
        created=0
        for n,data in valid:
            if kind=='controls':
                identity=insert_once(s,u.tenant_id,data)
                if identity is None:
                    skipped.append({'row':n,'code':data['code'],'reason':'already_exists'});continue
                created+=1
                log(s,u,'bulk.controls.create',identity,{'source':'csv','filename':file.filename});continue
            record=entity(tenant_id=u.tenant_id,**data);s.add(record);s.flush()
            log(s,u,f'bulk.{kind}.create',record.id,{'source':'csv','filename':file.filename})
        if kind=='controls':
            for skip in skipped:log(s,u,'bulk.controls.skipped',uid(),{'source':'csv',**skip})
            summary.update(skipped_count=len(skipped),skipped=skipped,valid=created)
        else:created=len(valid)
        s.commit();summary['created']=created
    except IntegrityError:
        s.rollback();raise HTTPException(409,'Import could not be committed; no records were imported')
    except Exception:
        s.rollback();raise
    emit_event('operations','document.bulk.completed',outcome='success',actor_id=u.id,tenant_id=u.tenant_id,kind=kind,created=summary['created'],skipped_count=len(skipped))
    return summary
