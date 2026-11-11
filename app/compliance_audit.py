"""Complete imported-catalogue audit workflow with explicit evidence gaps.
Author: Shahryar Jahangir, Aniza Inc. No AI-generated compliance passes.
"""
import base64,csv,hashlib,hmac,io,json,os
from datetime import datetime,timezone
from html import escape
from typing import Literal
from uuid import UUID
from fastapi import Depends,HTTPException,Query,File,UploadFile,Response
from pydantic import BaseModel,Field,ConfigDict,field_validator,ValidationInfo
from cryptography.exceptions import InvalidTag
from sqlalchemy import select,update,func
from sqlalchemy.orm import Session
from .main import app,db,principal,permit,User,uid,utc,log,emit_event
from .enterprise import EnterpriseRecord
from .governance_records import Framework,Requirement,Control,ControlLink,framework_view,requirement_view,evidence_key
from . import audit_connectors as connector
from .kms import encrypt_evidence,decrypt_evidence,provider,TransitError
from .conjur_kms import ConjurError

AUDIT='compliance_audit';ITEM='compliance_audit_item';EVIDENCE='compliance_audit_evidence';CONNECTOR='compliance_identity_connector'
EDIT=('tenant_admin','risk_manager','auditor')


def require_control_independence(s,u,items):
    items=[item.get('source',item) for item in items]
    identities={control['id'] for item in items for control in item.get('linked_controls',[])}
    identities.update(item['source_id'] for item in items if item.get('source_kind')=='control')
    versions={control['id']:str(control['version']) for item in items for control in item.get('linked_controls',[])}
    versions.update({item['source_id']:str(item['source_version']) for item in items if item.get('source_kind')=='control'})
    if not identities:return
    identities=sorted(identities)
    for offset in range(0,len(identities),500):
        batch=identities[offset:offset+500]
        controls=s.scalars(select(Control).where(Control.tenant_id==u.tenant_id,Control.id.in_(batch))
            .order_by(Control.id).with_for_update().execution_options(populate_existing=True)).all()
        if len(controls)!=len(batch) or any(str(control.version)!=versions[control.id] for control in controls):
            raise HTTPException(409,'An audited control changed; create and review a fresh catalogue snapshot')
        if any(control.owner.strip().casefold() in {u.id.casefold(),u.email.casefold()} for control in controls):
            raise HTTPException(403,'An identified control owner cannot issue a conclusive assurance review or finalize their own control audit')


def get(s,tenant,identity,kind):
    if not isinstance(identity,str) or '\x00' in identity or len(identity)>36:raise HTTPException(404,'Audit resource not found')
    row=s.scalar(select(EnterpriseRecord).where(EnterpriseRecord.tenant_id==tenant,EnterpriseRecord.id==identity,EnterpriseRecord.kind==kind))
    if row is None:raise HTTPException(404,'Audit resource not found')
    return row


def data(row):return json.loads(row.data)


def put(s,u,kind,title,value,state='open'):
    row=EnterpriseRecord(id=uid(),tenant_id=u.tenant_id,kind=kind,title=title[:200],owner=u.email,data=json.dumps(value,sort_keys=True,allow_nan=False),state=state,created_by=u.id)
    s.add(row);s.flush();return row


def touch(s,row,values=None,state=None):
    version=row.version
    result=s.execute(update(EnterpriseRecord).where(EnterpriseRecord.id==row.id,EnterpriseRecord.tenant_id==row.tenant_id,EnterpriseRecord.version==version).values(data=json.dumps(values if values is not None else data(row),sort_keys=True,allow_nan=False),state=state or row.state,version=version+1,updated_at=utc()).execution_options(synchronize_session=False))
    if result.rowcount!=1:s.rollback();raise HTTPException(409,'Audit changed concurrently; refresh before retrying')
    s.refresh(row)


def open_audit(s,u,identity):
    row=get(s,u.tenant_id,identity,AUDIT)
    from .main import Audit
    finalized=s.scalar(select(Audit.id).where(Audit.tenant_id==u.tenant_id,Audit.object_id==identity,Audit.action=='compliance.audit.finalize').limit(1))
    if row.state!='open' or finalized:raise HTTPException(409,'Finalized audit is read-only; create a new audit for further testing')
    return row


def seal(tenant,identity,purpose,value):
    try:
        key=evidence_key() if provider()=='local' else None
        nonce,ciphertext=encrypt_evidence(json.dumps(value,sort_keys=True,allow_nan=False).encode(),f'compliance:{tenant}:{identity}:{purpose}'.encode(),key)
        return {'nonce':base64.b64encode(nonce).decode(),'ciphertext':base64.b64encode(ciphertext).decode()}
    except (TransitError,ConjurError):raise HTTPException(503,'Evidence encryption provider unavailable; nothing was saved') from None


def unseal(row,purpose,value):
    try:
        nonce=base64.b64decode(value['nonce'],validate=True);key=evidence_key() if nonce!=b'VAULT1' and not nonce.startswith(b'CJ1') else None
        raw=decrypt_evidence(nonce,base64.b64decode(value['ciphertext'],validate=True),f'compliance:{row.tenant_id}:{row.id}:{purpose}'.encode(),key)
        return json.loads(raw)
    except (TransitError,ConjurError,ValueError,KeyError,TypeError,InvalidTag):raise HTTPException(503,'Protected audit evidence is unavailable') from None


def members(s,tenant,audit_id,kind):
    # JSON fields are stored portably as text. Filter tenant/kind before decoding.
    return [(row,value) for row in s.scalars(select(EnterpriseRecord).where(EnterpriseRecord.tenant_id==tenant,EnterpriseRecord.kind==kind).order_by(EnterpriseRecord.id)) if (value:=data(row)).get('audit_id')==audit_id]


def evidence_view(row,value):
    timestamp=row.created_at.replace(tzinfo=timezone.utc) if row.created_at.tzinfo is None else row.created_at.astimezone(timezone.utc)
    return {k:v for k,v in {'id':row.id,'created_by':row.created_by,'created_at':timestamp.isoformat(),**value,'protected_integrity':hmac.compare_digest(value.get('protected_sha256',''),connector.digest(value.get('protected',{})))}.items() if k!='protected'}


def scope_catalogue(s,tenant,framework_ids,include_controls):
    frames=[];items=[];mapped=set();controls={x.id:x for x in s.scalars(select(Control).where(Control.tenant_id==tenant))}
    mapping={}
    for link in s.scalars(select(ControlLink).where(ControlLink.tenant_id==tenant,ControlLink.requirement_id.is_not(None))):
        if link.control_id in controls:mapping.setdefault(link.requirement_id,set()).add(link.control_id)
    for fid in sorted(set(framework_ids)):
        frame=s.scalar(select(Framework).where(Framework.tenant_id==tenant,Framework.id==fid))
        if not frame:raise HTTPException(404,'Framework not found')
        requirements=s.scalars(select(Requirement).where(Requirement.tenant_id==tenant,Requirement.framework_id==fid).order_by(Requirement.id)).all()
        frames.append({**framework_view(frame),'requirement_count':len(requirements)})
        for req in requirements:
            linked=[{'id':c.id,'code':c.code,'title':c.title,'description':c.description,'status':c.status,'version':c.version} for cid in sorted(mapping.get(req.id,set())) if (c:=controls.get(cid))]
            mapped.update(x['id'] for x in linked)
            items.append({'source_kind':'requirement','source_id':req.id,'source_version':requirement_view(req)['version'],'framework_id':fid,'framework_name':frame.name,'framework_revision':frame.revision,'reference':req.reference,'text':req.text,'linked_controls':linked})
    if include_controls:
        for c in sorted(controls.values(),key=lambda x:x.id):
            if c.id in mapped:continue
            items.append({'source_kind':'control','source_id':c.id,'source_version':str(c.version),'framework_id':None,'framework_name':'Unmapped workspace control — no standard attribution','framework_revision':'','reference':c.code,'text':c.title+'\n'+c.description,'linked_controls':[{'id':c.id,'code':c.code,'status':c.status,'version':c.version}]})
    return frames,items,connector.digest({'frameworks':frames,'items':items})


def final_digest(row,value,items,evidence):
    keys=('scope','framework_ids','frameworks','include_unmapped_controls','catalogue_sha256','catalogue_complete_attested','completeness_statement','completeness_evidence_ids','finalized_by','finalized_at','conclusion')
    return connector.digest({'id':row.id,'title':row.title,'created_by':row.created_by,'header':{key:value.get(key) for key in keys},'items':items,'evidence':evidence})


class Strict(BaseModel):
    model_config=ConfigDict(extra='forbid')
    @field_validator('*')
    @classmethod
    def meaningful_text(cls,value,info:ValidationInfo):
        pending=[value]
        while pending:
            item=pending.pop()
            if isinstance(item,str) and '\x00' in item:raise ValueError('Null characters are not allowed')
            if isinstance(item,dict):pending.extend(item.keys());pending.extend(item.values())
            elif isinstance(item,(list,tuple)):pending.extend(item)
        if isinstance(value,str):
            minimum={'title':3,'name':3,'scope':10,'reason':20,'procedure':10,'observations':10,'completeness_statement':30}.get(info.field_name)
            if minimum and len(value.strip())<minimum:raise ValueError('Provide meaningful text for '+info.field_name)
        return value

class AuditIn(Strict):
    title:str=Field(min_length=3,max_length=200)
    scope:str=Field(min_length=10,max_length=5000)
    framework_ids:list[str]=Field(min_length=1)
    include_unmapped_controls:bool=True
class EntraIn(Strict):
    name:str=Field(min_length=3,max_length=200)
    directory_tenant_id:UUID
    client_id:UUID
    client_secret:str=Field(min_length=8,max_length=2000)
    lookback_days:int=Field(default=7,ge=1,le=30)
class CollectIn(Strict):connector_id:str
class SnapshotIn(Strict):
    snapshot:dict
    minimum_password_length:int=Field(default=14,ge=1,le=128)
    maximum_lockout_threshold:int=Field(default=10,ge=1,le=100)
    @field_validator('snapshot')
    @classmethod
    def bounded(cls,value):
        if len(json.dumps(value,allow_nan=False))>connector.MAX_BYTES:raise ValueError('Snapshot exceeds 20 MiB')
        return value
class CheckRef(Strict):evidence_id:str;check_id:str
class ReviewIn(Strict):
    version:int=Field(ge=1)
    applicability:Literal['applicable','not_applicable','undetermined']
    implementation:Literal['implemented','partial','not_implemented','unknown','not_applicable']
    effectiveness:Literal['passed','failed','not_tested','insufficient_evidence','not_applicable']
    method:Literal['manual_evidence_review','technical_observation']
    reason:str=Field(min_length=20,max_length=5000)
    procedure:str=Field(min_length=10,max_length=5000)
    observations:str=Field(min_length=10,max_length=5000)
    evidence_ids:list[str]=Field(default_factory=list)
    check_refs:list[CheckRef]=Field(default_factory=list)
    source_provenance_verified:bool=False
    provenance_notes:str=Field(default='',max_length=3000)
class FinalizeIn(Strict):
    version:int=Field(ge=1)
    catalogue_complete_attested:bool
    completeness_statement:str=Field(min_length=30,max_length=5000)
    completeness_evidence_ids:list[str]=Field(min_length=1)


@app.post('/api/compliance/connectors/entra',status_code=201)
def configure_entra(body:EntraIn,u:User=Depends(permit('tenant_admin')),s:Session=Depends(db)):
    identity=uid();config=body.model_dump(mode='json');secret=seal(u.tenant_id,identity,'connector',config)
    row=EnterpriseRecord(id=identity,tenant_id=u.tenant_id,kind=CONNECTOR,title=body.name,owner=u.email,state='active',created_by=u.id,data=json.dumps({'name':body.name,'directory_tenant_id':str(body.directory_tenant_id),'client_id':str(body.client_id),'lookback_days':body.lookback_days,'protected':secret}))
    s.add(row);s.flush();log(s,u,'compliance.connector.create',row.id,{'source':'entra','directory_tenant_id':str(body.directory_tenant_id)});s.commit()
    return {'id':row.id,'name':body.name,'state':row.state,'secret_configured':True}


@app.get('/api/compliance/connectors')
def connectors(u:User=Depends(permit('tenant_admin','risk_manager','auditor')),s:Session=Depends(db)):
    return [{'id':r.id,'state':r.state,**{k:v for k,v in data(r).items() if k!='protected'},'secret_configured':True} for r in s.scalars(select(EnterpriseRecord).where(EnterpriseRecord.tenant_id==u.tenant_id,EnterpriseRecord.kind==CONNECTOR))]


@app.post('/api/compliance/connectors/{identity}/disable')
def disable_connector(identity:str,u:User=Depends(permit('tenant_admin')),s:Session=Depends(db)):
    row=get(s,u.tenant_id,identity,CONNECTOR);touch(s,row,state='disabled');log(s,u,'compliance.connector.disable',identity,{});s.commit();return {'id':identity,'state':row.state}


@app.post('/api/compliance/audits',status_code=201)
def create_audit(body:AuditIn,u:User=Depends(permit(*EDIT)),s:Session=Depends(db)):
    frames,source,sha=scope_catalogue(s,u.tenant_id,body.framework_ids,body.include_unmapped_controls)
    if not source:raise HTTPException(422,'No requirements or controls in the selected scope. Import the complete standard catalogue first.')
    audit=put(s,u,AUDIT,body.title,{'scope':body.scope,'framework_ids':sorted(set(body.framework_ids)),'frameworks':frames,'include_unmapped_controls':body.include_unmapped_controls,'catalogue_sha256':sha,'total_safeguards':len(source),'catalogue_complete_attested':False})
    for item in source:
        put(s,u,ITEM,item['reference'],{'audit_id':audit.id,'source':item,'review':None})
    log(s,u,'compliance.audit.create',audit.id,{'framework_ids':body.framework_ids,'safeguards':len(source),'catalogue_sha256':sha});s.commit()
    return {'id':audit.id,'version':audit.version,'state':audit.state,'total_safeguards':len(source)}


@app.get('/api/compliance/audits')
def list_audits(limit:int=Query(100,ge=1,le=500),offset:int=Query(0,ge=0),u:User=Depends(principal),s:Session=Depends(db)):
    query=select(EnterpriseRecord).where(EnterpriseRecord.tenant_id==u.tenant_id,EnterpriseRecord.kind==AUDIT)
    return {'total':s.scalar(select(func.count()).select_from(query.subquery())),'items':[{'id':r.id,'title':r.title,'state':r.state,'version':r.version,'created_at':str(r.created_at),'created_by':r.created_by,**data(r)} for r in s.scalars(query.order_by(EnterpriseRecord.created_at.desc(),EnterpriseRecord.id).limit(limit).offset(offset))]}


def report(s,u,identity):
    row=get(s,u.tenant_id,identity,AUDIT);value=data(row);items=members(s,u.tenant_id,identity,ITEM);evidence=members(s,u.tenant_id,identity,EVIDENCE)
    counts={'total':len(items),'reviewed':0,'applicable':0,'not_applicable':0,'undetermined':0,'implemented':0,'partial':0,'not_implemented':0,'implementation_unknown':0,'effectiveness_passed':0,'effectiveness_failed':0,'not_tested':0,'insufficient_evidence':0}
    for _,item in items:
        review=item.get('review')
        if not review:counts['undetermined']+=1;counts['implementation_unknown']+=1;counts['not_tested']+=1;continue
        counts['reviewed']+=1;counts[review['applicability']]+=1
        if review['implementation'] in ('implemented','partial','not_implemented'):counts[review['implementation']]+=1
        elif review['implementation']=='unknown':counts['implementation_unknown']+=1
        outcome=review['effectiveness']
        if outcome in ('passed','failed'):counts['effectiveness_'+outcome]+=1
        elif outcome in ('not_tested','insufficient_evidence'):counts[outcome]+=1
    try:_,_,current=scope_catalogue(s,u.tenant_id,value['framework_ids'],value['include_unmapped_controls'])
    except HTTPException as exc:
        if exc.status_code!=404:raise
        current='source_removed'
    integrity='not_finalized'
    from . import main
    entry=s.scalar(select(main.Audit).where(main.Audit.tenant_id==u.tenant_id,main.Audit.object_id==identity,main.Audit.action=='compliance.audit.finalize').order_by(main.Audit.at.desc()))
    if row.state=='finalized' or entry:
        actual=final_digest(row,value,[{'id':r.id,'version':r.version,**v} for r,v in items],[evidence_view(r,v) for r,v in evidence])
        integrity='verified'
        if row.state!='finalized':integrity='lifecycle_mismatch'
        elif not hmac.compare_digest(actual,value.get('review_snapshot_sha256','')):integrity='digest_mismatch'
        elif not entry:integrity='missing_finalization_record'
        elif not main.AUDIT_HMAC_KEY or not entry.integrity_mac:integrity='signing_unavailable'
        elif not hmac.compare_digest(entry.integrity_mac,main.audit_digest(entry.tenant_id,entry.actor_id,entry.action,entry.object_id,entry.details,entry.at)):integrity='signature_invalid'
        elif json.loads(entry.details).get('review_snapshot_sha256')!=actual:integrity='signature_snapshot_mismatch'
    safe_state='integrity_failure' if entry and row.state!='finalized' else row.state
    safe_conclusion=value.get('conclusion') if integrity in ('verified','not_finalized') else 'unverified_snapshot_do_not_rely_on_conclusion'
    return {'id':row.id,'title':row.title,'state':row.state,'version':row.version,'created_by':row.created_by,'created_at':str(row.created_at),**value,'state':safe_state,'conclusion':safe_conclusion,'integrity_status':integrity,'source_catalogue_changed':current!=value['catalogue_sha256'],'counts':counts,'items':[{'id':r.id,'version':r.version,**v} for r,v in items],'evidence':[evidence_view(r,v) for r,v in evidence],'notice':'Coverage is every imported safeguard in the selected snapshot. Catalogue completeness and evidence relevance require independent review. Unmapped controls are not attributed to a standard. Check passes apply only to their stated criteria and scope; this report is not certification.'}


@app.get('/api/compliance/audits/{identity}')
def read_audit(identity:str,u:User=Depends(principal),s:Session=Depends(db)):return report(s,u,identity)


def save_evidence(s,u,audit,title,value,payload):
    identity=uid();value={'audit_id':audit.id,'title':title,**value};value['protected']=seal(u.tenant_id,identity,'evidence',payload);value['protected_sha256']=connector.digest(value['protected'])
    row=EnterpriseRecord(id=identity,tenant_id=u.tenant_id,kind=EVIDENCE,title=title[:200],owner=u.email,state='recorded',created_by=u.id,data=json.dumps(value,sort_keys=True))
    s.add(row);s.flush();log(s,u,'compliance.evidence.record',identity,{'audit_id':audit.id,'source':value['source'],'sha256':value['sha256'],'checks':len(value.get('checks',[]))});return row,value


@app.post('/api/compliance/audits/{identity}/evidence-files',status_code=201)
async def upload_audit_evidence(identity:str,file:UploadFile=File(...),u:User=Depends(permit(*EDIT)),s:Session=Depends(db)):
    audit=open_audit(s,u,identity);raw=await file.read(10*1024*1024+1)
    if not raw or len(raw)>10*1024*1024:raise HTTPException(413,'Audit evidence must be 1 byte through 10 MiB')
    touch(s,audit);name=(file.filename or 'audit-evidence.bin').replace('\\','/').split('/')[-1][:200]
    row,value=save_evidence(s,u,audit,name,{'source':'uploaded_file','trust':'operator_submitted','sha256':hashlib.sha256(raw).hexdigest(),'size':len(raw),'filename':name,'collected_at':utc().isoformat(),'checks':[]},{'content':base64.b64encode(raw).decode(),'content_type':(file.content_type or 'application/octet-stream')[:100]})
    s.commit();return evidence_view(row,value)


@app.get('/api/compliance/audits/{identity}/evidence/{eid}/download')
def download_audit_evidence(identity:str,eid:str,u:User=Depends(principal),s:Session=Depends(db)):
    get(s,u.tenant_id,identity,AUDIT);row=get(s,u.tenant_id,eid,EVIDENCE);value=data(row)
    if value.get('audit_id')!=identity:raise HTTPException(404,'Audit evidence not found')
    if not hmac.compare_digest(value.get('protected_sha256',''),connector.digest(value.get('protected',{}))):raise HTTPException(409,'Protected audit evidence integrity check failed')
    protected=unseal(row,'evidence',value['protected'])
    raw=base64.b64decode(protected['content']) if value['source']=='uploaded_file' else json.dumps(protected,sort_keys=True,indent=2).encode()
    actual=hashlib.sha256(raw).hexdigest() if value['source']=='uploaded_file' else connector.digest(protected)
    if not hmac.compare_digest(actual,value['sha256']):raise HTTPException(409,'Source evidence hash does not match the recorded artifact')
    # Always download; uploaded content is never rendered as executable HTML.
    return Response(raw,media_type='application/octet-stream',headers={'Content-Disposition':'attachment; filename="audit-evidence-'+eid+'.bin"','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})


@app.post('/api/compliance/audits/{identity}/active-directory-snapshots',status_code=201)
def ad_snapshot(identity:str,body:SnapshotIn,u:User=Depends(permit(*EDIT)),s:Session=Depends(db)):
    audit=open_audit(s,u,identity);snapshot=body.snapshot
    if snapshot.get('source')!='active_directory' or snapshot.get('collector_version')!='lexigrid-ad-v1' or not isinstance(snapshot.get('datasets'),dict):raise HTTPException(422,'Expected the read-only LexiGrid Active Directory collector snapshot')
    try:
        observed=datetime.fromisoformat(snapshot['collected_at'].replace('Z','+00:00'))
        if observed.tzinfo is None or (utc()-observed).total_seconds() < -300:raise ValueError()
    except (ValueError,KeyError,TypeError,AttributeError):raise HTTPException(422,'Collector timestamp must be a valid timezone-aware time, not in the future') from None
    checks=connector.evaluate_ad(snapshot,body.minimum_password_length,body.maximum_lockout_threshold)
    if (utc()-observed).days>30:
        for item in checks:item['result']='insufficient_evidence';item['limitations'].append('Snapshot is older than 30 days; collect current evidence.')
    touch(s,audit);row,value=save_evidence(s,u,audit,'Active Directory read-only snapshot',{'source':'active_directory','trust':'operator_submitted','collected_at':snapshot['collected_at'],'sha256':connector.digest(snapshot),'checks':checks,'criteria':{'minimum_password_length':body.minimum_password_length,'maximum_lockout_threshold':body.maximum_lockout_threshold}},snapshot)
    s.commit();return evidence_view(row,value)


@app.post('/api/compliance/audits/{identity}/collect-entra',status_code=201)
def entra_snapshot(identity:str,body:CollectIn,u:User=Depends(permit(*EDIT)),s:Session=Depends(db)):
    audit=open_audit(s,u,identity);connection=get(s,u.tenant_id,body.connector_id,CONNECTOR)
    if connection.state!='active':raise HTTPException(409,'Identity connector is disabled')
    config=unseal(connection,'connector',data(connection)['protected'])
    try:snapshot=connector.collect_entra(config)
    except connector.CollectionError as exc:
        emit_event('operations','compliance.collection.failed',outcome='error',audit_id=identity,source='entra',error_type='CollectionError');raise HTTPException(502,str(exc)) from None
    # Re-read lifecycle after the network call; never append to a finalized audit.
    s.refresh(audit)
    if audit.state!='open':raise HTTPException(409,'Audit finalized during collection; create a new audit')
    touch(s,audit);checks=connector.evaluate_entra(snapshot)
    row,value=save_evidence(s,u,audit,'Microsoft Entra read-only observation',{'source':'entra_live','trust':'server_collected','directory_tenant_id':config['directory_tenant_id'],'collected_at':snapshot['collected_at'],'sha256':connector.digest(snapshot),'checks':checks,'collection_complete':snapshot['complete'],'collection_errors':snapshot['errors']},snapshot)
    s.commit();return evidence_view(row,value)


@app.put('/api/compliance/audits/{identity}/items/{item_id}/review')
def review_item(identity:str,item_id:str,body:ReviewIn,u:User=Depends(permit(*EDIT)),s:Session=Depends(db)):
    audit=open_audit(s,u,identity);row=get(s,u.tenant_id,item_id,ITEM);value=data(row)
    if value['audit_id']!=identity:raise HTTPException(404,'Audit safeguard not found')
    if row.version!=body.version:raise HTTPException(409,'Safeguard review changed; refresh before retrying')
    if body.effectiveness in ('passed','failed') or body.applicability=='not_applicable':
        require_control_independence(s,u,[value])
    selected={}
    for eid in set(body.evidence_ids)|{x.evidence_id for x in body.check_refs}:
        record=get(s,u.tenant_id,eid,EVIDENCE);item=data(record)
        if item.get('audit_id')!=identity:raise HTTPException(422,'Evidence belongs to another audit')
        selected[eid]=item
    checks=[]
    for ref in body.check_refs:
        item=selected[ref.evidence_id];check=next((x for x in item.get('checks',[]) if x['id']==ref.check_id),None)
        if check is None:raise HTTPException(422,'Unknown technical check reference')
        checks.append(check)
    if body.applicability=='not_applicable':
        if not selected:raise HTTPException(422,'Not-applicable scope exclusions require recorded supporting evidence')
        if body.implementation!='not_applicable' or body.effectiveness!='not_applicable':raise HTTPException(422,'Not-applicable safeguards require matching dimension states')
    elif body.implementation=='not_applicable' or body.effectiveness=='not_applicable':raise HTTPException(422,'Applicable or undetermined safeguards cannot hide a dimension as not applicable')
    if (body.effectiveness in ('passed','failed') or body.applicability=='not_applicable') and any(item.get('trust')=='operator_submitted' for item in selected.values()) and (not body.source_provenance_verified or len(body.provenance_notes.strip())<20):raise HTTPException(422,'Verify and document provenance of operator-submitted evidence before a conclusive decision')
    if body.effectiveness in ('passed','failed'):
        if body.applicability!='applicable' or not selected:raise HTTPException(422,'A tested outcome requires applicable scope and recorded evidence')
        if body.effectiveness=='passed' and body.implementation!='implemented':raise HTTPException(422,'Effectiveness cannot pass while implementation is partial, absent or unknown')
        if any(item.get('trust')=='operator_submitted' for item in selected.values()) and (not body.source_provenance_verified or len(body.provenance_notes.strip())<20):raise HTTPException(422,'Verify and document provenance of operator-submitted evidence before recording a tested outcome')
        if body.method=='technical_observation':
            for evidence in selected.values():
                try:age=(utc()-datetime.fromisoformat(evidence['collected_at'].replace('Z','+00:00'))).total_seconds()
                except (ValueError,KeyError,TypeError):raise HTTPException(422,'Technical evidence needs a valid observation timestamp') from None
                if age>30*86400:raise HTTPException(422,'Technical evidence is older than 30 days; collect current observations')
            if not checks or not any(x['dimension']=='effectiveness' for x in checks):raise HTTPException(422,'Configuration-only checks cannot establish effectiveness; record an operating test or reviewed manual evidence')
            if body.effectiveness=='passed' and any(x['result']!='passed' for x in checks):raise HTTPException(422,'Failed, missing or insufficient technical observations cannot be recorded as passed')
            if body.effectiveness=='failed' and not any(x['result']=='failed' for x in checks):raise HTTPException(422,'A failed technical conclusion requires a failed referenced check')
        elif not body.evidence_ids:raise HTTPException(422,'Manual review requires recorded evidence references')
    touch(s,audit);review=body.model_dump(exclude={'version'});review.update(reviewed_by=u.id,reviewed_at=utc().isoformat())
    value['review']=review;touch(s,row,value,state='reviewed');log(s,u,'compliance.safeguard.review',item_id,{'audit_id':identity,'applicability':body.applicability,'implementation':body.implementation,'effectiveness':body.effectiveness,'method':body.method,'evidence_ids':sorted(selected),'version':row.version});s.commit()
    return {'id':row.id,'version':row.version,'review':review,'audit_version':audit.version}


@app.post('/api/compliance/audits/{identity}/finalize')
def finalize_audit(identity:str,body:FinalizeIn,u:User=Depends(permit('tenant_admin','auditor')),s:Session=Depends(db)):
    audit=open_audit(s,u,identity)
    from . import main
    if not main.AUDIT_HMAC_KEY:raise HTTPException(503,'Audit signing must be configured before independent finalization')
    if audit.created_by==u.id:raise HTTPException(409,'Independent final review requires a different reviewer from the audit creator')
    if body.version!=audit.version:raise HTTPException(409,'Audit changed; refresh before final review')
    if not body.catalogue_complete_attested:raise HTTPException(422,'Compare the imported catalogue against each complete source standard before attesting coverage')
    value=report(s,u,identity)
    require_control_independence(s,u,value['items'])
    if value['source_catalogue_changed']:raise HTTPException(409,'Source catalogue changed. Create a new audit snapshot and review the current safeguards.')
    if any(frame['requirement_count']==0 for frame in value['frameworks']):raise HTTPException(422,'A selected framework has no imported requirements; full standard coverage cannot be attested')
    unresolved=[item['id'] for item in value['items'] if not item.get('review') or item['review']['applicability']=='undetermined' or (item['review']['applicability']=='applicable' and (item['review']['implementation']=='unknown' or item['review']['effectiveness'] not in ('passed','failed')))]
    if unresolved:raise HTTPException(422,{'message':'Audit has untested or unresolved safeguards; completion is blocked','unresolved_count':len(unresolved)})
    for eid in set(body.completeness_evidence_ids):
        evidence=data(get(s,u.tenant_id,eid,EVIDENCE))
        if evidence.get('audit_id')!=identity:raise HTTPException(422,'Completeness evidence belongs to another audit')
    values=data(audit);values.update(catalogue_complete_attested=True,completeness_statement=body.completeness_statement,completeness_evidence_ids=sorted(set(body.completeness_evidence_ids)),finalized_by=u.id,finalized_at=utc().isoformat(),conclusion='no_applicable_safeguards_in_reviewed_scope' if not value['counts']['applicable'] else 'findings_present' if value['counts']['effectiveness_failed'] or value['counts']['not_implemented'] or value['counts']['partial'] else 'reviewed_evidence_supports_scoped_safeguards')
    values['review_snapshot_sha256']=final_digest(audit,values,value['items'],value['evidence'])
    touch(s,audit,values,state='finalized');log(s,u,'compliance.audit.finalize',identity,{'review_snapshot_sha256':values['review_snapshot_sha256'],'catalogue_sha256':values['catalogue_sha256'],'conclusion':values['conclusion'],'safeguards':len(value['items']),'creator':audit.created_by})
    # Build the scoped response before commit clears transaction-local PostgreSQL RLS context.
    response=report(s,u,identity)
    s.commit()
    return response


@app.get('/api/compliance/audits/{identity}/export/{format}')
def export_audit(identity:str,format:Literal['json','csv','pdf'],u:User=Depends(principal),s:Session=Depends(db)):
    value=report(s,u,identity);log(s,u,'compliance.audit.export',identity,{'format':format,'state':value['state'],'safeguards':len(value['items'])});s.commit()
    if format=='json':raw=json.dumps(value,sort_keys=True,indent=2,ensure_ascii=False).encode();mime='application/json'
    elif format=='csv':
        stream=io.StringIO();writer=csv.writer(stream);columns=['framework','revision','reference','source_kind','applicability','implementation','effectiveness','method','procedure','observations','reason','reviewed_by','reviewed_at','evidence_ids'];writer.writerow(columns)
        for item in value['items']:
            source=item['source'];review=item.get('review') or {};row=[source['framework_name'],source['framework_revision'],source['reference'],source['source_kind']]+[review.get(k,'not_reviewed') for k in columns[4:]]
            writer.writerow(["'"+str(x) if str(x).lstrip().startswith(('=','+','-','@','\t','\r')) else str(x) for x in row])
        raw=stream.getvalue().encode();mime='text/csv'
    else:
        from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.pagesizes import A4
        styles=getSampleStyleSheet();stream=io.BytesIO();story=[Paragraph('LexiGrid compliance audit',styles['Title']),Paragraph(escape(value['title']),styles['Heading1']),Paragraph('Shahryar Jahangir / Aniza Inc.',styles['Normal']),Paragraph(escape(value['notice']),styles['Normal'])]
        for label,text in [('State',value['state']),('Final snapshot integrity',value['integrity_status']),('Scope',value['scope']),('Coverage counts',json.dumps(value['counts'])),('Conclusion',value.get('conclusion') or 'Audit incomplete — untested items are not passed'),('Catalogue changed',str(value['source_catalogue_changed'])),('Review snapshot SHA-256',value.get('review_snapshot_sha256','Not finalized'))]:story.extend([Spacer(1,8),Paragraph(escape(label+': '+text),styles['Normal'])])
        for item in value['items']:
            source=item['source'];review=item.get('review') or {};story.extend([Spacer(1,12),Paragraph(escape(source['framework_name']+' / '+source['reference']),styles['Heading2'])])
            for label,text in [('Source safeguard',source['text']),*review.items()]:
                # Split long source/procedure text so a single paragraph cannot exceed a page.
                text=str(text)
                for start in range(0,max(1,len(text)),2500):story.append(Paragraph(escape((str(label)+': ' if start==0 else '')+text[start:start+2500]).replace('\n','<br/>'),styles['Normal']))
        SimpleDocTemplate(stream,pagesize=A4,title='LexiGrid compliance audit',author='Shahryar Jahangir / Aniza Inc.').build(story);raw=stream.getvalue();mime='application/pdf'
    return Response(raw,media_type=mime,headers={'Content-Disposition':f'attachment; filename="lexigrid-compliance-audit-{identity}.{format}"','Cache-Control':'no-store'})

@app.get('/api/compliance/collectors/active-directory.ps1')
def download_collector(u:User=Depends(principal)):
    from pathlib import Path
    path=Path(__file__).resolve().parents[1]/'scripts/audit/Collect-LexiGridAD.ps1'
    return Response(path.read_bytes(),media_type='application/octet-stream',headers={'Content-Disposition':'attachment; filename="Collect-LexiGridAD.ps1"','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})
