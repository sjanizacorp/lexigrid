"""Independent remediation closure using existing tests, files and audit records.

Author: Shahryar Jahangir, Aniza Inc. No schema migration or historical rewrite.
"""
import json
import hmac
from datetime import timezone

from fastapi import Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .main import app, Audit, User, db, principal, utc
from .governance_records import Finding, ControlTest, EvidenceBlob, owned, download_evidence_file
from .approval_records import Remediation


def aware(value):
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def review_context(s, u, r):
    finding=owned(s,Finding,r.finding_id,u.tenant_id)
    events=s.scalars(select(Audit).where(Audit.tenant_id==u.tenant_id,
        Audit.object_id==r.id,Audit.action.in_(('remediation.create','remediation.transition')))
        .order_by(Audit.at,Audit.id)).all()
    creators={e.actor_id for e in events if e.action=='remediation.create'}
    from . import main
    for event in events:
        if event.integrity_mac:
            if not main.AUDIT_HMAC_KEY:
                raise HTTPException(409,'Signed remediation history cannot be verified; restore audit signing before closure')
            expected=main.audit_digest(event.tenant_id,event.actor_id,event.action,event.object_id,event.details,event.at)
            if not hmac.compare_digest(event.integrity_mac,expected):
                raise HTTPException(409,'Remediation history integrity failed; closure requires investigation')
    performers=set(creators)
    ready=None
    for event in events:
        if event.action!='remediation.transition':continue
        try:payload=json.loads(event.details)
        except (ValueError,TypeError):raise HTTPException(409,'Remediation history is invalid; closure requires investigation')
        if not isinstance(payload,dict):raise HTTPException(409,'Remediation history is invalid; closure requires investigation')
        if payload.get('state')!='closed':performers.add(event.actor_id)
        if payload.get('state')=='ready_for_review' and payload.get('version')==r.version-1:
            ready=aware(event.at)
    independent=bool(creators) and u.id not in performers and r.owner.strip().casefold() not in {u.id.casefold(),u.email.casefold()}
    return finding,performers,ready,independent


@app.get('/api/remediations/{rid}/closure-context')
def closure_context(rid:str,u:User=Depends(principal),s:Session=Depends(db)):
    r=owned(s,Remediation,rid,u.tenant_id)
    finding,performers,ready,independent=review_context(s,u,r)
    tests=s.scalars(select(ControlTest).where(ControlTest.tenant_id==u.tenant_id,
        ControlTest.control_id==finding.control_id).order_by(ControlTest.tested_at.desc(),ControlTest.id)).all()
    # Listing choices must not load every encrypted attachment into memory.
    files=s.execute(select(EvidenceBlob.id,EvidenceBlob.filename,EvidenceBlob.sha256,EvidenceBlob.submitted_at).where(
        EvidenceBlob.tenant_id==u.tenant_id,EvidenceBlob.control_id==finding.control_id)
        .order_by(EvidenceBlob.submitted_at.desc(),EvidenceBlob.id)).all()
    now=utc()
    return {'remediation_id':r.id,'version':r.version,'control_id':finding.control_id,
        'can_review':independent and u.role in ('tenant_admin','auditor','platform_admin'),
        'ready_at':ready,'tests':[{'id':t.id,'result':t.result,'procedure':t.procedure,'tested_at':t.tested_at,
            'eligible':bool(ready and ready<=aware(t.tested_at)<=now and t.result=='pass' and t.tester_id not in performers)} for t in tests],
        'evidence_files':[{'id':f.id,'filename':f.filename,'sha256':f.sha256,'submitted_at':f.submitted_at,
            'eligible':bool(ready and ready<=aware(f.submitted_at)<=now)} for f in files],
        'notice':'Closure requires an independent reviewer, a passing independent retest recorded after readiness, '
                 'and 1–5 supporting files uploaded after readiness. Select files that substantiate the retest; '
                 'their availability and hashes are verified during closure. A stored pass is an operator observation, '
                 'not independent proof that a technical test was performed.'}


def validate_closure(s,u,r,body):
    finding,performers,ready,independent=review_context(s,u,r)
    if not independent:raise HTTPException(403,'The remediation creator, recorded participants and named owner cannot approve closure')
    if ready is None:raise HTTPException(409,'Current readiness history is missing; closure requires investigation')
    if not body.retest_id or not body.evidence_ids:raise HTTPException(422,'Select a passing independent retest and supporting evidence files before closing')
    if len(body.evidence_ids)!=len(set(body.evidence_ids)):raise HTTPException(422,'Select each evidence file once')
    test=owned(s,ControlTest,body.retest_id,u.tenant_id)
    if test.control_id!=finding.control_id:raise HTTPException(422,'Retest must belong to the finding control')
    if test.result!='pass':raise HTTPException(422,'Retest must have a passing result')
    if test.tester_id in performers:raise HTTPException(403,'Retest must be performed independently of the remediation work')
    now=utc()
    if not ready<=aware(test.tested_at)<=now:raise HTTPException(422,'Retest must be recorded after the current readiness submission')
    files=[]
    for eid in body.evidence_ids:
        record=owned(s,EvidenceBlob,eid,u.tenant_id)
        if record.control_id!=finding.control_id:raise HTTPException(422,'Evidence must belong to the finding control')
        if not ready<=aware(record.submitted_at)<=now:raise HTTPException(422,'Upload supporting evidence after the current readiness submission')
        download_evidence_file(eid,u,s)  # Existing authenticated decryption and SHA-256 verification.
        files.append({'id':eid,'sha256':record.sha256})
    return {'retest_id':test.id,'result':test.result,'tested_at':test.tested_at,
            'tester_id':test.tester_id,'evidence_files':files,'reviewer_id':u.id,'ready_at':ready,
            'attestation':body.note}
