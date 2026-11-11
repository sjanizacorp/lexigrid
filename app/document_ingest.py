"""Tenant-scoped governance document staging; no unreviewed text is published.
Author: Shahryar Jahangir, Aniza Inc.
"""
import io, hashlib
from zipfile import ZipFile
from fastapi import UploadFile, File, Form, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from .main import app, db, permit, User, log, emit_event, uid
from .governance_records import Framework, Requirement

MAX_DOCUMENT_BYTES = 8_000_000
MAX_TEXT_CHARS = 2_000_000
MAX_PDF_PAGES = 1000
MAX_PDF_LAYOUT_CHARS = 64 * 1024 * 1024
MAX_DOCX_EXPANDED_BYTES = 64 * 1024 * 1024
MAX_DOCX_ENTRIES = 2000
def _text_size(text, layout=False):
    # Layout-mode spaces describe coordinates, not additional source content.
    return len(" ".join(text.split())) if layout else len(text)


def _join_text(parts, layout=False):
    lines = []
    length = 0
    raw_length = 0
    for part in parts:
        raw_length += len(part) + bool(lines)
        if layout and raw_length > MAX_PDF_LAYOUT_CHARS:
            raise HTTPException(413, "PDF layout expansion exceeds its resource limit. Choose a smaller PDF page range.")
        length += _text_size(part, layout) + bool(lines)
        if length > MAX_TEXT_CHARS:
            raise HTTPException(413, 'Extracted document text exceeds limit')
        lines.append(part)
    return '\n'.join(lines)


def extract_blocks(data: bytes, filename: str, page_start=None, page_end=None, metadata=None):
    ext=filename.lower().rsplit('.',1)[-1] if '.' in filename else ''
    blocks=[]
    text_length=0
    def append(text,location,**metadata):
        nonlocal text_length
        text_length += _text_size(text, metadata.get('layout', False)) + bool(blocks)
        if text_length > MAX_TEXT_CHARS:
            raise HTTPException(413,'Extracted text exceeds 2 million characters. Choose a smaller PDF page range or split the source document.')
        blocks.append({'text':text,'location':location,**metadata})
    try:
        if ext=='pdf':
            from pypdf import PdfReader
            reader=PdfReader(io.BytesIO(data),strict=True)
            total=len(reader.pages)
            start=page_start if page_start is not None else 1
            end=page_end if page_end is not None else total
            if not total:raise HTTPException(422,'PDF contains no pages')
            if type(start) is not int or type(end) is not int or not 1 <= start <= end <= total:
                raise HTTPException(422,f'Choose a valid PDF page range from 1 to {total}.')
            if end-start+1 > MAX_PDF_PAGES:
                raise HTTPException(413,f'PDF has {total} pages. Extract up to {MAX_PDF_PAGES} pages at a time using PDF start/end pages; no pages were processed.')
            if metadata is not None:metadata.update(total_pages=total,page_start=start,page_end=end,partial_document=start!=1 or end!=total)
            from .iso27001_ingest import matches as iso27001_matches
            plain_pages=[];plain_length=0
            for index in range(start-1,end):
                text=reader.pages[index].extract_text() or ''
                plain_length+=len(text)+1
                if metadata is not None:metadata['plain_text_characters']=plain_length
                if plain_length>MAX_TEXT_CHARS:raise HTTPException(413,'Extracted text exceeds 2 million characters. Choose a smaller PDF page range.')
                plain_pages.append(text)
            # Justified ISO text is damaged by layout-mode word spacing. Use
            # its content stream order and an explicit standard profile instead.
            from .nist80053_ingest import matches as nist_matches,CATALOGUE
            nist_profile=nist_matches(plain_pages if start==1 else [reader.pages[i].extract_text() or '' for i in range(min(3,total))])
            from .cjis_ingest import identity as cjis_identity
            cjis_version=cjis_identity(plain_pages if start==1 else [reader.pages[i].extract_text() or '' for i in range(min(3,total))])
            profile=iso27001_matches(plain_pages)
            layout_length=0
            for page_number in range(start,end+1):
                page=reader.pages[page_number-1]
                text=plain_pages[page_number-start] if profile or nist_profile or cjis_version else (page.extract_text(extraction_mode='layout',layout_mode_space_vertically=False) or '')
                layout_length += len(text)
                if metadata is not None:metadata["layout_characters"]=layout_length
                if layout_length > MAX_PDF_LAYOUT_CHARS:
                    raise HTTPException(413,'PDF layout expansion exceeds its resource limit. Choose a smaller PDF page range.')
                for line_number,line in enumerate(text.splitlines(),1):
                    append(line,f'Page {page_number}, line {line_number}',layout=not (profile or nist_profile or cjis_version),
                           profile='cjis_security_policy' if cjis_version else 'nist80053_rev5' if nist_profile else 'iso27001_2022' if profile else None,
                           publication_version=cjis_version,
                           nist_catalogue=bool(CATALOGUE.search(plain_pages[page_number-start])) if nist_profile else False)
        elif page_start is not None or page_end is not None:
            raise HTTPException(422,'Page ranges apply only to PDF files.')
        elif ext=='docx':
            from docx import Document
            from docx.table import Table
            with ZipFile(io.BytesIO(data)) as archive:
                entries=archive.infolist()
                if len(entries)>MAX_DOCX_ENTRIES or sum(item.file_size for item in entries)>MAX_DOCX_EXPANDED_BYTES:
                    raise HTTPException(413,'DOCX exceeds archive expansion limits')
            doc=Document(io.BytesIO(data))
            for index,item in enumerate(doc.iter_inner_content(),1):
                if isinstance(item,Table):
                    for row_number,row in enumerate(item.rows,1):
                        cells=[];seen=set()
                        for cell in row.cells:
                            cells.append(cell.text if cell._tc not in seen else '')
                            seen.add(cell._tc)
                        append('\t'.join(cells),f'Block {index}, table row {row_number}',cells=cells,table=index)
                else:
                    append(item.text,f'Block {index}',heading=item.style.name.startswith('Heading') if item.style else False)
        elif ext=='txt':
            for index,line in enumerate(data.decode('utf-8-sig').splitlines(),1):append(line,f'Line {index}')
        else:raise HTTPException(415,'Supported formats: PDF, DOCX, TXT')
    except HTTPException:raise
    except Exception as exc:raise HTTPException(422,'Unable to extract text from document') from exc
    if metadata is not None:metadata['content_characters']=text_length
    if any('\x00' in block['text'] for block in blocks):raise HTTPException(422,'Document text contains a NUL character')
    if not any(block['text'].strip() for block in blocks):raise HTTPException(422,'No extractable text. Scanned documents require OCR before upload')
    return blocks


def extract_text(data: bytes, filename: str) -> str:
    blocks=extract_blocks(data,filename)
    return _join_text((block['text'] for block in blocks),layout=any(block.get('layout') for block in blocks))


def candidates(text: str):
    from .document_parser import parse_candidates
    return parse_candidates([{'text':line,'location':f'Line {index}'}
                             for index,line in enumerate(text.splitlines(),1)],'requirements')


async def extraction(file,kind,page_start=None,page_end=None):
    from .document_parser import parse_candidates
    filename=(file.filename or '')[:200]
    data=await file.read(MAX_DOCUMENT_BYTES+1)
    if len(data)>MAX_DOCUMENT_BYTES:raise HTTPException(413,'Document exceeds 8 MB')
    metadata={}
    try:
        blocks=extract_blocks(data,filename,page_start,page_end,metadata)
    except HTTPException as exc:
        emit_event('operations','document.extraction.rejected',outcome='failure',kind=kind,status=exc.status_code,**metadata)
        raise
    diagnostics=[]
    items=parse_candidates(blocks,kind,diagnostics)
    if not items and not diagnostics:diagnostics.append(
        "No candidates matched this record type. Check the chosen type, source layout and whether OCR is needed.")
    if metadata.get('partial_document'):diagnostics.insert(0,f"Partial document: pages {metadata['page_start']}-{metadata['page_end']} of {metadata['total_pages']}. Other pages were not assessed. Repeat extraction for the remaining page ranges after importing this review.")
    profile=next((b.get('profile') for b in blocks if b.get('profile')),None)
    return {**metadata,'filename':filename,'sha256':hashlib.sha256(data).hexdigest(),'kind':kind,
        'document_profile':{'cjis_security_policy':'FBI CJIS Security Policy','nist80053_rev5':'NIST SP 800-53 Rev. 5','iso27001_2022':'ISO/IEC 27001:2022'}.get(profile),
        'extraction_method':{'cjis_security_policy':'cjis_security_policy_structure_v1','nist80053_rev5':'nist80053_rev5_structure_v1','iso27001_2022':'iso27001_2022_structure_v1'}.get(profile,'source_order_structured_v2'),'candidate_count':len(items),'candidates':items,
        'warnings':['Review each candidate and source location before import. Extraction may omit content; scanned PDFs require OCR.',
                    'Missing metadata is left blank. No record is saved until explicitly reviewed and imported.',*diagnostics]}


@app.post('/api/documents/extract-requirements')
async def extract_requirements(file:UploadFile=File(...),page_start:int|None=Form(None,ge=1),page_end:int|None=Form(None,ge=1),u:User=Depends(permit('tenant_admin','risk_manager'))):
    result=await extraction(file,'requirements',page_start,page_end)
    emit_event('operations','document.extraction.completed',outcome='success',actor_id=u.id,tenant_id=u.tenant_id,kind='requirements',candidate_count=result['candidate_count'],source_sha256=result['sha256'],page_start=result.get('page_start'),page_end=result.get('page_end'),total_pages=result.get('total_pages'),plain_text_characters=result.get('plain_text_characters'),layout_characters=result.get('layout_characters'),content_characters=result.get('content_characters'))
    return result


@app.post('/api/documents/extract')
async def extract_records(kind:str=Form(...),file:UploadFile=File(...),
                          page_start:int|None=Form(None,ge=1),page_end:int|None=Form(None,ge=1),
                          u:User=Depends(permit('tenant_admin','risk_manager'))):
    result=await extraction(file,kind,page_start,page_end)
    emit_event('operations','document.extraction.completed',outcome='success',actor_id=u.id,tenant_id=u.tenant_id,kind=kind,candidate_count=result['candidate_count'],source_sha256=result['sha256'],page_start=result.get('page_start'),page_end=result.get('page_end'),total_pages=result.get('total_pages'),plain_text_characters=result.get('plain_text_characters'),layout_characters=result.get('layout_characters'),content_characters=result.get('content_characters'))
    return result


class ReviewedRequirement(BaseModel):
    reference:str=Field(min_length=1,max_length=120)
    text:str=Field(min_length=1,max_length=2000000)

    @field_validator('reference', 'text', mode='before')
    @classmethod
    def validate_text(cls, value):
        if isinstance(value, str):
            if '\x00' in value:
                raise ValueError('NUL characters are not allowed')
            return value.strip()
        return value


class ReviewedBatch(BaseModel):
    framework_id:str
    source_sha256:str=Field(pattern=r'^[0-9a-f]{64}$')
    requirements:list[ReviewedRequirement]=Field(min_length=1)

@app.post('/api/documents/import-reviewed-requirements')
def import_reviewed(body:ReviewedBatch,u:User=Depends(permit('tenant_admin','risk_manager')),s:Session=Depends(db)):
    emit_event('operations','document.import.requested',outcome='info',actor_id=u.id,tenant_id=u.tenant_id,kind='requirements',selected_count=len(body.requirements),source_sha256=body.source_sha256)
    framework=s.scalar(select(Framework).where(Framework.id==body.framework_id,Framework.tenant_id==u.tenant_id))
    if not framework:raise HTTPException(404,'Framework not found in this tenant')
    keys=[r.reference for r in body.requirements]
    if len(keys)!=len(set(keys)):raise HTTPException(422,'Duplicate references in batch')
    existing=set()
    for offset in range(0,len(keys),500):existing.update(s.scalars(select(Requirement.reference).where(Requirement.tenant_id==u.tenant_id,Requirement.framework_id==framework.id,Requirement.reference.in_(keys[offset:offset+500]))))
    if existing:raise HTTPException(409,{'message':'Existing requirements; nothing imported','references':sorted(existing)})
    try:
        for item in body.requirements:
            record=Requirement(tenant_id=u.tenant_id,framework_id=framework.id,reference=item.reference,text=item.text)
            s.add(record);s.flush()
            log(s,u,'document.requirement.import',record.id,{'source_sha256':body.source_sha256,'framework_id':framework.id,'reference':item.reference,'reviewed':True})
        s.commit()
    except IntegrityError as exc:
        s.rollback()
        raise HTTPException(409, 'Requirement import conflicts with existing records; nothing imported') from exc
    except Exception:
        s.rollback();raise
    emit_event('operations','document.import.completed',outcome='success',actor_id=u.id,tenant_id=u.tenant_id,kind='requirements',created=len(body.requirements),framework_id=framework.id,source_sha256=body.source_sha256)
    return {'created':len(body.requirements),'framework_id':framework.id,'source_sha256':body.source_sha256,'destination':{'kind':'requirements','page':'Frameworks','framework_id':framework.id}}


class ReviewedRecords(BaseModel):
    kind:str=Field(pattern='^(controls|frameworks|policies)$')
    source_sha256:str=Field(pattern=r'^[0-9a-f]{64}$')
    items:list[dict]=Field(min_length=1)
    default_owner:str=Field(default='',max_length=200)

    @field_validator('default_owner',mode='before')
    @classmethod
    def owner_text(cls,value):
        if isinstance(value,str):
            if '\x00' in value:raise ValueError('NUL characters are not allowed')
            return value.strip()
        return value


@app.post('/api/documents/import-reviewed')
def import_reviewed_records(body:ReviewedRecords,u:User=Depends(permit('tenant_admin','risk_manager')),
                            s:Session=Depends(db)):
    from pydantic import ValidationError
    from .governance_records import BULK_SCHEMAS
    from .document_parser import FIELDS
    model,entity,_=BULK_SCHEMAS[body.kind]
    emit_event('operations','document.import.requested',outcome='info',actor_id=u.id,tenant_id=u.tenant_id,kind=body.kind,selected_count=len(body.items),source_sha256=body.source_sha256)
    from .control_import import existing_ids,insert_once
    if body.default_owner and body.kind not in ('controls','policies'):raise HTTPException(422,'Default owner applies only to controls and policies')
    valid=[];seen=set();skipped=[]
    existing=existing_ids(s,u.tenant_id,[raw.get('code','').strip() for raw in body.items if isinstance(raw.get('code',''),str)]) if body.kind=='controls' else {}
    for index,raw in enumerate(body.items,1):
        if set(raw)-set(FIELDS[body.kind]):
            raise HTTPException(422,f'Unsupported fields in reviewed item {index}')
        if any(not isinstance(value,str) or '\x00' in value for value in raw.values()):
            raise HTTPException(422,f'Invalid text in reviewed item {index}')
        normalized={key:value.strip() for key,value in raw.items()}
        if body.kind=='controls':
            code=normalized.get('code','')
            if code in existing or (code,) in seen:
                skipped.append({'item':index,'code':code,'reason':'already_exists' if code in existing else 'duplicate_in_batch'})
                continue
        if body.kind in ('controls','policies') and not normalized.get('owner'):normalized['owner']=body.default_owner
        try:
            values=model.model_validate(normalized).model_dump()
        except ValidationError as exc:
            raise HTTPException(422,{'message':'Review invalid or missing fields; nothing imported',
                                     'item':index,'errors':[{'field':'.'.join(map(str,e['loc'])),
                                                            'message':e['msg']} for e in exc.errors()]}) from exc
        key=(values['name'],values['revision']) if body.kind=='frameworks' else (values['code'],)
        if key in seen:raise HTTPException(422,'Duplicate identifiers in reviewed batch; nothing imported')
        seen.add(key)
        query=select(entity.id).where(entity.tenant_id==u.tenant_id)
        if body.kind=='frameworks':query=query.where(entity.name==key[0],entity.revision==key[1])
        else:query=query.where(entity.code==key[0])
        if body.kind!='controls' and s.scalar(query):raise HTTPException(409,'Record already exists in this tenant; nothing imported')
        valid.append((index,values))
    created=0
    try:
        for index,values in valid:
            if body.kind=='controls':
                identity=insert_once(s,u.tenant_id,values)
                if identity is None:
                    skipped.append({'item':index,'code':values['code'],'reason':'already_exists'});continue
                created+=1
                log(s,u,'document.controls.import',identity,{'source_sha256':body.source_sha256,'reviewed':True,'identifier':values['code']})
                continue
            record=entity(tenant_id=u.tenant_id,**values)
            s.add(record);s.flush()
            created+=1
            log(s,u,f'document.{body.kind}.import',record.id,{
                'source_sha256':body.source_sha256,'reviewed':True,
                'identifier':values.get('code',values.get('name'))})
        if body.kind=='controls':
            for skip in skipped:log(s,u,'document.controls.import.skipped',uid(),{'source_sha256':body.source_sha256,**skip})
        s.commit()
    except IntegrityError as exc:
        s.rollback();raise HTTPException(409,'Import conflicts with existing records; nothing imported') from exc
    except Exception:
        s.rollback();raise
    emit_event('operations','document.import.completed',outcome='success',actor_id=u.id,tenant_id=u.tenant_id,kind=body.kind,created=created,skipped_count=len(skipped),source_sha256=body.source_sha256)
    return {**({'skipped_count':len(skipped),'skipped':skipped} if body.kind=='controls' else {}),'created':created,'kind':body.kind,'source_sha256':body.source_sha256,'destination':{'kind':body.kind,'page':{'controls':'Controls','frameworks':'Frameworks','policies':'Policies'}[body.kind]}}
