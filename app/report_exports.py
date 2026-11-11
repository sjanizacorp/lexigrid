"""Attributed risk report exports. Shahryar Jahangir / Aniza Inc."""
import csv
import io
import re
from types import SimpleNamespace
from xml.sax.saxutils import escape
from fastapi import Depends,HTTPException,Query,Response
from fastapi.encoders import jsonable_encoder
from sqlalchemy import select
from sqlalchemy.orm import Session
from .main import app,principal,db,User,Tenant,risk_report,_set_platform_tenant_context,log

COLUMNS=['tenant_id','tenant_name','id','title','description','category','owner','likelihood','impact','score','status','version','created_at','updated_at','created_by','updated_by','approved_by','approval_status','approval_count','closed_by']


def render(items,kind):
    if kind=='csv':
        out=io.StringIO();writer=csv.writer(out);writer.writerow(COLUMNS)
        for item in items:
            writer.writerow([("'"+str(value) if isinstance(value,str) and value.lstrip().startswith(('=','+','-','@','\t','\r')) else value) for value in (item.get(key) for key in COLUMNS)])
        return out.getvalue().encode(),'text/csv'
    out=io.BytesIO()
    if kind=='xlsx':
        from openpyxl import Workbook
        from openpyxl.cell import WriteOnlyCell
        workbook=Workbook(write_only=True);sheet=workbook.create_sheet('Risks')
        sheet.append(COLUMNS)
        for item in items:
            cells=[]
            for key in COLUMNS:
                value=item.get(key)
                if hasattr(value,'isoformat'):value=value.isoformat()
                if isinstance(value,str):value=re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '\ufffd', value)
                cell=WriteOnlyCell(sheet,value=value)
                if isinstance(value,str):cell.data_type='s' # Never interpret user text as a formula.
                cells.append(cell)
            sheet.append(cells)
        workbook.save(out)
        return out.getvalue(),'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    if kind!='pdf':raise HTTPException(422,'Unsupported report format')
    from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.pagesizes import A4
    styles=getSampleStyleSheet();story=[Paragraph('LexiGrid risk report',styles['Title']),Paragraph('Shahryar Jahangir / Aniza Inc.',styles['Normal']),Spacer(1,12)]
    story.append(Paragraph(str(len(items))+' risk records. Attribution reflects recorded history; blank values are not proof that no action occurred.',styles['Normal']))
    for item in items:
        story.extend([Spacer(1,12),Paragraph(escape(str(item.get('title',''))),styles['Heading2'])])
        for key in COLUMNS:
            value=item.get(key)
            story.append(Paragraph(escape(key.replace('_',' ').title()+': '+('' if value is None else str(value))).replace('\n','<br/>'),styles['Normal']))
    SimpleDocTemplate(out,pagesize=A4,title='LexiGrid risk report',author='Shahryar Jahangir / Aniza Inc.').build(story)
    return out.getvalue(),'application/pdf'


def attachment(items,kind,prefix):
    content,mime=render(items,kind)
    return Response(content,media_type=mime,headers={'Content-Disposition':f'attachment; filename="{prefix}.{kind}"','Cache-Control':'no-store'})


@app.get('/api/reports/risks.xlsx')
def risk_xlsx(status:str|None=None,category:str|None=None,owner:str|None=None,u:User=Depends(principal),s:Session=Depends(db)):
    return attachment(risk_report(status,category,owner,u,s)['items'],'xlsx','lexigrid-risk-report')


@app.get('/api/reports/risks.pdf')
def risk_pdf(status:str|None=None,category:str|None=None,owner:str|None=None,u:User=Depends(principal),s:Session=Depends(db)):
    return attachment(risk_report(status,category,owner,u,s)['items'],'pdf','lexigrid-risk-report')


@app.get('/api/platform/reports/risks')
def platform_report(tenant_ids:list[str]=Query(...,min_length=1,max_length=50),format:str=Query('json',pattern='^(json|csv|xlsx|pdf)$'),u:User=Depends(principal),s:Session=Depends(db)):
    if u.role!='platform_admin':raise HTTPException(403,'Platform administrator required')
    selected=sorted(set(tenant_ids))
    tenants=s.scalars(select(Tenant).where(Tenant.id.in_(selected)).order_by(Tenant.id)).all()
    if len(tenants)!=len(selected):raise HTTPException(404,'Selected organization not found')
    items=[];actor_tenant=u.tenant_id;actor_id=u.id
    try:
        for tenant in tenants:
            _set_platform_tenant_context(s,tenant.id)
            report=risk_report(None,None,None,SimpleNamespace(tenant_id=tenant.id),s)
            items.extend({**item,'tenant_id':tenant.id,'tenant_name':tenant.name} for item in report['items'])
    finally:_set_platform_tenant_context(s,actor_tenant)
    # Record the explicit selection in the caller's audit partition before returning data.
    log(s,SimpleNamespace(id=actor_id,tenant_id=actor_tenant),'report.platform.export','risks',{'tenant_ids':selected,'format':format,'records':len(items)})
    s.commit()
    if format=='json':return jsonable_encoder({'total':len(items),'tenant_ids':selected,'items':items})
    return attachment(items,format,'lexigrid-platform-risk-report')
