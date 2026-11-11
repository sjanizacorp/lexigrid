"""Source-preserving governance candidates; explicit review is always required.
Author: Shahryar Jahangir, Aniza Inc.
"""
import re
from collections import Counter
from fastapi import HTTPException

REF = re.compile(r'^\s*(?:(?:control|requirement)\s+)?((?:[A-Z]{1,8}[.-])*[A-Z]{0,8}\d+(?:[.-]\d+){0,6}(?:\(\d+\))?)(?:\s+|[.):]\s+|\s*[-:]\s*)(.*)$',re.I)
OBLIGATION = re.compile(r'\b(must|shall|should|required|will ensure)\b',re.I)
FIELDS = {'requirements':('reference','text'), 'controls':('code','title','description','owner'),
          'frameworks':('name','revision'), 'policies':('code','title','body','owner')}
ALIASES = {
 'code':{'code','id','control id','control identifier','control code','policy id','policy code','reference','ref'},
 'reference':{'reference','ref','requirement id','clause','clause id','control id','code','id'},
 'title':{'title','name','control title','control name','policy title','policy name'},
 'description':{'description','control description','control statement','statement','requirement','text'},
 'text':{'text','requirement','requirement text','description','statement','control statement'},
 'body':{'body','policy text','policy body','text','description','statement'},
 'owner':{'owner','control owner','policy owner','responsible'},
 'name':{'name','framework','framework name','standard','standard name'},
 'revision':{'revision','version','edition'},
}


def normalized(value):
    return ' '.join(value.split())


def parse_candidates(blocks,kind,diagnostics=None):
    if kind not in FIELDS:raise HTTPException(422,'Unsupported document record type')
    if any(block.get('profile')=='cjis_security_policy' for block in blocks):
        from .cjis_ingest import parse
        return parse(blocks,kind,diagnostics)
    if any(block.get('profile')=='nist80053_rev5' for block in blocks):
        from .nist80053_ingest import parse
        return parse(blocks,kind,diagnostics)
    if any(block.get('profile')=='iso27001_2022' for block in blocks):
        from .iso27001_ingest import parse
        return parse(blocks,kind,diagnostics)
    results=[];current=None;table_header=None;table_id=None;used_table=False;columns=None
    def add(values,location,warnings=None):
        results.append({**{field:values.get(field,'') for field in FIELDS[kind]},
            'source_location':location,'confidence':'source_match','review_required':True,
            'warnings':warnings or []})
    def flush():
        nonlocal current
        if current is not None:
            ref,title,parts,location=current
            text='\n'.join(parts).strip()
            if kind=='requirements' and OBLIGATION.search(title+' '+text):
                add({'reference':ref,'text':(title+'\n'+text).strip()},location)
            elif kind=='controls':
                add({'code':ref,'title':title if text else '',
                     'description':text or title,'owner':''},location,
                    ['Owner was not inferred. Review title and description against the source.'])
        current=None
    for block in blocks:
        text=block['text'].strip()
        if re.fullmatch(r'(?:page\s+)?\d+\s*(?:of|/)\s*\d+',text,re.I):continue
        cells=block.get('cells')
        if block.get('layout') and columns and table_header and text:
            raw=block['text']
            cells=[raw[start:columns[i+1] if i+1<len(columns) else None].strip()
                   for i,start in enumerate(columns)]
        # DOCX cells and PDF/TXT aligned columns are mapped by their headers,
        # never appended after the rest of the document or joined by position alone.
        if cells is None and re.search(r'\S\s{2,}\S',text):
            cells=re.split(r'\s{2,}|\t+',text)
        if block.get('table')!=table_id:
            table_header=None;columns=None;table_id=block.get('table')
        if cells and len(cells)>1:
            header={}
            for field in FIELDS[kind]:
                indexes=[i for i,cell in enumerate(cells) if normalized(cell).lower().rstrip(':') in ALIASES[field]]
                if len(indexes)==1:header[field]=indexes[0]
            required={'requirements':{'reference','text'},'controls':{'code','description'},
                      'policies':{'code','body'},'frameworks':{'name','revision'}}[kind]
            if required<=header.keys():
                flush();table_header=header;used_table=True
                if block.get('layout'):
                    columns=[match.start() for match in re.finditer(r'\S.*?(?=\s{2,}|$)',block['text'])]
                continue
            if table_header:
                flush()
                values={field:cells[index].strip() if index<len(cells) else ''
                        for field,index in table_header.items()}
                identifier='reference' if kind=='requirements' else 'name' if kind=='frameworks' else 'code'
                if block.get('layout') and not values.get(identifier) and results:
                    continuation='description' if kind=='controls' else 'text' if kind=='requirements' else 'body'
                    if continuation in values and values[continuation]:
                        results[-1][continuation]+='\n'+values[continuation]
                        continue
                if any(values.values()):add(values,block['location'])
                continue
        if cells:
            # Unrecognized table layout is preserved as one source block for
            # policy/framework review, rather than assigning arbitrary columns.
            if diagnostics is not None and len(diagnostics)<30:
                diagnostics.append('Unmapped table or aligned columns at '+block['location']+'. Compare this content manually; it was not assigned to record fields.')
            flush();continue
        if not text:continue
        table_header=None
        if re.fullmatch(r'(?:page\s+)?\d+\s*(?:of|/)\s*\d+',text,re.I) or re.search(r'\.{3,}\s*\d+$',text):
            flush();continue
        match=REF.match(text)
        if match and current is not None and re.match(r'^\d+[.)]\s',text) and ('.' in current[0] or re.search(r'[A-Z]',current[0],re.I)):
            current[2].append(text);continue
        if match and kind in ('requirements','controls'):
            flush();current=(match.group(1),match.group(2),[],block['location'])
        elif current is not None:
            if block.get('heading'):
                flush()
            else:current[2].append(text)
    flush()
    if kind in ('frameworks','policies') and not used_table:
        texts=[b['text'].strip() for b in blocks if b['text'].strip()]
        metadata={}
        labels={'framework':'name','framework name':'name','standard':'name','name':'name',
                'revision':'revision','version':'revision','edition':'revision',
                'policy id':'code','policy code':'code','code':'code','policy title':'title',
                'title':'title','owner':'owner','policy owner':'owner'}
        for text in texts:
            match=re.match(r'^([A-Za-z ]{2,30})\s*:\s*(.+)$',text)
            if match and match.group(1).lower() in labels:
                metadata.setdefault(labels[match.group(1).lower()],match.group(2).strip())
        if texts:
            values=({'name':metadata.get('name',texts[0]),'revision':metadata.get('revision','')}
                    if kind=='frameworks' else {'code':metadata.get('code',''),
                        'title':metadata.get('title',texts[0]),'owner':metadata.get('owner',''),
                        'body':'\n'.join(texts)})
            add(values,blocks[0]['location'],['Document-level candidate. Supply missing metadata and review the complete source.'])
    key='reference' if kind=='requirements' else 'name' if kind=='frameworks' else 'code'
    counts=Counter(item[key] for item in results)
    for item in results:
        if item[key] and counts[item[key]]>1:
            item['warnings'].append('Repeated source identifier: occurrences were retained for review.')
        if any(not item[field] for field in FIELDS[kind]):
            item['warnings'].append('Required fields are missing; edit before importing.')
    return results
