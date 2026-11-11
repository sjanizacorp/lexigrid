"""Structural ISO/IEC 27001:2022 import profile; source text stays local.
Author: Shahryar Jahangir, Aniza Inc.
No licensed standard content is embedded in this module.
"""
import re

STANDARD = re.compile(r'ISO\s*/\s*IEC\s+27001\s*:\s*2022',re.I)
CLAUSE = re.compile(r'^((?:[4-9]|10)(?:\.\d+){0,3})\s+(.+)$')
CONTROL = re.compile(r'^([5-8]\.\d{1,2})\s+(.+)$')
OBLIGATION = re.compile(r'\b(?:shall|must|should|required)\b',re.I)


def matches(pages):
    return (any(STANDARD.search(text) for text in pages[:3]) and
            any(re.search(r'^Annex\s+A\s*$',text,re.M) for text in pages))


def clean_line(text):
    text=text.strip().replace('\u00ad','')
    # Page furniture and publisher/watermark artifacts are not clauses.
    if (not text or STANDARD.fullmatch(text.replace('(E)','')) or
        re.match(r'^(?:\d*\s*©\s*ISO|ISO/IEC\s+27001:2022|Table\s+A\s*\.\s*1)',text,re.I) or
        re.fullmatch(r'[\d ivxlcdm]+',text,re.I) or
        (not re.search(r'[A-Za-z0-9]',text))):
        return ''
    return text


def join_lines(lines):
    # A source word split across a printed line ending is rejoined; semantic
    # in-line hyphens and list markers are retained.
    result=''
    for line in lines:
        if not result:result=line
        elif re.search(r'[A-Za-z]\s*-\s*$',result) and re.match(r'^[a-z]',line):
            result=re.sub(r'\s*-\s*$','',result)+line
        else:result+=' '+line
    return result.strip()


def parse(blocks,kind,diagnostics=None):
    location=next((b['location'] for b in blocks if STANDARD.search(b['text'])),'Source cover')
    if kind=='frameworks':
        return [{'name':'ISO/IEC 27001','revision':'2022','source_location':location,
                 'confidence':'standard_identifier','review_required':True,'warnings':[]}]
    if kind=='policies':
        if diagnostics is not None:
            diagnostics.append('This is a standards document, not an organization policy. Import its framework, requirements and Annex A controls; create your organization policies separately.')
        return []
    results=[];body=False;annex=False;current=None
    def flush():
        nonlocal current
        if current is None:return
        reference,heading,parts,start=current
        if kind=='controls':
            # Annex A titles may wrap over several source lines before the
            # bold Control column label. The label is a structural delimiter.
            title_parts=[heading];description=[];in_description=False
            for line in parts:
                if not in_description and re.search(r'Control\s*$',line):
                    before=re.sub(r'Control\s*$','',line).strip()
                    if before:title_parts.append(before)
                    in_description=True
                elif in_description:description.append(line)
                else:title_parts.append(line)
            if re.search(r'Control\s*$',heading):
                title_parts=[re.sub(r'Control\s*$','',heading).strip()]
                description=parts;in_description=True
            if in_description and description:
                results.append({'code':'A.'+reference,'title':join_lines(title_parts),
                    'description':join_lines(description),'owner':'','source_reference':reference,
                    'source_location':start,'confidence':'annex_a_structure','review_required':True,
                    'warnings':['Annex A reference is namespaced with A.; provide your organization owner before import.']})
            elif diagnostics is not None:
                diagnostics.append('Unresolved Annex A row '+reference+' at '+start+'; compare with the source.')
        else:
            text=join_lines([heading,*parts])
            if parts and OBLIGATION.search(text):
                results.append({'reference':reference,'text':text,'source_location':start,
                    'confidence':'management_clause_structure','review_required':True,'warnings':[]})
        current=None
    for block in blocks:
        raw=block['text'].strip()
        if re.fullmatch(r'1\s+Scope',raw,re.I):body=True
        if not body:continue
        if re.fullmatch(r'Annex\s+A',raw,re.I):
            flush();annex=True;continue
        if annex and re.fullmatch(r'Bibliography',raw,re.I):
            flush();break
        text=clean_line(raw)
        if not text:continue
        if kind=='controls' and annex:
            if re.match(r'^[5-8]\s+.+controls\s*$',text,re.I):
                flush();continue
            text=re.sub(r'^([5-8])\.\s+(\d{1,2})(?=\s)',r'\1.\2',text)
            match=CONTROL.match(text)
            if match:
                flush();current=(match.group(1),match.group(2),[],block['location'])
            elif current:current[2].append(text)
        elif kind=='requirements' and not annex:
            match=CLAUSE.match(text)
            if match:
                flush();current=(match.group(1),match.group(2),[],block['location'])
            elif current:current[2].append(text)
    flush()
    if kind=='controls':
        identifiers=[item['code'] for item in results]
        if len(identifiers)!=len(set(identifiers)) and diagnostics is not None:
            diagnostics.append('Repeated Annex A references were retained; reconcile duplicates before import.')
        # Count is reported as an extraction check, not used to fabricate rows.
        if diagnostics is not None:diagnostics.append(f'ISO/IEC 27001:2022 Annex A: {len(results)} control rows extracted. Review against your source.')
    return results
