"""CJIS published-policy identity and normative control statements; no policy text embedded.
Author: Shahryar Jahangir, Aniza Inc.
"""
import re
PROFILE='cjis_security_policy'
ENHANCEMENT=re.compile(r'^\((\d+)\)\s+(.+?)\s*\|\s*(.*)$')
HEADING=re.compile(r'^([A-Z]{2}-\d+(?:\(\d+\))?)\s+(.+)$')

def identity(pages):
 cover='\n'.join(pages[:3])
 if not re.search(r'Criminal Justice Information Services',cover,re.I) or not re.search(r'Security\s+Policy',cover,re.I):return None
 version=re.search(r'Version\s+(\d+(?:\.\d+)+)',cover,re.I)
 return version[1] if version else None

def clean(text):
 text=text.strip().replace('\u00ad','')
 if (re.fullmatch(r'\d+|[ivxlcdm]+',text,re.I) or re.fullmatch(r'\d{2}/\d{2}/\d{4}',text) or re.match(r'^CJISSECPOL\s+v\d',text,re.I)):return ''
 return text

def parse(blocks,kind,diagnostics=None):
 version=next((b.get('publication_version') for b in blocks if b.get('publication_version')),'')
 first=next((b['location'] for b in blocks if b['text'].strip()),'Source cover')
 if kind=='frameworks':return [{'name':'FBI CJIS Security Policy','revision':version,'source_location':first,'confidence':'publication_identity','review_required':True,'warnings':[]}]
 if kind=='policies':
  body='\n'.join(block['text'] for block in blocks).strip()
  notice='The source is one published CJIS Security Policy. This draft candidate retains all extracted text from the selected pages, including appendices when selected. Use Controls or Requirements for individual normative statements. Local approval and ownership are not inferred.'
  if diagnostics is not None:diagnostics.append(notice)
  return [{'code':'CJIS-SECPOL-'+version,'title':'CJIS Security Policy v'+version,'body':body,'owner':'','source_location':first,'confidence':'published_policy_text','review_required':True,'warnings':[notice]}]
 results=[];current=None;phase='none';started=False;withdrawn=0;parent=None
 def flush():
  nonlocal current,withdrawn
  if current:
   if current['withdrawn']:withdrawn+=1
   elif current['body'] and (not current.get('legacy') or re.search(r'\b(?:shall|must|required)\b',' '.join(current['body']),re.I)):
    title=' '.join(current['title']);body='\n'.join(current['body']).strip();code=current['code']
    item={'source_location':current['location'],'source_reference':code,'confidence':'cjis_normative_statement','review_required':True,'warnings':['CJIS published requirements are not proof of implementation. Supply local ownership and review.']}
    if kind=='controls':item.update(code='CJIS-'+code,title=title,description=body,owner='')
    else:item.update(reference=code,text=title+'\n'+body)
    results.append(item)
  current=None
 for block in blocks:
  text=clean(block['text'])
  if not text:continue
  if started and re.match(r'^APPENDIX\s+[A-Z]\b',text):flush();break
  legacy=re.match(r'^(5\.20(?:\.\d+){0,6})\s+(.+)$',text)
  if started and legacy and not re.search(r'\.{3,}',text):
   flush();phase='body';current={'code':legacy[1],'title':[legacy[2]],'body':[],'withdrawn':False,'location':block['location'],'legacy':True};continue
  match=HEADING.match(text)
  enhancement=ENHANCEMENT.match(text) if parent else None
  if enhancement and (enhancement[2]+' '+enhancement[3]).isupper():
   flush();phase='title';current={'code':parent+'('+enhancement[1]+')','title':[enhancement[2]+' | '+enhancement[3]],'body':[],'withdrawn':False,'location':block['location']};continue
  if match and match[2].isupper() and not re.search(r'\.{3,}',text):
   flush();parent=match[1].split('(')[0];phase='title';current={'code':match[1],'title':[match[2]],'body':[],'withdrawn':False,'location':block['location']};continue
  if current is None:continue
  if re.match(r'^\[Withdrawn\b',text,re.I):current['withdrawn']=True;phase='notes';continue
  if re.match(r'^\[(?:Existing|New|Priority)',text,re.I):continue
  if text.startswith('Control:'):
   started=True;phase='body';rest=text[len('Control:'):].strip()
   if rest:current['body'].append(rest)
   continue
  if re.match(r'^(?:Discussion|Related Controls|References|Control Enhancements):',text):phase='notes';continue
  if phase=='title' and text.isupper():current['title'].append(text)
  elif phase=='body':current['body'].append(text)
 flush()
 if diagnostics is not None:diagnostics.append('CJIS profile: '+str(len(results))+' normative control statements; '+str(withdrawn)+' withdrawn entries omitted. Discussion, examples, front matter and appendices are not separate control requirements; Policies retains the complete published policy text.')
 return results
