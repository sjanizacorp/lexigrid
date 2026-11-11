"""NIST SP 800-53 Rev. 5 source-structure profile; no standard text embedded.
Author: Shahryar Jahangir, Aniza Inc.
"""
import re

PROFILE='nist80053_rev5'
BASE=re.compile(r'^([A-Z]{2}-\d+)\s+(.+)$')
ENHANCEMENT=re.compile(r'^\((\d+)\)\s+(.+?)\s*\|\s*(.*)$')
CATALOGUE=re.compile(r'^CHAPTER THREE\s+PAGE\s+\d+',re.M)

def matches(pages):
 cover='\n'.join(pages[:3])
 return bool(re.search(r'NIST\s+(?:Special\s+Publication|SP)\s+800-53\b',cover,re.I) and
             re.search(r'(?:Revision\s+5|REV\.\s*5|800-53r5)',cover,re.I))

def clean_line(line):
 text=line.strip().replace('\u00ad','')
 if (not text or re.match(r'^NIST SP 800-53,\s*REV\.\s*5',text) or
     re.match(r'^CHAPTER THREE\s+PAGE\s+\d+',text) or
     text.startswith('This publication is available free of charge from:') or
     re.fullmatch(r'[_\s]+',text)):
  return ''
 return text

def parse(blocks,kind,diagnostics=None):
 if kind=='frameworks':
  first=next((b['location'] for b in blocks if re.search(r'800-53',b['text'])),'Source cover')
  return [{'name':'NIST SP 800-53','revision':'Revision 5','source_location':first,'confidence':'standard_identifier','review_required':True,'warnings':[]}]
 if kind=='policies':
  if diagnostics is not None:diagnostics.append('NIST SP 800-53 is a control catalogue, not an organization policy. No organization policy was invented.')
  return []
 results=[];current=None;parent=None;enhancements=False;phase='none';withdrawn=[];missing=[]
 def flush():
  nonlocal current
  if current is None:return
  if current['withdrawn']:withdrawn.append(current['code'])
  elif current['body']:
   code=current['code'];title=' '.join(current['title']);body='\n'.join(current['body']).strip()
   result={'source_location':current['location'],'confidence':'nist80053_rev5_structure','review_required':True,
           'warnings':['Owner was not inferred. Review the source control statement and supply an accountable owner.']}
   if kind=='controls':result.update(code=code,title=title,description=body,owner='')
   else:result.update(reference=code,text=title+'\n'+body)
   results.append(result)
  else:missing.append(current['code'])
  current=None
 for block in blocks:
  if not block.get('nist_catalogue'):continue
  text=clean_line(block['text'])
  if not text:continue
  base=BASE.match(text)
  # Control headings are uppercase; cross-reference prose is not a heading.
  if base and base[2].isupper():
   flush();parent=base[1];enhancements=False;phase='title'
   current={'code':parent,'title':[base[2]],'body':[],'location':block['location'],'withdrawn':False}
   continue
  if current is not None and re.match(r'^\[Withdrawn\b',text,re.I):current['withdrawn']=True;phase='notes';continue
  if text.startswith('Control Enhancements:'):
   flush();enhancements=True;phase='notes';continue
  enhancement=ENHANCEMENT.match(text) if parent else None
  if enhancement and (enhancement[2]+' '+enhancement[3]).isupper():
   flush();phase='title'
   current={'code':parent+'('+enhancement[1]+')','title':[enhancement[2]+' | '+enhancement[3]],'body':[],'location':block['location'],'withdrawn':False}
   continue
  if current is None:continue
  if text.startswith('Control:'):
   phase='body'
   remainder=text[len('Control:'):].strip()
   if remainder:current['body'].append(remainder)
   continue
  if re.match(r'^(?:Discussion|Related Controls|References):',text):phase='notes';continue
  if phase=='title':
   if text.isupper():current['title'].append(text)
   else:phase='body';current['body'].append(text)
  elif phase=='body':current['body'].append(text)
 flush()
 if diagnostics is not None:
  diagnostics.append('NIST catalogue profile: extracted '+str(len(results))+' active control and enhancement statements; omitted '+str(len(withdrawn))+' withdrawn entries. Front matter, references, discussion and Appendix C summary tables are not imported as controls.')
  if missing:diagnostics.append('No normative statement identified for '+', '.join(missing)+'. Review these source entries manually.')
  if not results:diagnostics.append('No complete NIST catalogue statements found in this page range. Include each control heading and its statement; a range beginning inside a control cannot establish its identifier.')
 return results
