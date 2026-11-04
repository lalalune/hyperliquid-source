import ast
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

B=Path(__file__).resolve().parent
R=B/'integration'
sys.path.insert(0,str(R/'tools'))
import elf_index, fde_extents
from capstone import Cs,CS_ARCH_X86,CS_MODE_64

data=(R/'artifacts/node/115/hl-node').read_bytes()
digest=hashlib.sha256(data).hexdigest()
assert digest=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
sections=elf_index.sections(data)
_,fdes=fde_extents.eh_frame_records(data,sections)
actual={(f['start'],f['end']):f for f in fdes}
md=Cs(CS_ARCH_X86,CS_MODE_64)
q=json.loads((B/'foundation-analysis.json').read_text())
details={p['number']:p for p in json.loads((B/'details.json').read_text())}
for p in q:p['files']=[f[-1]for f in details[p['number']]['files']]
cache={};results=[]
cat=subprocess.Popen(['git','cat-file','--batch'],cwd=R,stdin=subprocess.PIPE,stdout=subprocess.PIPE)

def blob(head,path):
    cat.stdin.write((head+':'+path+'\n').encode());cat.stdin.flush()
    header=cat.stdout.readline().split()
    if len(header)!=3:return None
    size=int(header[2]);payload=cat.stdout.read(size);assert cat.stdout.read(1)==b'\n'
    return payload

def integer(value):
    if isinstance(value,int):return value
    if isinstance(value,str) and re.fullmatch(r'0x[0-9a-fA-F]+',value):return int(value,16)
    return None

def read(va,n):
    s=next((s for s in sections if s['type']!=8 and s['address']<=va and va+n<=s['address']+s['size']),None)
    if s is None:return None
    return data[s['offset']+va-s['address']:s['offset']+va-s['address']+n]

def walk(x,path=''):
    if isinstance(x,dict):
        yield path,x
        for key,v in x.items():yield from walk(v,path+'/'+key)
    elif isinstance(x,list):
        for i,v in enumerate(x):yield from walk(v,path+'/'+str(i))

def admit_range(start,end,source,row,claim=False,sha=None):
    if not isinstance(start,int)or not isinstance(end,int)or start>=end:return
    if (start,end) in actual:
        key=(start,end)
        if key not in cache:
            raw=read(start,end-start)
            dis=list(md.disasm(raw,start));decoded=b''.join(bytes(i.bytes)for i in dis)
            cache[key]={'start':hex(start),'end':hex(end),'bytes':len(raw),'rows':len(dis),'complete_capstone':decoded==raw,'sha256':hashlib.sha256(raw).hexdigest()}
        r=cache[key]
        if sha and sha!=r['sha256']:row['errors'].append({'file':source,'range':[hex(start),hex(end)],'kind':'full-FDE hash differs','expected':sha,'actual':r['sha256']})
        row['ranges'].add(key)
    elif claim:
        row['unmatched_ranges'].append({'file':source,'start':hex(start),'end':hex(end)})

for pr in q:
    row={'number':pr['number'],'head':pr['head'],'author':pr['author'],'ranges':set(),'raw_rows':0,'raw_bytes':0,'json_atoms':0,'errors':[],'unmatched_ranges':[],'identity_mentions':0,'python_sources':[]}
    for path in pr['files']:
        if not path.startswith(('research/','tools/','tests/')):continue
        payload=blob(pr['head'],path)
        if payload is None:continue
        text=payload.decode('utf-8',errors='replace')
        row['identity_mentions']+=text.count(digest)
        if path.endswith('.py'):
            row['python_sources'].append({'path':path,'sha256':hashlib.sha256(payload).hexdigest()})
        if path.endswith('.json'):
            try:value=json.loads(text)
            except ValueError:continue
            for pointer,v in walk(value):
                # Historical #94 subrecords are provenance only, not active evidence.
                if 'baseline' in pointer or 'node94' in pointer.lower():continue
                start=integer(next((v[k]for k in ('start','start_va','address')if k in v),None))
                end=integer(next((v[k]for k in ('end','end_va','end_va_exclusive','end_exclusive')if k in v),None))
                sha=next((v[k]for k in ('full_sha256','sha256','body_sha256','code_sha256')if isinstance(v.get(k),str)and re.fullmatch(r'[0-9a-f]{64}',v[k])),None)
                if start and end:admit_range(start,end,path+pointer,row,False,sha)
                for key in ('fde','range'):
                    s=v.get(key)
                    if isinstance(s,str):
                        m=re.fullmatch(r'(0x[0-9a-fA-F]+)\.\.(0x[0-9a-fA-F]+)',s)
                        if m:admit_range(int(m[1],16),int(m[2],16),path+pointer+'/'+key,row,key=='fde')
                va=integer(next((v[k]for k in ('va','address','site','start','start_va','base')if k in v),None))
                rawhex=next((v[k]for k in ('bytes_hex','raw_hex','hex','bytes')if isinstance(v.get(k),str)and re.fullmatch(r'(?:[0-9a-fA-F]{2})+',v[k])),None)
                if va and rawhex and not pointer.endswith(('/fde','/cie','/candidate_enclosing_fde')):
                    raw=bytes.fromhex(rawhex);observed=read(va,len(raw))
                    if observed is not None:
                        row['json_atoms']+=1
                        if observed!=raw:row['errors'].append({'file':path+pointer,'va':hex(va),'kind':'JSON raw bytes differ','expected':raw.hex(),'actual':observed.hex()})
        if path.endswith('.txt'):
            for m in re.finditer(r'^\s*([0-9a-fA-F]+):\s*((?:[0-9a-fA-F]{2}[ \t]+)+)',text,re.M):
                va=int(m[1],16);raw=bytes.fromhex(m[2]);observed=read(va,len(raw))
                if observed is not None:
                    row['raw_rows']+=1;row['raw_bytes']+=len(raw)
                    if observed!=raw:row['errors'].append({'file':path,'va':hex(va),'kind':'native export raw bytes differ','expected':raw.hex(),'actual':observed.hex()})
            for m in re.finditer(r'FDE[^\n]*pc=([0-9a-fA-F]+)\.\.([0-9a-fA-F]+)',text):
                admit_range(int(m[1],16),int(m[2],16),path,row,True)
    row['ranges']=[cache[key]for key in sorted(row['ranges'])]
    results.append(row)
    (B/'foundation-native-progress.json').write_text(json.dumps({'completed':len(results),'total':len(q),'last':row['number']}))
cat.stdin.close();cat.wait()
out={'target_sha256':digest,'capstone_version':__import__('capstone').__version__,'prs':results,'unique_ranges':len(cache),'unique_complete_decodes':sum(v['complete_capstone']for v in cache.values()),'unique_bytes':sum(v['bytes']for v in cache.values()),'unique_rows':sum(v['rows']for v in cache.values()),'limits':'Only declared complete FDE ranges and directly recorded raw byte atoms were checked. A matching byte partition does not prove semantic equivalence or ownership. Broad census and source-label inferences are outside this check.'}
(B/'foundation-native-review.json').write_text(json.dumps(out,indent=2)+'\n')
print(json.dumps({'prs':len(results),'unique_ranges':out['unique_ranges'],'complete':out['unique_complete_decodes'],'errors':sum(len(v['errors'])for v in results),'unmatched':sum(len(v['unmatched_ranges'])for v in results)}))
