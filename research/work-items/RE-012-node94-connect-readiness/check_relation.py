"""Independent aggregate-field specification, checked against a prior freeze.

This module does not load an ELF or interpret captured CPU instructions.
"""
from pathlib import Path
import gzip,hashlib,json,struct,sys
B=Path(__file__).resolve().parent
SOURCE=B/'expectations.jsonl.gz'
META=B/'FROZEN.json'

def poll_result(i,wrong=None):
    events=[]
    if i['phase']==0 or wrong=='register-resume':events.append('register')
    events.append('poll')
    code=i['pollCode']
    if code==3 and wrong!='pending-is-ready':
        return {'kind':'pending','tag':3,'nextPhase':3,'actions':events}
    def failed(word):
        cleanup=[] if i['fd']==-1 else ['deregister','close']
        if wrong=='double-close' and i['fd']!=-1:cleanup.append('close')
        if wrong=='leak-failure':cleanup=[e for e in cleanup if e!='close']
        return {'kind':'error','tag':2,'errorWord':word,'nextPhase':1,
                'actions':events+cleanup+['release']}
    if code==2:return failed(i['pollError'])
    if i['fd']==-1:return {'kind':'descriptor-sentinel-diagnostic','actions':events}
    if wrong!='skip-query':events.append('query')
    query_failed=i['queryReturn']==-1
    if wrong=='any-negative-query':query_failed=i['queryReturn']<0
    value=i['errno'] if query_failed else i['option']
    if wrong=='ignore-errno' and query_failed:value=0
    if wrong=='ignore-option' and not query_failed:value=0
    if query_failed and wrong!='ignore-errno' or value!=0:
        word=struct.unpack('<Q',struct.pack('<II',2,value&0xffffffff))[0]
        return failed(word)
    if wrong=='close-success':events.append('close')
    return {'kind':'ready','handleTag':i['handleTag'],'fd':i['fd'],'nextPhase':1,'actions':events}

def registration_error(i,wrong=None):
    events=['register','close']
    if wrong=='release-uninstalled':events+=['release']
    return {'tag':2,'errorWord':i['errorWord'],'nextPhase':1,'actions':events}

def cancellation(i,wrong=None):
    phase=i['phase'];fd=i['fd'];events=[]
    if phase==0:
        if fd!=-1 or wrong!='guard-fresh-sentinel':events=['close']
    elif phase==3:
        if fd!=-1:events=['deregister','close']
        events+=['release']
    elif wrong=='drop-completed':events=['release']
    return {'actions':events,'phaseUnchanged':phase}

def reactor(i,wrong=None):
    mask=5 if wrong=='read-mask' else 10
    a,b=i['first'],i['second']
    first_ready=bool(a&(mask|0x80000000))
    if wrong=='ignore-fatal':first_ready=bool(a&mask)
    waker=not first_ready
    word=a if first_ready or wrong=='first-read-only' else b
    fatal=bool(word&0x80000000) and wrong!='ignore-fatal'
    ready=word&mask
    if not first_ready and fatal:ready=mask
    code=1 if fatal else (0 if ready else 2)
    result={'reactorCode':code,'wakerTableVisited':waker}
    if code!=2:result.update(mask=ready,generation=(word>>16)&255)
    return result

def tls(i,wrong=None):
    budget=i['budget'];enabled=bool(i['flag']);code=i['reactorCode']
    exhausted=enabled and budget==0 and wrong!='ignore-budget'
    requested=not exhausted
    poll_code=3 if exhausted else {0:0,1:2,2:3}[code]
    if enabled and requested:
        budget-=1
        if code!=0 and wrong!='never-restore-budget':budget+=1
    return {'reactorRequested':requested,'pollCode':poll_code,'budgetAfter':budget}

functions={'poll-result':poll_result,'registration-error':registration_error,
 'cancellation':cancellation,'reactor-projection':reactor,'initialized-tls-projection':tls}
wrongs={'poll-result':['register-resume','pending-is-ready','skip-query','any-negative-query',
 'ignore-errno','ignore-option','double-close','leak-failure','close-success'],
 'registration-error':['release-uninstalled'],'cancellation':['guard-fresh-sentinel','drop-completed'],
 'reactor-projection':['read-mask','first-read-only','ignore-fatal'],
 'initialized-tls-projection':['ignore-budget','never-restore-budget']}
meta=json.loads(META.read_bytes());raw=SOURCE.read_bytes()
if hashlib.sha256(raw).hexdigest()!=meta['compressedSha256']:raise ValueError('Frozen compressed identity')
data=gzip.decompress(raw)
if hashlib.sha256(data).hexdigest()!=meta['uncompressedSha256']:raise ValueError('Frozen value identity')
rows=[json.loads(x) for x in data.splitlines()]
if len(rows)!=meta['cases']:raise ValueError('Frozen denominator')
counts={k:0 for k in functions};mutants={w:0 for ws in wrongs.values() for w in ws}
for row in rows:
    family=row['family'];fun=functions[family];i=row['input']
    if fun(i)!=row['expected']:raise ValueError('Independent value relation differs '+row['id'])
    counts[family]+=1
    for wrong in wrongs[family]:mutants[wrong]+=fun(i,wrong)!=row['expected']
if counts!=meta['families'] or any(x==0 for x in mutants.values()):raise ValueError('Incomplete or neutral controls')
receipt={'state':'readiness-abstract-relation-check-unqualified','cases':counts,'wrongRules':mutants,
 'frozenSha256':meta['compressedSha256'],'capturedExecution':False,'instructionEvaluation':False,
 'networkOperations':0,'nativeEquivalence':False,
 'limits':'Aggregate value and request projection under the manual premises, not target execution or original ABI. TLS budget projection assumes initialized, stable, nonreentrant ordinary callbacks.'}
out=B/sys.argv[1]
if out.exists():raise ValueError('Preserve prior check')
out.write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n',encoding='utf-8',newline='\n')
print(json.dumps(receipt,sort_keys=True))
