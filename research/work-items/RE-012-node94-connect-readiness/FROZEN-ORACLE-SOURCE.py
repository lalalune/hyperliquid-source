"""Pre-checker mathematical projections justified by the addressed manual argument.

No captured instructions, registers, network operations or target outputs are
evaluated. Numeric import branch representatives do not claim ABI reachability.
"""
from pathlib import Path
import datetime,gzip,hashlib,io,itertools,json,sys
B=Path(__file__).resolve().parent
rows=[]
def add(family,inputs,expected):
    rows.append({'family':family,'id':family+'-'+str(len(rows)),
                 'input':inputs,'expected':expected})
fds=[-1,0,1,9,2147483647]
errors=[-2147483648,-1,0,1,115,2147483647]
options=[-2147483648,-1,0,1,5,115,2147483647]
for phase,handle,fd,poll,rc,opt,err in itertools.product([0,3],[0,1],fds,[0,2,3],[-2147483648,-2,-1,0,1,2147483647],options,errors):
    payload=0x1122334455667788
    i={'phase':phase,'handleTag':handle,'fd':fd,'pollCode':poll,
       'pollError':payload,'queryReturn':rc,'option':opt,'errno':err}
    actions=['register'] if phase==0 else []
    if poll==3:
        e={'kind':'pending','tag':3,'nextPhase':3,'actions':actions+['poll']}
    elif poll==2:
        e={'kind':'error','tag':2,'errorWord':payload,'nextPhase':1,
           'actions':actions+['poll']+(['deregister','close'] if fd!=-1 else [])+['release']}
    elif fd==-1:
        e={'kind':'descriptor-sentinel-diagnostic','actions':actions+['poll']}
    elif rc==-1 or opt!=0:
        value=err if rc==-1 else opt
        word=int.from_bytes(bytes([2,0,0,0])+(value%(2**32)).to_bytes(4,'little'),'little')
        e={'kind':'error','tag':2,'errorWord':word,'nextPhase':1,
           'actions':actions+['poll','query','deregister','close','release']}
    else:
        e={'kind':'ready','handleTag':handle,'fd':fd,'nextPhase':1,
           'actions':actions+['poll','query']}
    add('poll-result',i,e)
for fd,error in itertools.product(fds,[0,1,2,0x8000000000000000,0x1122334455667788,0xffffffffffffffff]):
    add('registration-error',{'fd':fd,'errorWord':error},
        {'tag':2,'errorWord':error,'nextPhase':1,'actions':['register','close']})
for phase,fd in itertools.product(range(256),fds):
    actions=['close'] if phase==0 else ((['deregister','close'] if fd!=-1 else [])+['release'] if phase==3 else [])
    add('cancellation',{'phase':phase,'fd':fd},{'actions':actions,'phaseUnchanged':phase})
words={0,0xffffffff}|{2**k for k in range(32)}
for generation,mask,fatal in itertools.product([0,1,127,255],[0,1,2,4,5,8,10,15],[0,0x80000000]):
    words.add((generation*65536)|mask|fatal)
words=sorted(words)
for first,second in itertools.product(words,words):
    first_bits=[bool(first&(2**k)) for k in range(32)]
    if first_bits[1] or first_bits[3] or first_bits[31]:
        used=first;mask=(2 if first_bits[1] else 0)+(8 if first_bits[3] else 0)
        code=1 if first_bits[31] else 0;waker=False
    else:
        used=second;fatal=(second//(2**31))%2
        mask=10 if fatal else sum(2**k for k in [1,3] if (second//(2**k))%2)
        code=1 if fatal else (0 if mask else 2);waker=True
    e={'reactorCode':code,'wakerTableVisited':waker}
    if code!=2:e.update(mask=mask,generation=(used//65536)%256)
    add('reactor-projection',{'first':first,'second':second},e)
for flag,budget,code in itertools.product([0,1],[0,1,2,127,255],[0,1,2]):
    query=not(flag==1 and budget==0)
    mapped=3 if not query or code==2 else (2 if code==1 else 0)
    after=budget-1 if flag==1 and query and code==0 else budget
    add('initialized-tls-projection',{'flag':flag,'budget':budget,'reactorCode':code},
        {'reactorRequested':query,'pollCode':mapped,'budgetAfter':after})
payload=('\n'.join(json.dumps(x,sort_keys=True,separators=(',',':')) for x in rows)+'\n').encode()
buffer=io.BytesIO()
with gzip.GzipFile(filename='',mode='wb',fileobj=buffer,compresslevel=9,mtime=0) as gz:gz.write(payload)
raw=buffer.getvalue();stem=sys.argv[1]
archive=B/(stem+'.jsonl.gz');receipt=B/(stem+'.json')
if archive.exists() or receipt.exists():raise ValueError('Preserve previous freeze')
counts={f:sum(r['family']==f for r in rows) for f in sorted({r['family'] for r in rows})}
meta={'state':'readiness-expectations-frozen-before-checker','base':'966865f1637a29ce75b019e1bf11d5529cc6f519',
 'targetSha256':'3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f',
 'sourceSha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
 'manualProofSha256':hashlib.sha256((B/'node94-readiness-proof-draft.md').read_bytes()).hexdigest(),
 'cases':len(rows),'families':counts,'reactorWordRepresentatives':len(words),
 'uncompressedBytes':len(payload),'compressedBytes':len(raw),
 'uncompressedSha256':hashlib.sha256(payload).hexdigest(),'compressedSha256':hashlib.sha256(raw).hexdigest(),
 'gzipOsByte':raw[9],'capturedExecution':False,'instructionEvaluation':False,'checkerCreated':False,
 'scope':'Variant-defined abstract values and ordinary request ordering. Separate first/second readiness inputs. Numeric unusual import returns do not claim reachability. TLS initialized/ordinary callbacks/nonreentrant storage premises; no native/runtime/component equivalence.'}
archive.write_bytes(raw);receipt.write_text(json.dumps(meta,sort_keys=True,indent=2)+'\n',encoding='utf-8',newline='\n')
print(json.dumps(meta,sort_keys=True))
