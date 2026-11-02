"""Construct small-limit map authorities from supplied values/field boundaries.

No arbitrary-byte parser, captured instruction evaluator, target invocation,
checker import or inferred source is used. This source precedes a new checker.
"""
from pathlib import Path
import collections,gzip,hashlib,io,itertools,json,sys
B=Path(__file__).resolve().parent
U=(1<<64)-1
rows=[];seen={};categories=collections.Counter()

def encoded(v,width=None):
    if width is None:width=1 if v<251 else 3 if v<65536 else 5 if v<1<<32 else 9
    if width==1:
        if not 0<=v<251:raise ValueError('One-byte value')
        return bytes([v])
    if width not in [3,5,9] or not 0<=v<1<<(8*(width-1)):raise ValueError('Encoded width')
    return bytes([{3:251,5:252,9:253}[width]])+v.to_bytes(width-1,'little')

def cell(offset,value,width=8):return {'offset':offset,'hex':value.to_bytes(width,'little').hex()}
def error(kind,needed=None,expected=None,found=None):
    out=[cell(0,kind,1)]
    if kind==0:out.append(cell(8,needed))
    if kind==3:out.extend([cell(1,expected,1),cell(2,found,1)])
    return out

V=[0,1,250,251,65535,65536,(1<<32)-1,1<<32,U]
def plan(key,index=0,wide=False,values=None,last=None):
    if len(key)!=20:raise ValueError('Key length')
    values=tuple(V[(index+i)%len(V)] for i in range(8)) if values is None else tuple(values)
    if len(values)!=8:raise ValueError('Eight logical words')
    last=(index*37+128)%256 if last is None else last
    return {'key':key,'values':values,'chunks':[encoded(v,9 if wide else None) for v in values],
            'tail':bytes([last]),'last':last,'bad':None}

def rankkey(rank):return rank.to_bytes(20,'big')

def sequence(n,wide=False,duplicate=False,seed=0):
    return [plan(rankkey(0 if duplicate else n-i),seed+i,wide) for i in range(n)]

def construct(category,counts=(0,0),plans=((),()),charge=0,widths=(None,None),
              prefix=bytes(range(32)),suffix=b'',cut=None,bad_counts=(None,None)):
    if len(prefix)!=32 or not 0<=charge<=1000:raise ValueError('Selected domain')
    counts=tuple(counts);plans=[list(x) for x in plans]
    count_parts=[encoded(k,w) if bad is None else bytes([bad[0]])+b'\xa5'*bad[1]
                 for k,w,bad in zip(counts,widths,bad_counts)]
    wire=prefix+b''.join(count_parts[j]+b''.join(p['key']+b''.join(p['chunks'])+p['tail'] for p in plans[j]) for j in range(2))+suffix
    data=wire if cut is None else wire[:cut]
    cursor=0;counter=charge;stores=[];allocs=[];releases=[];drops=[];calls=[]
    comparisons=[];moves=[];completed=[[],[]];allocated=[False,False];first_done=False

    def finish(kind=None,needed=None,expected=None,found=None):
        maps=[]
        if kind is None:
            cells=[cell(0,0),{'offset':8,'hex':prefix.hex()}]
            for j in range(2):
                keys=sorted({p['key'] for p in completed[j]})
                vals=[]
                for k in keys:
                    p=next(p for p in reversed(completed[j]) if p['key']==k)
                    vals.append({'keyHex':k.hex(),'words':list(p['values']),'byte':p['last']})
                maps.append(vals)
                o=40+24*j
                cells.append({'offset':o,'symbol':'map'+str(j)} if allocated[j] else cell(o,0))
                if allocated[j]:cells.append(cell(o+8,0))
                cells.append(cell(o+16,len(keys)))
        else:
            cells=[cell(0,1)]+[dict(c,offset=c['offset']+8) for c in error(kind,needed,expected,found)]
            # Internal map failure cleanup is recorded at its actual stage.
            # Caller always drops the completed first descriptor after second failure.
            if first_done:
                drops.append('map0')
                if allocated[0]:releases.append({'symbol':'map0','bytes':1024,'flags':0})
        projection={'charge':counter,'stores':stores[:],'consumed':cursor,'remainingHex':data[cursor:].hex(),
          'cells':cells,'maps':maps,'calls':calls[:],'dropCalls':drops[:],
          'allocationRequests':allocs[:],'releaseRequests':releases[:],
          'comparisons':comparisons[:],'movements':moves[:]}
        inp={'dataHex':data.hex(),'charge':charge,'mode':1,'limit':1000}
        identity=(data,charge)
        if identity in seen:
            if seen[identity]!=projection:raise ValueError('Constructive authorities disagree')
            return
        seen[identity]=projection;rows.append({'id':str(len(rows)),'category':category,'input':inp,'expected':projection})
        categories[category]+=1

    calls.append('fixed32');counter+=32;stores.append(counter)
    if counter>1000:return finish(2)
    if len(data)<32:return finish(0,needed=32-len(data))
    cursor=32
    for j in range(2):
        symbol='map'+str(j);calls.append(symbol)
        counter+=8;stores.append(counter)
        if counter>1000:return finish(2)
        part=count_parts[j];available=len(data)-cursor
        if bad_counts[j] is not None:
            if not available:return finish(0,needed=1)
            marker=bad_counts[j][0];fast=available>8
            if not fast:cursor+=1
            return finish(3,expected=2 if fast else 3,found=4 if marker==254 else 12)
        if available<len(part):
            if available:cursor+=1
            return finish(0,needed=len(part)-available if available else 1)
        cursor+=len(part)
        amount=96*counts[j]
        if amount>U or counter+amount>U:return finish(2)
        counter+=amount;stores.append(counter)
        if counter>1000:return finish(2)
        if counts[j]>10 or len(plans[j])!=counts[j]:raise ValueError('Admitted known-field plan required')
        reserved=counter
        for q,p in enumerate(plans[j]):
            if counter!=reserved-11*q or counter<96:raise ValueError('Refund invariant')
            counter-=96;stores.append(counter)
            counter+=20;stores.append(counter)
            def inner_failure(kind,**extra):
                drops.append(symbol)
                if allocated[j]:releases.append({'symbol':symbol,'bytes':1024,'flags':0})
                return finish(kind,**extra)
            available=len(data)-cursor
            if available<20:return inner_failure(0,needed=20-available)
            cursor+=20
            for group in range(2):
                counter+=32;stores.append(counter)
                if counter>reserved:raise ValueError('Inner budget theorem')
                for i in range(4*group,4*group+4):
                    available=len(data)-cursor
                    if p['bad'] is not None and i==p['bad'][0]:
                        if not available:return inner_failure(0,needed=1)
                        marker=p['bad'][1];fast=available>8
                        if not fast:cursor+=1
                        return inner_failure(3,expected=2 if fast else 3,found=4 if marker==254 else 12)
                    width=len(p['chunks'][i])
                    if available<width:
                        if available:cursor+=1
                        return inner_failure(0,needed=width-available if available else 1)
                    cursor+=width
            counter+=1;stores.append(counter)
            if counter>reserved:raise ValueError('Inner byte budget theorem')
            if cursor==len(data):return inner_failure(0,needed=1)
            cursor+=1
            before=sorted({x['key'] for x in completed[j]});key=p['key']
            candidates=[k for k in before if k<key];upper=[k for k in before if k>=key]
            if upper:candidates.append(upper[0])
            comparisons.extend({'map':symbol,'leftKeyHex':key.hex(),'rightKeyHex':k.hex(),'bytes':20} for k in candidates)
            if key not in before:
                if not before:
                    allocated[j]=True;allocs.append({'symbol':symbol,'bytes':1024})
                else:
                    index=sum(k<key for k in before);moved=len(before)-index
                    if moved:moves.extend([
                      {'symbol':symbol,'sourceOffset':800+20*index,'destinationOffset':800+20*(index+1),'bytes':20*moved},
                      {'symbol':symbol,'sourceOffset':8+72*index,'destinationOffset':8+72*(index+1),'bytes':72*moved}])
            completed[j].append(p)
        if counter!=reserved-11*counts[j]:raise ValueError('Map accounting theorem')
        if j==0:first_done=True
    return finish()

# Initial state is the counter at THIS helper's entry. Do not substitute the
# enclosing fresh message counter. Cover every finite incoming counter.
for c in range(1001):construct('all-entry-counters',charge=c)
for m,n in itertools.product(range(13),repeat=2):
    boundaries=[0,1,4,1000,960-96*m,952-85*m-96*n]
    cs=sorted({x+d for x in boundaries for d in [-1,0,1] if 0<=x+d<=1000})
    ps=(sequence(m) if m<=10 else [],sequence(n,seed=19) if n<=10 else [])
    for c,w,dup in itertools.product(cs,[None,9],[False,True]):
        use=(sequence(m,w==9,dup) if m<=10 else [],sequence(n,w==9,dup,19) if n<=10 else [])
        construct('joint-admission-boundaries',(m,n),use,c,(w,w))

# Separate logical fields even when all keys are shared across both maps.
histories=[r for n in range(5) for r in itertools.product(range(2),repeat=n)]
for left,right in itertools.product(histories,repeat=2):
    ps=([plan(rankkey(k),i) for i,k in enumerate(left)],
        [plan(rankkey(k),i+17) for i,k in enumerate(right)])
    construct('two-map-duplicate-histories',(len(left),len(right)),ps)
for which,ranks in itertools.product(range(2),itertools.permutations(range(5))):
    ps=[sequence(1),sequence(1,seed=19)];ps[which]=[plan(rankkey(k),i+which*17) for i,k in enumerate(ranks)]
    construct('two-map-insertion-orders',tuple(map(len,ps)),ps)
for which,position,bit in itertools.product(range(2),range(20),range(8)):
    k=bytearray(20);k[position]=1<<bit
    ps=[sequence(1),sequence(1,seed=19)]
    ps[which]=[plan(bytes(k),0),plan(bytes(20),1),plan(bytes(k),2)]
    construct('map-key-bit-preservation',tuple(map(len,ps)),ps)
for which,(first,second) in itertools.product(range(2),itertools.combinations(range(20),2)):
    a=bytearray(20);b=bytearray(20);a[first]=1;b[second]=2
    ps=[[],[]];ps[which]=[plan(bytes(a),0),plan(bytes(b),1),plan(bytes(a),2)]
    construct('cross-position-key-order',tuple(map(len,ps)),ps)
for which,index,value in itertools.product(range(2),range(8),V+[1<<b for b in range(64)]):
    words=[0]*8;words[index]=value;ps=[[],[]]
    ps[which]=[plan(rankkey(3),values=words)]
    construct('two-map-value-words',tuple(map(len,ps)),ps)
for which,last in itertools.product(range(2),range(256)):
    ps=[[],[]];ps[which]=[plan(rankkey(7),last=0),plan(rankkey(7),last=last,index=17)]
    construct('two-map-raw-tail-replacement',tuple(map(len,ps)),ps,suffix=b'\xfe'*9)
for position,bit in itertools.product(range(32),range(8)):
    prefix=bytearray(32);prefix[position]=1<<bit
    construct('fixed32-preservation',prefix=bytes(prefix))

# Truncation predictions come from supplied field widths, never a byte parser.
for m,n,wide,dup in itertools.product([0,1,2,10],[0,1,2,9],[False,True],[False,True]):
    if 40+96*m>1000 or 48+85*m+96*n>1000:continue
    ps=(sequence(m,wide,dup),sequence(n,wide,dup,19));ws=(9,9) if wide else (None,None)
    length=32+sum(len(encoded(k,w)) for k,w in zip((m,n),ws))+sum(20+sum(map(len,p['chunks']))+1 for group in ps for p in group)
    for cut in range(length):construct('all-selected-wire-cuts',(m,n),ps,widths=ws,cut=cut)
    construct('suffix-and-wide-counts',(m,n),ps,widths=ws,suffix=b'\xfe\xff\xfb'+b'\xa5'*12)
for which,width,cut in itertools.product(range(2),[3,5,9],range(9)):
    if cut>=width:continue
    ws=[None,None];ws[which]=width
    construct('short-count-prefix',widths=tuple(ws),cut=32+(1 if which else 0)+cut)
for which,marker,padding,c in itertools.product(range(2),[254,255],range(11),[0,952,953,960,961,968,969,1000]):
    bad=[None,None];bad[which]=(marker,padding)
    # A malformed first count is final material: second bytes must not change
    # the intended fast/slow boundary. Restrict by a physical cut.
    construct('bad-count-and-budget-order',charge=c,bad_counts=tuple(bad),cut=32+(1 if which else 0)+1+padding)
for which,done,index,marker,padding in itertools.product(range(2),[0,1,8],range(8),[254,255],range(11)):
    ps=[[],[]];prior=sequence(done,seed=which*17)
    bad=plan(rankkey(100),done,values=(0,)*8)
    bad['chunks']=[b'\x00']*index+[bytes([marker])+b'\xa5'*padding];bad['tail']=b'';bad['bad']=(index,marker)
    ps[which]=prior+[bad]
    if which:ps[0]=sequence(1)
    counts=tuple(map(len,ps))
    length=32+sum(len(encoded(k)) for k in counts)+sum(20+sum(map(len,p['chunks']))+len(p['tail']) for group in ps for p in group)
    # First-map error must not accidentally see a second count as padding.
    if which==0:length-=1
    construct('bad-value-and-ordered-cleanup',counts,ps,cut=length)
for which,k in itertools.product(range(2),[U//96-1,U//96,U//96+1,U]):
    counts=[0,0];counts[which]=k
    construct('huge-count-overflow',tuple(counts))

payload=('\n'.join(json.dumps(r,sort_keys=True,separators=(',',':')) for r in rows)+'\n').encode()
buf=io.BytesIO()
with gzip.GzipFile(filename='',mode='wb',fileobj=buf,mtime=0,compresslevel=9) as z:z.write(payload)
raw=buf.getvalue();stem=sys.argv[1];out=B/(stem+'.jsonl.gz');meta_path=B/(stem+'.json')
if out.exists() or meta_path.exists():raise ValueError('Preserve frozen authority')
meta={'state':'nested-maps-constructive-expectations-frozen-before-checker',
 'base':'e5c9b6436876b2a4a39daef813171f9879317699',
 'targetSha256':'3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f',
 'sourceSha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
 'manualProofSha256':hashlib.sha256((B/'node94-nested-maps-proof-draft.md').read_bytes()).hexdigest(),
 'cases':len(rows),'categories':dict(sorted(categories.items())),
 'uncompressedBytes':len(payload),'compressedBytes':len(raw),
 'uncompressedSha256':hashlib.sha256(payload).hexdigest(),'compressedSha256':hashlib.sha256(raw).hexdigest(),
 'gzipOsByte':raw[9],'checkerCreated':False,'capturedExecution':False,'instructionEvaluation':False,
 'scope':'Constructive supplied-field arithmetic for fixed32/ordered two maps; incoming C0..1000/L1000, original-attempt accounting, active output, map ordering, partial errors and cleanup requests. No captured outputs/native ABI/whole greeting/component gate.'}
out.write_bytes(raw);meta_path.write_text(json.dumps(meta,sort_keys=True,indent=2)+'\n',encoding='utf-8',newline='\n')
print(json.dumps(meta,sort_keys=True))

