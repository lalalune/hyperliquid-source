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

def construct(category,count,plans=(),charge=0,count_width=None,suffix=b'',cut=None,bad_count=None):
    plans=list(plans)
    if not 0<=charge<=U:raise ValueError('Charge domain')
    if bad_count is not None:
        marker,padding=bad_count
        prefix=bytes([marker])+b'\xa5'*padding
    else:prefix=encoded(count,count_width)
    body=b''.join(p['key']+b''.join(p['chunks'])+p['tail'] for p in plans)
    whole=prefix+body+suffix
    data=whole if cut is None else whole[:cut]
    cursor=0;counter=charge;stores=[];completed=[];comparisons=[];moves=[];allocated=False

    def finish(cells,success=False):
        nonlocal allocated
        associations=[]
        if success:
            keys=sorted({p['key'] for p in completed})
            for key in keys:
                final=next(p for p in reversed(completed) if p['key']==key)
                associations.append({'keyHex':key.hex(),'words':list(final['values']),'byte':final['last']})
        projection={'charge':counter,'stores':stores[:],'consumed':cursor,'remainingHex':data[cursor:].hex(),
          'cells':cells,'associations':associations,
          'allocationRequests':[{'symbol':'leaf0','bytes':1024}] if allocated else [],
          'releaseRequests':[{'symbol':'leaf0','bytes':1024,'flags':0}] if allocated and not success else [],
          'comparisons':comparisons[:],'movements':moves[:]}
        inp={'dataHex':data.hex(),'charge':charge,'mode':1,'limit':1000}
        identity=(data,charge)
        if identity in seen:
            if seen[identity]!=projection:raise ValueError('Constructive authorities disagree')
            return
        seen[identity]=projection
        rows.append({'id':str(len(rows)),'category':category,'input':inp,'expected':projection})
        categories[category]+=1

    # Constructed count scalar: charge before any availability or marker test.
    if counter>U-8:return finish(error(2))
    counter+=8;stores.append(counter)
    if counter>1000:return finish(error(2))
    if bad_count is not None:
        marker,_=bad_count
        fast=len(data)>8
        if not fast:cursor=1
        return finish(error(3,expected=2 if fast else 3,found=4 if marker==254 else 12))
    if len(data)<len(prefix):
        if data:cursor=1
        return finish(error(0,needed=len(prefix)-len(data) if data else 1))
    cursor=len(prefix)
    reservation=96*count
    if reservation>U or counter+reservation>U:return finish(error(2))
    counter+=reservation;stores.append(counter)
    if counter>1000:return finish(error(2))
    if count>10:raise ValueError('Admission proof failed')
    if len(plans)!=count:raise ValueError('Known admitted rows required')
    admitted=counter
    for j,p in enumerate(plans):
        # This arithmetic assertion is a theorem check, never a CPU interpreter.
        if counter!=admitted-11*j or counter<96:raise ValueError('Refund invariant')
        counter-=96;stores.append(counter)
        counter+=20;stores.append(counter)
        if len(data)-cursor<20:return finish(error(0,needed=20-(len(data)-cursor)))
        cursor+=20
        for group in range(2):
            counter+=32;stores.append(counter)
            if counter>admitted:raise ValueError('Admitted-stage budget invariant')
            for i in range(group*4,(group+1)*4):
                available=len(data)-cursor
                if p['bad'] is not None and i==p['bad'][0]:
                    marker=p['bad'][1];fast=available>8
                    if not fast:cursor+=1
                    return finish(error(3,expected=2 if fast else 3,found=4 if marker==254 else 12))
                width=len(p['chunks'][i])
                if available<width:
                    if available:cursor+=1
                    return finish(error(0,needed=width-available if available else 1))
                cursor+=width
        counter+=1;stores.append(counter)
        if counter>admitted:raise ValueError('Final-byte budget invariant')
        if cursor==len(data):return finish(error(0,needed=1))
        cursor+=1
        # Derive insertion rank and search/move requests from a sorted prefix set.
        before=sorted({x['key'] for x in completed});key=p['key']
        candidates=[k for k in before if k<key]
        upper=[k for k in before if k>=key]
        if upper:candidates.append(upper[0])
        comparisons.extend({'leftKeyHex':key.hex(),'rightKeyHex':k.hex(),'bytes':20} for k in candidates)
        if key not in before:
            if not before:allocated=True
            else:
                index=sum(k<key for k in before);moved=len(before)-index
                if moved:
                    moves.extend([
                      {'symbol':'leaf0','sourceOffset':800+20*index,'destinationOffset':800+20*(index+1),'bytes':20*moved},
                      {'symbol':'leaf0','sourceOffset':8+72*index,'destinationOffset':8+72*(index+1),'bytes':72*moved}])
        completed.append(p)
    if counter!=admitted-11*count:raise ValueError('Final accounting')
    cells=[cell(0,18,1),{'offset':8,'symbol':'leaf0'} if allocated else cell(8,0)]
    if allocated:cells.append(cell(16,0))
    cells.append(cell(24,len({p['key'] for p in completed})))
    return finish(cells,True)

def sequence(keys,wide=False):return [plan(k,i,wide) for i,k in enumerate(keys)]

# Prefix charge, same-value M0 store, reservation multiplication/addition and
# exact admitted/equal/over-limit boundaries; no huge body allocation is used.
counts=list(range(13))+[250,251,65535,65536,(1<<32)-1,1<<32,U//96-1,U//96,U//96+1,U]
charges=[0,1,7,8,31,32,39,40,41,55,56,63,64,991,992,993,1000,U-8,U-7,U]
for count,charge,wide,suffix in itertools.product(counts,charges,[False,True],[b'',b'\xa5'*9]):
    ps=sequence([rankkey(i) for i in range(count)]) if count<=10 else []
    construct('count-and-reservation',count,ps,charge,9 if wide else None,suffix)
for count in range(11):
    boundary=992-96*count
    for charge in [max(0,boundary-1),boundary,boundary+1]:
        for width in [None,3,5,9]:
            for duplicate in [False,True]:
                ps=sequence([rankkey(0 if duplicate else i) for i in range(count)])
                construct('exact-limit-count',count,ps,charge,width)

# Every binary/ternary short key history, plus long histories up to the ten
# attempt limit, with different supplied values on every replacement.
for n in range(8):
    for ranks in itertools.product(range(3),repeat=n):
        construct('short-key-histories',n,sequence([rankkey(k) for k in ranks]))
for n in [8,9,10]:
    for ranks in itertools.product(range(2),repeat=n):
        construct('long-duplicate-histories',n,sequence([rankkey(k) for k in ranks]))

# All five-key permutations and a search/insertion at each rank of each
# possible preceding nonfull-leaf size, ascending and descending.
for ranks in itertools.permutations(range(5)):
    construct('five-key-orders',5,sequence([rankkey(k) for k in ranks]))
for n in range(1,10):
    for reverse in [False,True]:
        before=list(range(0,2*n,2))[::(-1 if reverse else 1)]
        for rank in range(2*n+1):
            construct('all-nonfull-insertion-ranks',n+1,sequence([rankkey(k) for k in before+[rank]]))

# Unsigned lexicographic key order, full20byte comparisons and layout boundaries.
for position in range(20):
    for a,b in [(0,1),(127,128),(128,255),(0,255)]:
        left=bytearray(b'\x55'*20);right=bytearray(left)
        left[position]=a;right[position]=b
        for keys in [[bytes(left),bytes(right)],[bytes(right),bytes(left)],[bytes(right),bytes(left),bytes(right)]]:
            construct('key-byte-order',len(keys),sequence(keys))
for position,bit in itertools.product(range(20),range(8)):
    changed=bytearray(20);changed[position]=1<<bit
    construct('key-bit-boundaries',3,sequence([bytes(changed),bytes(20),bytes(changed)]))
for first,second in itertools.combinations(range(20),2):
    left=bytearray(20);right=bytearray(20)
    left[first]=1;right[second]=2
    for keys in [[bytes(left),bytes(right)],[bytes(right),bytes(left),bytes(right)]]:
        construct("cross-position-lexicographic-keys",len(keys),sequence(keys))
for index,value in itertools.product(range(8),V+[1<<b for b in range(64)]):
    values=[0]*8;values[index]=value
    construct('value-defined-word-projection',1,[plan(rankkey(1),values=values)])
for last,wide in itertools.product(range(256),[False,True]):
    construct('raw-tail-and-duplicate-value',2,[plan(rankkey(7),0,wide),plan(rankkey(7),1,wide,last=last)],suffix=b'\xff'*9)

# Each truncation is predicted from selected field lengths. Complete prefixes
# include duplicates, nonminimal encodings, maximum ten attempts and cleanup.
for count,wide,duplicate in itertools.product([1,2,5,10],[False,True],[False,True]):
    ps=sequence([rankkey(0 if duplicate else (count-i)) for i in range(count)],wide)
    count_width=9 if wide else None
    length=len(encoded(count,count_width))+sum(20+sum(map(len,p['chunks']))+1 for p in ps)
    for cut in range(length):
        construct('every-byte-truncation',count,ps,count_width=count_width,cut=cut)

# Invalid count markers at the actual <=8/>8 boundary; charge failures win.
for marker,padding,charge in itertools.product([254,255],range(11),[0,992,993,U-7]):
    construct('bad-count-marker',0,charge=charge,bad_count=(marker,padding))
for width in [3,5,9]:
    for cut,charge in itertools.product(range(width),[0,992,993]):
        construct('short-count-prefix',0,charge=charge,count_width=width,cut=cut)

# A bad value field after zero/one/nine full entries. Its suffix controls the
# Reader vs fast path. The bad field is final wire material, so no fake next
# row or raw-tail byte can turn an intended shortage into a successful read.
for done,index,marker,padding in itertools.product([0,1,9],range(8),[254,255],range(11)):
    prior=sequence([rankkey(i%3) for i in range(done)])
    bad=plan(rankkey(100),done,values=(0,)*8)
    bad['chunks']=[b'\x00']*index+[bytes([marker])+b'\xa5'*padding]
    bad['tail']=b'';bad['bad']=(index,marker)
    construct('bad-value-marker-and-cleanup',done+1,prior+[bad])

payload=('\n'.join(json.dumps(r,sort_keys=True,separators=(',',':')) for r in rows)+'\n').encode()
buf=io.BytesIO()
with gzip.GzipFile(filename='',mode='wb',fileobj=buf,mtime=0,compresslevel=9) as z:z.write(payload)
raw=buf.getvalue();stem=sys.argv[1];out=B/(stem+'.jsonl.gz');meta_path=B/(stem+'.json')
if out.exists() or meta_path.exists():raise ValueError('Preserve frozen authority')
meta={'state':'small-limit-greeting-map-expectations-frozen-before-map-checker',
  'proofBase':'966865f1637a29ce75b019e1bf11d5529cc6f519',
  'reviewedBase':'e5c9b6436876b2a4a39daef813171f9879317699',
  'targetSha256':'3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f',
  'sourceSha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
  'manualProofSha256':hashlib.sha256((B/'node94-greeting-map-proof-draft.md').read_bytes()).hexdigest(),
  'manualAddendumSha256':hashlib.sha256((B/'node94-greeting-map-proof-addendum.md').read_bytes()).hexdigest(),
  'cases':len(rows),'categories':dict(sorted(categories.items())),
  'uncompressedBytes':len(payload),'compressedBytes':len(raw),
  'uncompressedSha256':hashlib.sha256(payload).hexdigest(),'compressedSha256':hashlib.sha256(raw).hexdigest(),
  'gzipOsByte':raw[9],'checkerCreated':False,'capturedExecution':False,'instructionEvaluation':False,
  'scope':'Constructive mathematics for mode1/limit1000 map admission, attempt accounting, sorted last-value associations, active cells, search/move/allocation/release requests and partial input failures. Not captured outputs, runtime ABI, all-limit trees, allocator implementation, whole greeting or a component gate.'}
out.write_bytes(raw);meta_path.write_text(json.dumps(meta,sort_keys=True,indent=2)+'\n',encoding='utf-8',newline='\n')
print(json.dumps(meta,sort_keys=True))
