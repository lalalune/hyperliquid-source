"""Construct three-record expectations from known words and array boundaries.

Created before a protocol checker. No arbitrary-byte parser or CPU evaluator.
"""
from pathlib import Path
import collections,gzip,hashlib,io,itertools,json,sys
B=Path(__file__).resolve().parent;U=(1<<64)-1
rows=[];seen={};categories=collections.Counter()
def encoded(v,wide=False):
    width=9 if wide else 1 if v<251 else 3 if v<65536 else 5 if v<1<<32 else 9
    return bytes([v]) if width==1 else bytes([{3:251,5:252,9:253}[width]])+v.to_bytes(width-1,'little')
def cell(o,v,n=8):return {'offset':o,'hex':v.to_bytes(n,'little').hex()}
def error(kind,needed=None,expected=None,found=None):
    cells=[cell(0,1),cell(8,kind,1)]
    if kind==0:cells.append(cell(16,needed))
    if kind==3:cells.extend([cell(9,expected,1),cell(10,found,1)])
    return cells
def buffers(seed):return [bytes((seed+73*j+29*k)&255 for k in range(2048)) for j in range(3)]
def construct(category,words,arrays,wide=False,suffix=b'',charge=0,limit=U,cut=None,bad=None):
    if len(words)!=6 or len(arrays)!=3 or any(len(a)!=2048 for a in arrays):raise ValueError('Known record fields')
    fields=[]
    for j in range(3):fields.extend([encoded(words[2*j],wide),encoded(words[2*j+1],wide),arrays[j]])
    if bad is not None:
        stage,marker,padding=bad
        if stage%3==2 or marker not in [254,255]:raise ValueError('Bad scalar site')
        fields=fields[:stage]+[bytes([marker])+b'\xa5'*padding]
    whole=b''.join(fields)+suffix;data=whole if cut is None else whole[:cut]
    counter=charge;stores=[];consumed=0
    def finish(cells):
        inp={'dataHex':data.hex(),'charge':charge,'limit':limit,'mode':1}
        expected={'charge':counter,'stores':stores[:],'consumed':consumed,'remainingHex':data[consumed:].hex(),'cells':cells}
        identity=(data,charge,limit)
        if identity in seen:
            if seen[identity]!=expected:raise ValueError('Constructive authorities disagree')
            return
        seen[identity]=expected
        rows.append({'id':str(len(rows)),'category':category,'input':inp,'expected':expected});categories[category]+=1
    for stage in range(9):
        amount=2048 if stage%3==2 else 8
        if counter>U-amount:return finish(error(2))
        counter+=amount;stores.append(counter)
        if counter>limit:return finish(error(2))
        available=len(data)-consumed
        if bad is not None and stage==bad[0]:
            fast=available>8
            if not fast:consumed+=1
            return finish(error(3,expected=5,found=4 if bad[1]==254 else 12))
        width=len(fields[stage])
        if available<width:
            if stage%3==2:return finish(error(0,needed=2048-available))
            if available:consumed+=1
            return finish(error(0,needed=width-available if available else 1))
        consumed+=width
    cells=[cell(0,0)]
    for j,array in enumerate(arrays):
        base=8+2064*j
        cells.extend([{'offset':base,'hex':array.hex()},cell(base+2048,words[2*j]),cell(base+2056,words[2*j+1])])
    return finish(cells)

zero=[bytes(2048)]*3;Z=(0,)*6;V=[0,1,250,251,65535,65536,(1<<32)-1,1<<32,U]
# Every byte position in all three arrays receives distinct marker values.
for position in range(2048):
    arrays=[bytearray(2048) for _ in range(3)]
    for array,value in zip(arrays,[85,170,255]):array[position]=value
    construct('all-array-byte-coordinates',Z,[bytes(a) for a in arrays])
boundaries=[0,1,6,7,8,14,15,16,22,23,24,30,31,32,63,64,1023,1024,2046,2047]
for record,position,bit in itertools.product(range(3),boundaries,range(8)):
    arrays=list(zero);a=bytearray(2048);a[position]=1<<bit;arrays[record]=bytes(a)
    construct('individual-array-boundary-bits',Z,arrays)
for word,value in itertools.product(range(6),V+[1<<bit for bit in range(64)]):
    values=[0]*6;values[word]=value
    construct('word-order-and-high-bits',values,zero)
for seed,wide in itertools.product(range(32),[False,True]):
    values=tuple(V[(seed+j)%len(V)] for j in range(6))
    construct('patterned-records',values,buffers(seed),wide)
for value in range(256):
    arrays=[bytes([(value+85*j)&255])*2048 for j in range(3)]
    construct('all-raw-array-byte-values',tuple(range(6)),arrays)
for order in itertools.permutations(range(3)):
    arrays=buffers(7);words=[10,11,20,21,30,31]
    construct('record-permutations',sum(([words[2*j],words[2*j+1]] for j in order),[]),[arrays[j] for j in order])
# Exhaust every cut of one maximum-width record sequence. Field boundaries
# construct each shortage; the source does not parse the bytes to predict it.
arrays=buffers(13);values=(U,)*6;length=6144+6*9
for cut in range(length):construct('every-maximal-wire-truncation',values,arrays,True,cut=cut)
minimal_words=(1,)*6;minimal_length=6150
ends=[0,1,2,2050,2051,2052,4100,4101,4102,6150]
for cut in sorted({max(0,min(minimal_length,k+d)) for k in ends for d in range(-3,4)}):
    construct('minimal-wire-stage-boundaries',minimal_words,arrays,cut=cut)
for wide,suffix in itertools.product([False,True],[b'',b'\xfe'*8,b'\xff'*9]):
    construct('suffix-and-nonminimal-widths',minimal_words,arrays,wide,suffix)
# Precharge/limit/overflow precedence at all nine reached stage boundaries.
costs=[8,16,2064,2072,2080,4128,4136,4144,6192]
charges=[0,1,997,U-6193,U-6192,U-6191,U-2065,U-2064,U-2049,U-2048,U-17,U-16,U-9,U-8,U-7,U]
limits=[0,1,7,8,15,16,1000,2063,2064,2071,2072,4127,4128,4135,4136,6191,6192,6193,U]
for charge,limit,wide,cut in itertools.product(charges,limits,[False,True],[None,0,1,2]):
    construct('budget-and-input-precedence',minimal_words,zero,wide,charge=charge,limit=limit,cut=cut)
for cost in costs:
    for charge in [0,1,997,U-cost,U-cost+1]:
        if charge>U:continue
        total=min(U,charge+cost)
        for limit in {max(0,total-1),total,min(U,total+1)}:
            construct('exact-stage-charge-limits',minimal_words,arrays,charge=charge,limit=limit)
for stage,marker,padding,limit in itertools.product([0,1,3,4,6,7],[254,255],range(11),[0,1000,U]):
    construct('invalid-scalar-marker-ordering',Z,arrays,limit=limit,bad=(stage,marker,padding))

payload=('\n'.join(json.dumps(row,sort_keys=True,separators=(',',':')) for row in rows)+'\n').encode()
buf=io.BytesIO()
with gzip.GzipFile(filename='',mode='wb',fileobj=buf,mtime=0,compresslevel=9) as z:z.write(payload)
compressed=buf.getvalue();stem=sys.argv[1];out=B/(stem+'.jsonl.gz');meta_path=B/(stem+'.json')
if out.exists() or meta_path.exists():raise ValueError('Preserve frozen authority')
meta={'state':'three-record-expectations-frozen-before-protocol-checker','base':'e5c9b6436876b2a4a39daef813171f9879317699',
 'targetSha256':'3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f',
 'sourceSha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
 'manualProofSha256':hashlib.sha256((B/'node94-greeting-records-proof-draft.md').read_bytes()).hexdigest(),
 'cases':len(rows),'categories':dict(sorted(categories.items())),
 'uncompressedBytes':len(payload),'compressedBytes':len(compressed),
 'uncompressedSha256':hashlib.sha256(payload).hexdigest(),'compressedSha256':hashlib.sha256(compressed).hexdigest(),
 'gzipOsByte':compressed[9],'checkerCreated':False,'capturedExecution':False,'instructionEvaluation':False,
 'scope':'Constructive word/array-boundary mathematics for mode1 three-record decoding, active array-first output, ordered charges/stores, partial input and errors. Not captured target output, native ABI or complete caller/greeting/connection equivalence.'}
out.write_bytes(compressed);meta_path.write_text(json.dumps(meta,sort_keys=True,indent=2)+'\n',encoding='utf-8',newline='\n')
print(json.dumps(meta,sort_keys=True))
