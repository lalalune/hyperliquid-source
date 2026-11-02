"""Construct expectations from known word values/field boundaries before checker."""
from pathlib import Path
import gzip,hashlib,io,itertools,json,sys
B=Path(__file__).resolve().parent
U=(1<<64)-1
rows=[];seen={}
def encoded(v,wide=False):
    n=9 if wide else 1 if v<251 else 3 if v<65536 else 5 if v<1<<32 else 9
    return bytes([v]) if n==1 else bytes([{3:251,5:252,9:253}[n]])+v.to_bytes(n-1,'little')
def cell(o,v,n=8):return {'offset':o,'hex':v.to_bytes(n,'little').hex()}
def error(kind,**kw):
    cells=[cell(0,1),cell(8,kind,1)]
    if kind==0:cells.append(cell(16,kw['needed']))
    if kind==3:cells.extend([cell(9,kw['expected'],1),cell(10,kw['found'],1)])
    return cells
def construct(family,values,chunks,tail=b'',suffix=b'',charge=0,limit=U,cut=None,bad=None):
    whole=b''.join(chunks)+tail+suffix
    data=whole if cut is None else whole[:cut]
    c=charge;stores=[];pos=0
    def finish(cells):
        inp={'dataHex':data.hex(),'charge':charge,'limit':limit}
        exp={'charge':c,'stores':stores[:],'consumed':pos,'remainingHex':data[pos:].hex(),'cells':cells}
        key=(family,data.hex(),charge,limit)
        if key in seen:
            if seen[key]!=exp:raise ValueError('Constructive authorities disagree')
            return
        seen[key]=exp;rows.append({'id':str(len(rows)),'family':family,'input':inp,'expected':exp})
    for group in range(1 if family=='four-word' else 2):
        if c>U-32:return finish(error(2))
        c+=32;stores.append(c)
        if c>limit:return finish(error(2))
        for i in range(group*4,(group+1)*4):
            available=len(data)-pos
            if bad and i==bad[0]:
                fast=available>8
                if not fast:pos+=1
                return finish(error(3,expected=2 if fast else 3,found=bad[1]))
            width=len(chunks[i])
            if available<width:
                needed=1 if not available else width-available
                if available:pos+=1
                return finish(error(0,needed=needed))
            pos+=width
    if family=='paired-value':
        if c==U:return finish(error(2))
        c+=1;stores.append(c)
        if c>limit:return finish(error(2))
        if pos==len(data):return finish(error(0,needed=1))
        pos+=1
    cells=[cell(0,0)]+[cell(8+8*i,v) for i,v in enumerate(values)]
    if family=='paired-value':cells.append(cell(72,tail[0],1))
    return finish(cells)
V=[0,1,250,251,65535,65536,(1<<32)-1,1<<32,U]
patterns={(0,)*4,tuple(V[:4]),tuple(V[4:8]),(U,)*4}
for i in range(4):
    for value in V+[1<<bit for bit in range(64)]:
        row=[0]*4;row[i]=value;patterns.add(tuple(row))
for a,b in itertools.product(V,repeat=2):patterns.add((a,b,a^b,U-a))
for values,wide,suffix in itertools.product(sorted(patterns),[False,True],[b'',b'\xa5'*8,b'\xa5'*9]):
    construct('four-word',values,[encoded(v,wide) for v in values],suffix=suffix)
pair_patterns=[tuple((V[(j+i)%len(V)]) for i in range(8)) for j in range(len(V))]+[(U,)*8,(0,)*8]
for values,wide,last,suffix in itertools.product(pair_patterns,[False,True],range(256),[b'',b'\xfe'*9]):
    construct('paired-value',values,[encoded(v,wide) for v in values],tail=bytes([last]),suffix=suffix)
# Truncated expectations use known field boundaries/widths, never an input parser.
for family,patterns0 in [('four-word',sorted(patterns)[::19]),('paired-value',pair_patterns)]:
    for values,wide in itertools.product(patterns0,[False,True]):
        chunks=[encoded(v,wide) for v in values];tail=b'\xff' if family=='paired-value' else b''
        for cut in range(sum(map(len,chunks))+len(tail)):
            construct(family,values,chunks,tail=tail,cut=cut)
# FE/FF in any word; padding controls the actual fast/slow admission predicate.
for family,count in [('four-word',4),('paired-value',8)]:
    for index,marker,padding in itertools.product(range(count),[254,255],range(11)):
        values=(0,)*count;chunks=[b'\x00']*count
        chunks[index]=bytes([marker])+b'\xa5'*padding
        chunks=chunks[:index+1]
        # Only preceding known fields exist; evaluation stops at this bad word.
        construct(family,values,chunks,bad=(index,4 if marker==254 else 12))
# Budget/input precedence, overflow, equality and reached-store traces.
C=[0,1,8,U-66,U-65,U-64,U-33,U-32,U-31,U-1,U]
L=[0,1,31,32,33,63,64,65,66,1000,U-1,U]
for family,count in [('four-word',4),('paired-value',8)]:
    for charge,limit,wide,cut in itertools.product(C,L,[False,True],[None,0,1]):
        values=(1,)*count
        construct(family,values,[encoded(v,wide) for v in values],tail=b'\xfe' if count==8 else b'',charge=charge,limit=limit,cut=cut)
payload=('\n'.join(json.dumps(x,sort_keys=True,separators=(',',':')) for x in rows)+'\n').encode()
buf=io.BytesIO()
with gzip.GzipFile(filename='',mode='wb',fileobj=buf,mtime=0,compresslevel=9) as z:z.write(payload)
raw=buf.getvalue();stem=sys.argv[1];out=B/(stem+'.jsonl.gz');meta_path=B/(stem+'.json')
if out.exists() or meta_path.exists():raise ValueError('Preserve frozen authority')
meta={'state':'greeting-value-expectations-frozen-before-aggregate-checker',
    'base':'966865f1637a29ce75b019e1bf11d5529cc6f519',
    'targetSha256':'3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f',
    'sourceSha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    'manualProofSha256':hashlib.sha256((B/'node94-greeting-value-proof-draft.md').read_bytes()).hexdigest(),
    'cases':len(rows),'families':{f:sum(x['family']==f for x in rows) for f in ['four-word','paired-value']},
    'uncompressedBytes':len(payload),'compressedBytes':len(raw),
    'uncompressedSha256':hashlib.sha256(payload).hexdigest(),'compressedSha256':hashlib.sha256(raw).hexdigest(),
    'gzipOsByte':raw[9],'checkerCreated':False,'capturedExecution':False,'instructionEvaluation':False,
    'scope':'Mode QWORD exactly1. Mathematical active-cell/counter/cursor composition, not captured target output, live-state validity or native ABI. Generic scalar grammar/sites credited; no whole map/connection gate.'}
out.write_bytes(raw);meta_path.write_text(json.dumps(meta,sort_keys=True,indent=2)+'\n',encoding='utf-8',newline='\n')
print(json.dumps(meta,sort_keys=True))
