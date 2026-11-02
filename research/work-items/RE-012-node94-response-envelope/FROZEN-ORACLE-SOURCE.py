"""Construct independent response expectations before any aggregate checker."""
from pathlib import Path
import gzip,hashlib,io,itertools,json,sys
B=Path(__file__).resolve().parent;rows=[]
def cell(o,v,n=8):return {'offset':o,'hex':v.to_bytes(n,'little').hex()}
def ref(o,v):return {'offset':o,'ref':'image+'+hex(v),'width':8}
STREAM=[cell(8,0x1122334455667788),cell(32,0x1020304050607080),cell(144,3999,2)]
def constructor(a,n,p):
    limit=1000 if a==0 else 3000000000
    return {'readLimit':limit,'diagnosticFlag':a,'decodeState':{'mode':1,'limit':limit,'pointer':p,'remaining':n,'charge':0}}
def envelope(a,n,cap,p,tag,remaining,cells):
    c=constructor(a,n,p)
    if tag!=8 and remaining>n:
        return {'constructor':c,'diagnosticConsumed':None,'route':'wrapper-underflow',
                'wrapperCells':[],'releaseRequests':[],'outerCells':[]}
    return {'constructor':c,'diagnosticConsumed':0 if tag==8 else n-remaining,
      'route':'caller-error-conversion' if tag==8 else 'return',
      'wrapperCells':cells,'releaseRequests':[[p,cap,0]] if cap else [],
      'outerCells':[] if tag==8 else cells+[cell(120,0)]+[dict(x,offset=x['offset']+120) for x in STREAM]}
def add(f,i,e):rows.append({'id':str(len(rows)),'family':f,'input':i,'expected':e})
for a in range(256):
    n=a+1;p=0x4000+a*16
    add('constructor',{'flag':a,'length':n,'pointer':p},constructor(a,n,p))
for a,n,tag in itertools.product([0,1,255],[0,1,4,64],range(9)):
    for rem in sorted(set([0,max(0,n-1),n,n+1,2**64-1])):
        for cap in sorted(set([n,n+16])):
            cells=[cell(0,tag)]
            if tag==3:cells += [cell(8,22),cell(16,33),cell(24,11)]
            if tag==8:cells += [cell(8,2,1)]
            i={'flag':a,'length':n,'capacity':cap,'pointer':0x12340000,
               'resultTag':tag,'remaining':rem,'responseCells':cells,'streamCells':STREAM}
            add('envelope',i,envelope(a,n,cap,i['pointer'],tag,rem,cells))
def encoded(v,width=None):
    if width is None:width=1 if v<251 else 3 if v<=65535 else 5 if v<=0xffffffff else 9
    if width==1:return bytes([v])
    return bytes([{3:251,5:252,9:253}[width]])+v.to_bytes(width-1,'little')
def err(kind,**kw):
    cells=[cell(0,8),cell(8,kind,1)]
    if kind==0:cells.append(cell(16,kw['needed']))
    if kind==3:cells += [cell(9,kw['expected'],1),cell(10,kw['found'],1)]
    if kind==5:cells += [cell(12,kw['value'],4),ref(16,0x3e63d4),cell(24,18),ref(32,0x203580)]
    return cells
def bytes_case(data,tag,cells,charge,consumed):
    a=len(rows)%2;n=len(data);cap=n+16 if n else 0;p=0x12345600
    i={'flag':a,'dataHex':data.hex(),'capacity':cap,'pointer':p,'streamCells':STREAM}
    e={'logicalCharge':charge,'innerConsumed':consumed,'remainingHex':data[consumed:].hex(),
       'decoderCells':cells,'envelope':envelope(a,n,cap,p,tag,n-consumed,cells)}
    add('simple-response',i,e)
for selector,width in itertools.product(range(2,6),[1,3,5]):
    h=encoded(selector,width)
    suffixes=[b'',b'\x00',b'\xff\x00',bytes(range(16)),b'\xa5'*(1000-len(h))]
    for suffix in suffixes:bytes_case(h+suffix,selector+2,[cell(0,selector+2)],4,len(h))
values=[0,1,250,251,65535,65536,0xffffffff,0x100000000,2**64-1]
for triple,width,wide,suffix in itertools.product(itertools.product(values,repeat=3),[1,3,5],[False,True],[b'',b'\xff\x00']):
    h=encoded(1,width);fields=[encoded(v,9 if wide else None) for v in triple]
    raw=h+b''.join(fields);x,y,z=triple
    bytes_case(raw+suffix,3,[cell(0,3),cell(8,y),cell(16,z),cell(24,x)],28,len(raw))
for selector in list(range(6,251))+[251,65535,65536,0xffffffff]:
    for width in [1,3,5]:
        if width==1 and selector>=251 or width==3 and selector>65535:continue
        h=encoded(selector,width)
        for suffix in [b'',bytes(range(16))]:bytes_case(h+suffix,8,err(5,value=selector),4,len(h))
bytes_case(b'',8,err(0,needed=1),4,0)
for width in [3,5]:
    h=encoded(2,width)
    for n in range(1,width):bytes_case(h[:n],8,err(0,needed=width-n),4,1)
for marker,found in [(253,3),(254,4),(255,12)]:
    for padding in range(10):
        raw=bytes([marker])+b'\xa5'*padding
        bytes_case(raw,8,err(3,expected=2,found=found),4,1 if len(raw)<=4 else 0)
# Constructive truncation expectations from known field boundaries, not a parser.
for triple in [(251,65536,2**64-1),(0,1,250),(65535,0xffffffff,0x100000000)]:
    for hw in [1,3,5]:
        h=encoded(1,hw);fields=[encoded(v) for v in triple];whole=h+b''.join(fields)
        for cut in range(len(h),len(whole)):
            offset=len(h)
            for index,field in enumerate(fields):
                if cut>=offset+len(field):offset+=len(field);continue
                available=cut-offset
                consumed=offset+(1 if available else 0)
                need=1 if not available else len(field)-available
                bytes_case(whole[:cut],8,err(0,needed=need),4+8*(index+1),consumed)
                break
payload=('\n'.join(json.dumps(r,sort_keys=True,separators=(',',':')) for r in rows)+'\n').encode()
buf=io.BytesIO()
with gzip.GzipFile(filename='',mode='wb',fileobj=buf,compresslevel=9,mtime=0) as z:z.write(payload)
raw=buf.getvalue();stem=sys.argv[1];out=B/(stem+'.jsonl.gz');receipt=B/(stem+'.json')
if out.exists() or receipt.exists():raise ValueError('Preserve frozen corpus')
families={f:sum(r['family']==f for r in rows) for f in sorted({r['family'] for r in rows})}
meta={'state':'response-expectations-frozen-before-checker','base':'966865f1637a29ce75b019e1bf11d5529cc6f519',
 'targetSha256':'3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f',
 'sourceSha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
 'manualProofSha256':hashlib.sha256((B/'node94-response-proof-draft.md').read_bytes()).hexdigest(),
 'cases':len(rows),'families':families,'uncompressedBytes':len(payload),'compressedBytes':len(raw),
 'uncompressedSha256':hashlib.sha256(payload).hexdigest(),'compressedSha256':hashlib.sha256(raw).hexdigest(),
 'gzipOsByte':raw[9],'checkerCreated':False,'capturedExecution':False,'instructionEvaluation':False,
 'scope':'Actual response constructor and conditional defined-result envelope; simple selector1..5/scalar-failure byte cases corroborate composition. Scalar primitive/schema ownership credited. Selector0 byte decoding excluded. Supplied decoder cells are admitted synthetic projections, not live-state/ABI validity. Image references/pointers are symbolic tokens.'}
out.write_bytes(raw);receipt.write_text(json.dumps(meta,sort_keys=True,indent=2)+'\n',encoding='utf-8',newline='\n')
print(json.dumps(meta,sort_keys=True))
