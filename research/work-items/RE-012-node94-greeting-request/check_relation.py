"""Aggregate byte-request relation, independent of the prefrozen oracle."""
from pathlib import Path
import gzip,hashlib,json,struct,sys
B=Path(__file__).resolve().parent
SOURCE=B/'expectations.jsonl.gz'
META=B/'FROZEN.json'
def request(i,wrong=None):
    word=int.from_bytes(bytes.fromhex(i['originalWordHex']),'little')
    a=word&255;b=(word>>8)&255
    values=[a,b,0]
    if wrong=='swap-fields':values=[b,a,0]
    if wrong=='coerce-booleans':values=[int(bool(a)),int(bool(b)),0]
    if wrong=='omit-zero':values=values[:2]
    if wrong=='nonzero-suffix':values[2]=1
    payload=bytes(values)
    if wrong=='diagnostic-as-payload':payload=b'abci_stream send tcp greeting'
    n=len(payload);compressed=wrong=='compressed-small'
    head=struct.pack('<I' if wrong=='little-length' else '>I',n)
    if wrong=='wide-length':head=struct.pack('>Q',n)
    frame=head+bytes([int(compressed)])+payload
    return {'sourceOffsets':[513,514] if wrong!='wrong-source-offsets' else [512,513],
      'retainedOffsets':[496,497],'size':n,'allocationRequests':[n],
      'capacity':n,'length':n,'payloadHex':payload.hex(),'writerLength':n,
      'compressed':compressed,'frameHex':frame.hex(),'frameLength':len(frame),
      'chunkSeconds':60 if wrong=='stored-timeout-wins' else 20}
def count(i,wrong=None):
    c=i['count'];limit=(1<<64)-1
    if wrong=='unchecked-size':return {'normal':True,'countAfter':(c+3)&limit,'tag':8}
    if c==limit:return {'normal':False,'stop':'initial'}
    if c+1==limit:return {'normal':False,'stop':'after-first'}
    if c+2==limit:return {'normal':False,'stop':'after-second'}
    return {'normal':True,'countAfter':c+(2 if wrong=='size-two' else 3),'tag':8}
functions={'greeting-request':request,'size-count':count}
wrongs={'greeting-request':['swap-fields','coerce-booleans','omit-zero','nonzero-suffix',
 'diagnostic-as-payload','compressed-small','little-length','wide-length',
 'wrong-source-offsets','stored-timeout-wins'],'size-count':['unchecked-size','size-two']}
meta=json.loads(META.read_bytes());raw=SOURCE.read_bytes()
if hashlib.sha256(raw).hexdigest()!=meta['compressedSha256']:raise ValueError('Frozen compressed identity')
data=gzip.decompress(raw)
if hashlib.sha256(data).hexdigest()!=meta['uncompressedSha256']:raise ValueError('Frozen values differ')
rows=[json.loads(x) for x in data.splitlines()]
if len(rows)!=meta['cases']:raise ValueError('Frozen denominator differs')
counts={k:0 for k in functions};mutants={w:0 for ws in wrongs.values() for w in ws}
for r in rows:
    f=r['family'];fun=functions[f]
    if fun(r['input'])!=r['expected']:raise ValueError('Independent relation differs '+r['id'])
    counts[f]+=1
    for wrong in wrongs[f]:mutants[wrong]+=fun(r['input'],wrong)!=r['expected']
if counts!=meta['families'] or any(x==0 for x in mutants.values()):raise ValueError('Incomplete or neutral wrong rules')
receipt={'state':'greeting-abstract-request-check-unqualified','cases':counts,'wrongRules':mutants,
 'frozenSha256':meta['compressedSha256'],'capturedExecution':False,'instructionEvaluation':False,
 'networkOperations':0,'nativeEquivalence':False,
 'scope':'Three-byte serializer to frame-request buffer under manual helper premises. Raw byte projections are not original type validity; no socket delivery, timer expiry, scheduling or full transport/ABI equivalence.'}
out=B/sys.argv[1]
if out.exists():raise ValueError('Preserve prior check')
out.write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n',encoding='utf-8',newline='\n')
print(json.dumps(receipt,sort_keys=True))
