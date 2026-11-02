"""Independent request-byte/result expectations, before a checker or implementation.

These are synthetic mathematical expectations justified by the addressed manual
argument, not captured instruction evaluations or observed networking results.
"""
from pathlib import Path
import gzip,hashlib,io,json,sys
B=Path(__file__).resolve().parent
BASE=[4001,4002,4003,4004,3998,3999]
configs={}
def add(d,b,label):configs.setdefault((d,bytes(b)),set()).add(label)
for d in range(6):
    for position in range(4):
        for value in range(256):
            ip=bytearray([192,0,2,17]);ip[position]=value
            add(d,bytes([0])+ip,'all-ip-byte-'+str(position))
    for b0 in range(256):
        for index in [0,1,61,62,65,66,255]:
            add(d,bytes([b0,index,0,2,17]),'flag-high-bits-and-index-boundaries')
    for index in range(256):add(d,bytes([1,index,0,0,0]),'credited-port-full-index-domain')
addresses=[]
for i,((d,b),labels) in enumerate(sorted(configs.items())):
    local=(b[0]%2)==1
    index=b[1]
    if local and index>=66:result={'kind':'credited-multiply-panic-no-request'}
    elif local and index>=62:result={'kind':'credited-add-panic-no-request'}
    else:
        port=BASE[d]+(1000*index if local else 0)
        ip=bytes([127,0,0,1]) if local else b[1:5]
        frame=bytes([2,0])+port.to_bytes(2,'big')+ip+bytes(8)
        result={'kind':'request','domain':2,'type':526337,'protocol':0,
                'addrlen':16,'frameHex':frame.hex()}
    addresses.append({'id':'a%05d'%i,'input':{'selector':d,'packedHex':b.hex()},
                      'expected':result,'provenance':sorted(labels)})
# Every semantic field class gets independent basis/boundary error words.
errors=sorted({-(1<<31),-1,0,1,4,11,22,114,115,116,(1<<31)-1}|
              {1<<i for i in range(31)}|{-(1<<i) for i in range(31)})
outcomes=[]
for fd in [-2147483648,-2,-1,0,1,17,2147483647]:
    for cr in [-2147483648,-2,-1,0,1,2147483647]:
        for errno in errors:
            if fd<0:
                result={'tag':1,'errorWord':(((errno%(1<<32))<<32)|2),
                        'connectRequests':0,'closeRequests':0}
            elif cr>=0 or errno==115:
                result={'tag':0,'fd':fd,'connectRequests':1,'closeRequests':0}
            else:
                result={'tag':1,'errorWord':(((errno%(1<<32))<<32)|2),
                        'connectRequests':1,'closeRequests':1,'closeFd':fd}
            outcomes.append({'id':'r%05d'%len(outcomes),'input':{'socketReturn':fd,'connectReturn':cr,'errno':errno},
                             'expected':result,'provenance':'ordinary-import-result-basis-and-boundaries'})
rows=[dict(family='address',**x) for x in addresses]+[dict(family='result',**x) for x in outcomes]
payload=('\n'.join(json.dumps(x,sort_keys=True,separators=(',',':')) for x in rows)+'\n').encode()
buffer=io.BytesIO()
with gzip.GzipFile(filename='',mode='wb',fileobj=buffer,compresslevel=9,mtime=0) as gz:gz.write(payload)
raw=buffer.getvalue()
stem=sys.argv[1];archive=B/(stem+'.jsonl.gz');receipt=B/(stem+'.json')
if archive.exists() or receipt.exists():raise ValueError('Preserve previous freeze')
archive.write_bytes(raw)
record={'state':'first-connect-expectations-frozen-before-checker','targetSha256':'3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f',
 'base':'966865f1637a29ce75b019e1bf11d5529cc6f519','sourceSha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
 'manualProofSha256':hashlib.sha256((B/'node94-first-connect-proof-draft.md').read_bytes()).hexdigest(),
 'addressCases':len(addresses),'resultCases':len(outcomes),'cases':len(rows),'errorWordRepresentatives':len(errors),
 'uncompressedBytes':len(payload),'compressedBytes':len(raw),'uncompressedSha256':hashlib.sha256(payload).hexdigest(),
 'compressedSha256':hashlib.sha256(raw).hexdigest(),'gzipOsByte':raw[9],
 'capturedExecution':False,'instructionEvaluation':False,'networkOperations':0,'implementationCreated':False,
 'limits':'Declared request byte order and ordinary-import result classes only. Port/panic arithmetic is credited context. No runtime, original ABI, descriptor ownership or whole-future equivalence.'}
receipt.write_text(json.dumps(record,sort_keys=True,indent=2)+'\n',encoding='utf-8',newline='\n')
print(json.dumps(record,sort_keys=True))
