"""Independent pre-checker greeting request projections, no target evaluator."""
from pathlib import Path
import gzip,hashlib,io,json,sys
B=Path(__file__).resolve().parent
rows=[]
def add(f,i,e):rows.append({'id':str(len(rows)),'family':f,'input':i,'expected':e})
for a in range(256):
    for b in range(256):
        payload=bytes((a,b,0));frame=b'\x00\x00\x00\x03\x00'+payload
        add('greeting-request',{'originalWordHex':bytes((a,b)).hex()},
            {'sourceOffsets':[513,514],'retainedOffsets':[496,497],
             'size':3,'allocationRequests':[3],'capacity':3,'length':3,
             'payloadHex':payload.hex(),'writerLength':3,'compressed':False,
             'frameHex':frame.hex(),'frameLength':8,'chunkSeconds':20})
limit=2**64-1
counts=sorted(set([0,1,2,3,255,256,1023,1024,2**31,2**32,2**63-1,2**63,limit-4,limit-3,limit-2,limit-1,limit]))
for c in counts:
    if c>=limit-2:
        stop={limit:'initial',limit-1:'after-first',limit-2:'after-second'}[c]
        add('size-count',{'count':c},{'normal':False,'stop':stop})
    else:add('size-count',{'count':c},{'normal':True,'countAfter':c+3,'tag':8})
payload=('\n'.join(json.dumps(r,sort_keys=True,separators=(',',':')) for r in rows)+'\n').encode()
buf=io.BytesIO()
with gzip.GzipFile(filename='',mode='wb',fileobj=buf,compresslevel=9,mtime=0) as z:z.write(payload)
raw=buf.getvalue();stem=sys.argv[1]
out=B/(stem+'.jsonl.gz');meta_path=B/(stem+'.json')
if out.exists() or meta_path.exists():raise ValueError('Preserve frozen values')
meta={'state':'greeting-expectations-frozen-before-checker','base':'966865f1637a29ce75b019e1bf11d5529cc6f519',
 'targetSha256':'3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f',
 'sourceSha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
 'manualProofSha256':hashlib.sha256((B/'node94-greeting-proof-draft.md').read_bytes()).hexdigest(),
 'cases':len(rows),'families':{'greeting-request':65536,'size-count':len(counts)},
 'uncompressedBytes':len(payload),'compressedBytes':len(raw),
 'uncompressedSha256':hashlib.sha256(payload).hexdigest(),'compressedSha256':hashlib.sha256(raw).hexdigest(),
 'gzipOsByte':raw[9],'checkerCreated':False,'capturedExecution':False,'instructionEvaluation':False,
 'scope':'Mathematical request-buffer and count projection under manual premises. Arbitrary raw fields are not live-state reachability or original Rust validity. No actual socket write, timer expiry or ABI claim.'}
out.write_bytes(raw);meta_path.write_text(json.dumps(meta,sort_keys=True,indent=2)+'\n',encoding='utf-8',newline='\n')
print(json.dumps(meta,sort_keys=True))
