"""Independent codec/envelope abstractions versus previously frozen normative data."""
from pathlib import Path
import json,gzip,hashlib,datetime,collections
B=Path(__file__).resolve().parent
meta=json.loads((B/'FROZEN-CORPUS.json').read_text())
compressed=(Path(__import__('sys').argv[1])).read_bytes();raw=gzip.decompress(compressed)
if hashlib.sha256(compressed).hexdigest()!=meta['compressedSha256'] or hashlib.sha256(raw).hexdigest()!=meta['uncompressedSha256']:raise ValueError('Frozen UTF8 corpus changed')
envraw=(B/'frozen-envelope.json').read_bytes()
if hashlib.sha256(envraw).hexdigest()!=meta['envelopeSha256']:raise ValueError('Frozen envelope corpus changed')
def codec(data):
    try:data.decode('utf-8','strict');return (0,None,None)
    except UnicodeDecodeError as e:return (1,e.start,None if e.reason=='unexpected end of data' else e.end-e.start)
count=0;selected={};digest=hashlib.sha256()
for line in raw.splitlines():
    text,tag,start,length=line.decode().split('\t');data=bytes.fromhex(text)
    want=(int(tag),None if start=='-' else int(start),None if length=='-' else int(length))
    got=codec(data)
    if got!=want:raise ValueError('Independent strict codec disagrees: '+text+' '+str((want,got)))
    count+=1;digest.update(line+b'\n')
    if data in [b'\x00',b'\xc0\x80',b'\xed\xa0\x80\x80',b'\xf4\x90\x80\x80',b'\xc2',b'A\x80']:selected[text]=want
if count!=meta['utf8Cases'] or digest.hexdigest()!=meta['uncompressedSha256']:raise ValueError('Frozen count/order changed')
def envelope(inp,mutant=None):
    data=bytes.fromhex(inp['initializedPrefixHex']);opened=inp['opened'];read_error=inp['readError']
    close=int(opened)
    if not opened:return dict(kind='error',payload='open-error',closeRequests=close)
    if mutant=='metadata-is-read-error' and inp['metadata']=='error':return dict(kind='error',payload='metadata-error',closeRequests=close)
    if inp['allocationError']:return dict(kind='error',payload='capacity-error-0x2600000003',closeRequests=0 if mutant=='skip-close-on-capacity-error' else close)
    valid=codec(data)[0]==0
    if mutant=='utf8-error-overrides-read-error' and not valid:return dict(kind='error',payload='utf8-descriptor-7db9a8',closeRequests=close)
    if read_error is not None:return dict(kind='error',payload='read-errno-'+str(read_error),closeRequests=close)
    if mutant=='accept-invalid-utf8':valid=True
    if mutant=='reject-nul' and b'\0' in data:valid=False
    if not valid:return dict(kind='error',payload='utf8-descriptor-7db9a8',closeRequests=close)
    if mutant=='strip-bom' and data.startswith(b'\xef\xbb\xbf'):data=data[3:]
    if mutant=='trim-content':data=data.strip()
    if mutant=='discard-zero-metadata-content' and inp['metadata']=='zero-hint':data=b''
    return dict(kind='success',bytesHex=data.hex(),closeRequests=close)
envelopes=json.loads(envraw)
for case in envelopes:
    if envelope(case['input'])!=case['expected']:raise ValueError('Abstract envelope differs from frozen expectation')
mutants=['metadata-is-read-error','skip-close-on-capacity-error','utf8-error-overrides-read-error','accept-invalid-utf8','reject-nul','strip-bom','trim-content','discard-zero-metadata-content']
witnesses=[]
for mutant in mutants:
    case=next((c for c in envelopes if envelope(c['input'],mutant)!=c['expected']),None)
    if case is None:raise ValueError('Wrong abstract rule survived: '+mutant)
    witnesses.append(dict(mutant=mutant,input=case['input'],expected=case['expected'],mutantResult=envelope(case['input'],mutant)))
# New table data is independently checked against the normative lead classes.
native=json.loads((B/'observed/summary.json').read_bytes())
table=bytes.fromhex(next(row for row in native['data'] if row['va']=='0x8047e')['bytes'])
expected=bytes(1 if v<128 else 2 if 0xc2<=v<=0xdf else 3 if 0xe0<=v<=0xef else 4 if 0xf0<=v<=0xf4 else 0 for v in range(256))
if table!=expected:raise ValueError('Native UTF8 width table differs from RFC lead grammar')
result=dict(state='independent-codec-and-abstract-envelope-checks-unqualified',
 utf8Cases=count,envelopeCases=len(envelopes),nativeWidthTableBytes=256,corpusCompressedSha256=meta['compressedSha256'],corpusUncompressedSha256=meta['uncompressedSha256'],
 abstractMutationWitnesses=witnesses,selectedCodecBoundaryCases=selected,
 scope='Python strict UTF8 codec and independent logical envelope model versus prior frozen expectations; native table audit is data binding. No captured execution, native state/branch evaluator, target comparator or implementation equivalence.',
 qualified=False,capturedExecution=False,instructionEvaluation=False)
dest=Path(__import__('sys').argv[2])
if dest.exists():raise ValueError('Preserve model receipt')
dest.write_text(json.dumps(result,indent=2)+'\n',newline='\n');print(json.dumps({'utf8Cases':count,'envelopeCases':len(envelopes),'nativeWidthTableBytes':256,'abstractMutationWitnesses':len(witnesses),'qualified':False}))
