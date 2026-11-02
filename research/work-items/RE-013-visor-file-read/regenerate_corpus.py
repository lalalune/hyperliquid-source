"""Freeze normative byte/error and synthetic envelope expectations before any proposed model."""
from pathlib import Path
import json,gzip,io,hashlib,collections,datetime
B=Path(__file__).resolve().parent
cases={};categories=collections.Counter()
def add(raw,tag,start=None,length=None,category='manual-boundary'):
    value=(tag,start,length)
    if raw in cases:
        if cases[raw]!=value:raise ValueError('Contradictory normative expectation: '+raw.hex())
    else:cases[raw]=value;categories[category]+=1
def second_ok(a,b):
    if 0xc2<=a<=0xdf:return 0x80<=b<=0xbf
    if a==0xe0:return 0xa0<=b<=0xbf
    if a==0xed:return 0x80<=b<=0x9f
    if 0xe1<=a<=0xef:return 0x80<=b<=0xbf
    if a==0xf0:return 0x90<=b<=0xbf
    if a==0xf4:return 0x80<=b<=0x8f
    if 0xf1<=a<=0xf3:return 0x80<=b<=0xbf
    return False
# Known Unicode scalars encoded by an independent standard codec; no native
# parser/proposed implementation output is used. Prefixes of these canonical
# encodings are normative truncation cases, not partial successful strings.
add(b'',0,category='empty')
for cp in range(0x110000):
    if 0xd800<=cp<=0xdfff:continue
    raw=chr(cp).encode('utf-8');add(raw,0,category='canonical-scalar')
    for n in range(1,len(raw)):add(raw[:n],1,0,None,'canonical-truncated-prefix')
# All one-byte strings: ASCII above already covered; every admitted lead is
# truncated, other high bytes are invalid leads with length1.
for a in range(0x80,256):add(bytes([a]),1,0,None if 0xc2<=a<=0xf4 else 1,'single-byte-partition')
# Explicit two-byte grammar partition, independent of a parser/decoder.
for a in range(256):
    for b in range(256):
        raw=bytes([a,b])
        if a<128:
            if b<128:add(raw,0,category='two-byte-partition')
            else:add(raw,1,1,None if 0xc2<=b<=0xf4 else 1,'two-byte-partition')
        elif 0xc2<=a<=0xdf:
            add(raw,0 if second_ok(a,b) else 1,None if second_ok(a,b) else 0,None if second_ok(a,b) else 1,'two-byte-partition')
        elif 0xe0<=a<=0xf4:
            add(raw,1,0,None if second_ok(a,b) else 1,'two-byte-partition')
        else:add(raw,1,0,1,'two-byte-partition')
lead_second=[(0xc2,0x80),(0xdf,0xbf),(0xe0,0xa0),(0xe1,0x80),(0xed,0x80),(0xee,0x80),(0xef,0xbf),(0xf0,0x90),(0xf1,0x80),(0xf3,0xbf),(0xf4,0x80)]
boundaries=[]
for lead,second in lead_second:
    for value in range(256):
        if not second_ok(lead,value):
            raw=bytes([lead,value,0x80,0x80]);add(raw,1,0,1,'invalid-second');boundaries.append((raw,1))
        if lead>=0xe0 and not 0x80<=value<=0xbf:
            raw=bytes([lead,second,value,0x80]);add(raw,1,0,2,'invalid-third');boundaries.append((raw,2))
        if lead>=0xf0 and not 0x80<=value<=0xbf:
            raw=bytes([lead,second,0x80,value]);add(raw,1,0,3,'invalid-fourth');boundaries.append((raw,3))
for prefix_length in [0,1,7,8,15,16,17,23,31,32,33,47,48,63]:
    before=b'A'*prefix_length
    for raw,length in boundaries[::37]:add(before+raw+b'Z',1,prefix_length,length,'aligned-first-error')
    for raw in [b'\xc2',b'\xe0\xa0',b'\xed\x80',b'\xf0\x90',b'\xf1\x80\x80',b'\xf4\x80\x80']:
        add(before+raw,1,prefix_length,None,'aligned-truncation')
        add(before+raw+b'A',1,prefix_length,len(raw),'truncation-followed-by-ASCII')
    for raw in [b'\x00',b'\xc3\xa9',b'\xef\xbb\xbf',b'\xf0\x90\x80\x80',b'\xf4\x8f\xbf\xbf']:
        add(before+raw+b'Z',0,category='aligned-valid-concatenation')
lines=[]
for raw,(tag,start,length) in sorted(cases.items()):lines.append(raw.hex()+'\t'+str(tag)+'\t'+('-' if start is None else str(start))+'\t'+('-' if length is None else str(length))+'\n')
payload=''.join(lines).encode();buf=io.BytesIO()
with gzip.GzipFile(fileobj=buf,mode='wb',mtime=0,filename='') as f:f.write(payload)
compressed=buf.getvalue();OUT=Path(__import__('sys').argv[1]);OUT.mkdir(exist_ok=False);dest=OUT/'expectations.tsv.gz'
if dest.exists():raise ValueError('Preserve frozen expectations')
dest.write_bytes(compressed)
prefixes=[(b'',True),(b'A\x00B',True),('é'.encode(),True),(b'\xef\xbb\xbf',True),(b' \t\r\n',True),(b'\xff',False),(b'\xc2',False),(b'\xe0\x80\x80',False),(b'\xed\xa0\x80',False),(b'\xf4\x90\x80\x80',False)]
envelopes=[]
for metadata in ['error','zero-hint','positive-hint']:
    for opened in [False,True]:
        for allocation_error in ([False,True] if metadata=='positive-hint' else [False]):
            for read_error in [None,5,11,22]:
                for raw,valid in prefixes:
                    if not opened:result=dict(kind='error',payload='open-error',closeRequests=0)
                    elif allocation_error:result=dict(kind='error',payload='capacity-error-0x2600000003',closeRequests=1)
                    elif read_error is not None:result=dict(kind='error',payload='read-errno-'+str(read_error),closeRequests=1)
                    elif not valid:result=dict(kind='error',payload='utf8-descriptor-7db9a8',closeRequests=1)
                    else:result=dict(kind='success',bytesHex=raw.hex(),closeRequests=1)
                    envelopes.append(dict(input=dict(metadata=metadata,opened=opened,allocationError=allocation_error,readError=read_error,initializedPrefixHex=raw.hex()),expected=result))
envraw=(json.dumps(envelopes,indent=2,sort_keys=True)+'\n').encode();envdest=OUT/'envelope.json'
if envdest.exists():raise ValueError('Preserve envelope expectations')
envdest.write_bytes(envraw)
meta=json.loads((B/'FROZEN-CORPUS.json').read_bytes())
result={'utf8Cases':len(cases),'categoryUniqueCases':dict(categories),'compressedBytes':len(compressed),'uncompressedBytes':len(payload),
 'compressedSha256':hashlib.sha256(compressed).hexdigest(),'uncompressedSha256':hashlib.sha256(payload).hexdigest(),
 'envelopeCases':len(envelopes),'envelopeSha256':hashlib.sha256(envraw).hexdigest()}
for key,value in result.items():
    if meta[key]!=value:raise ValueError('Original frozen expectation identity changed: '+key)
(OUT/'receipt.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
print(json.dumps(result))
