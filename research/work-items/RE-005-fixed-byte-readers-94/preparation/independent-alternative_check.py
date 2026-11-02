"""A second same-reviewer raw-wire/bytearray formulation, not another peer."""
from pathlib import Path
import json,hashlib,collections,datetime
P=Path(__file__).parent;U=2**64-1
sha=lambda b:hashlib.sha256(b).hexdigest()
expected=iter((P/'expected.jsonl').read_bytes().splitlines(keepends=True));counts=collections.Counter();stimuli=rows=0;seen=set()
for line in(P/'inputs.txt').read_text().splitlines():
 ident,width,mode,limit,charged,wire,output,calls=line.split('|');n=int(width);m=int(mode);b=int(limit,16);c=int(charged,16);data=bytes.fromhex(wire);out=bytearray.fromhex(output);cursor=0
 stimulus=(n,m,b,c,data,bytes(out),int(calls));assert stimulus not in seen;seen.add(stimulus);stimuli+=1
 for call in range(1,int(calls)+1):
  previous=cursor;kind=None;needed=None
  if m==1:
   if c>U-n:kind='charge'
   else:
    c+=n
    if c>b:kind='charge'
  if kind is None:
   if len(data[cursor:])<n:kind='end';needed=n-len(data[cursor:])
   else:kind='value';cursor+=n
  if kind=='value':out[1:]=data[previous:cursor];out[0]=18 if n==20 else 0
  elif n==20:
   out[0]=0 if kind=='end'else 2
   if kind=='end':out[8:16]=needed.to_bytes(8,'little')
  else:
   out[0]=1;out[8]=0 if kind=='end'else 2
   if kind=='end':out[16:24]=needed.to_bytes(8,'little')
  record={'additional':needed,'call':call,'charged':c,'consumed':cursor-previous,'cursor':cursor,'id':ident,'kind':kind,'limit':b,'mode':m,'output':out.hex(),'remaining':len(data)-cursor,'tail':data[cursor:].hex()}
  serialized=(json.dumps(record,sort_keys=True,separators=(',',':'),ensure_ascii=True)+'\n').encode();assert serialized==next(expected),(ident,call)
  counts[kind]+=1;rows+=1
try:next(expected);raise AssertionError('extra expected row')
except StopIteration:pass
receipt={'schema':'fixed217-alternative-math-crosscheck-v1','status':'PASS','utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'stimuli':stimuli,'distinct_complete_stimuli':len(seen),'observations':rows,'outcomes':dict(counts),'input_sha256':sha((P/'inputs.txt').read_bytes()),'expected_sha256':sha((P/'expected.jsonl').read_bytes()),'freeze_sha256':sha((P/'FREEZE.json').read_bytes()),'checker_sha256':sha(Path(__file__).read_bytes()),'method':'Separate raw serializer parse, complement overflow bound and bytearray slice assignments/int.to_bytes; all complete canonical rows agree.','limitations':['Second same-reviewer mathematical method, not a second reviewer or native execution.','No proposed source was read, no target/CPU/instruction evaluator, compiler or client executed.']}
(P/'ALTERNATIVE-MATH-CROSSCHECK.json').write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n');print(json.dumps({'status':'PASS','stimuli':stimuli,'observations':rows,'receipt_sha256':sha((P/'ALTERNATIVE-MATH-CROSSCHECK.json').read_bytes())}))
