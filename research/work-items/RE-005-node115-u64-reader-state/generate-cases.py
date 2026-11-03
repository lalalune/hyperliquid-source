"""Freeze native-branch-derived logical expectations BEFORE Rust; never executes target."""
from pathlib import Path
import json,hashlib
P=Path(__file__).resolve().parent;MAX=(1<<64)-1
# Independent mathematical relation, reviewed against CONTRACT and raw target bytes.
def projected(data):
 n=len(data)
 if not n:return ('e0:1',0)
 b=data[0]; slow=n<=8
 if b<251:return ('v:'+str(b),1)
 if b>=254:return ('e3:'+str(3 if slow else 2)+':'+str(4 if b==254 else 12),int(slow))
 width={251:3,252:5,253:9}[b]
 if n<width:return ('e0:'+str(width-n),1)
 return ('v:'+str(sum(data[j]<<(8*(j-1)) for j in range(1,width))),width)
def expected(op,mode,c,l,data):
 cost={'s':8,'q':32}[op];new=c
 if mode:
  if c>MAX-cost:return 'e2|0|'+str(c)
  new=c+cost
  if new>l:return 'e2|0|'+str(new)
 cursor=0;values=[]
 for _ in range(1 if op=='s' else 4):
  result,used=projected(data[cursor:]);cursor+=used
  if not result.startswith('v:'):return result+'|'+str(cursor)+'|'+str(new)
  values.append(result[2:])
 return 'v:'+','.join(values)+'|'+str(cursor)+'|'+str(new)
# Hand-checked native anchors guard algebra/transcription independently of the implementation.
assert expected('s',0,7,0,bytes.fromhex('fe00000000000000'))=='e3:3:4|1|7'
assert expected('s',0,7,0,bytes.fromhex('fe0000000000000000'))=='e3:2:4|0|7'
assert expected('s',1,5,12,b'')=='e2|0|13'
assert expected('s',1,MAX-7,MAX,b'')=='e2|0|'+str(MAX-7)
assert expected('s',0,0,0,bytes.fromhex('fd0102030405060708'))=='v:578437695752307201|9|0'
assert expected('s',0,0,0,bytes.fromhex('fc00'))=='e0:3|1|0'
assert expected('q',1,1,33,bytes([1,2,254]))=='e3:3:4|3|33'
assert expected('q',1,1,32,bytes([1,2,3,4]))=='e2|0|33'
assert expected('q',1,1,33,bytes([1,2,3,4]))=='v:1,2,3,4|4|33'
cases={}
def add(op,m,c,l,data):
 key=(op,m,c,l,data.hex() or '-');cases[key]=expected(op,m,c,l,data)
for b in range(256):
 for n in range(11):
  for payload in [bytes(10),bytes([255])*10,bytes(range(1,11))]:add('s',0,19,0,(bytes([b])+payload)[:n])
for b in [0,250,251,252,253,254,255]:
 for n in [0,1,2,3,4,5,8,9,10]:
  data=(bytes([b])+bytes(range(1,11)))[:n]
  for c,l in [(0,0),(0,7),(0,8),(1,8),(1,9),(MAX-8,MAX),(MAX-7,MAX),(MAX,MAX)]:add('s',1,c,l,data)
for prefix in [b'',b'\x01',b'\x01\x02',b'\x01\x02\x03']:
 for b in [0,250,251,252,253,254,255]:
  for n in [1,2,3,4,5,8,9]:
   for suffix in [b'',bytes(12)]:
    data=prefix+(bytes([b])+bytes(range(1,10)))[:n]+suffix
    for m,c,l in [(0,MAX,0),(1,7,38),(1,7,39),(1,MAX-32,MAX),(1,MAX-31,MAX)]:add('q',m,c,l,data)
for data in [b'',b'\x01',b'\x01\x02',b'\x01\x02\x03',b'\x01\x02\x03\x04']:
 for m,c,l in [(0,0,0),(1,0,31),(1,0,32),(1,MAX-32,MAX),(1,MAX-31,MAX)]:add('q',m,c,l,data)
text=''.join('\t'.join(map(str,(*key,value)))+'\n' for key,value in sorted(cases.items()))
(P/'cases.tsv').write_text(text,newline='\n')
print(json.dumps({'cases':len(cases),'sha256':hashlib.sha256(text.encode()).hexdigest(),'targetExecuted':False}),flush=True)
