"""Whole three-leaf addition family, no original type/owner attribution."""
from pathlib import Path
import sys,hashlib,random,json
ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'tools'))
import decimal_scaled_u64 as cpu
from elfview import View
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
TARGET=ROOT/'artifacts/node/115/hl-node';PACKET=Path(__file__).resolve().parent
RANGES=[(0x298f5b0,0x298f5f9),(0x29fc880,0x29fc8b1),(0x4fb12f0,0x4fb1321)]
DESC=cpu.INPUT;BUFFER=DESC+0x1000;RIGHT=DESC+0x2000;OUT=DESC+0x3000;STACK=cpu.STACK
REGIONS=[(DESC,64),(BUFFER,256),(RIGHT,32),(OUT,64),(STACK,8)]
class Image:
 slots={};note_target=None;panic_targets=set()
 def __init__(self):
  self.view=View(TARGET);self.data=self.view.b;self.cache={}
 def read_only(self,a):return None
 def fetch(self,a):
  if not any(lo<=a<hi for lo,hi in RANGES):raise ValueError('addition CFG escape')
  if a not in self.cache:self.cache[a]=cpu.decode(self.data,self.view.offset(a),a)
  return self.cache[a]
 def close(self):
  if self.data is not self.view.b:self.data.close()
  self.view.b.close();self.view.file.close()
class Machine(cpu.Machine):
 def bounds(self,a,n):
  if not any(lo<=a and a+n<=lo+length for lo,length in REGIONS):raise ValueError('addition fixture footprint')
 def load(self,a,n):self.bounds(a,n);return super().load(a,n)
 def reload(self,r,a,n):self.bounds(a,n);return super().reload(r,a,n)
 def store(self,a,n,v):self.bounds(a,n);return super().store(a,n,v)
 def spill(self,a,r,n):self.bounds(a,n);return super().spill(a,r,n)
 def call(self,*args):raise ValueError('unclosed addition call')
def evaluate(im,mode,count,left,right):
 if mode not in (0,1,2) or not 0<=count<=8:raise ValueError('mode/count')
 if len(left)!=4 or len(right)!=4 or any(type(v) is not int or not 0<=v<=cpu.U64 for v in [*left,*right]):raise ValueError('limbs')
 m=Machine(im)
 for a,n in REGIONS:
  for i in range(n):m.mem[a+i]=0xa5
 def word(a,v):
  for i,b in enumerate(v.to_bytes(8,'little')):m.mem[a+i]=b
 word(STACK,cpu.RETURN_MARK);word(DESC+0x28,BUFFER);word(DESC+0x30,count)
 for i in range(8):
  for j in range(4):word(BUFFER+i*32+j*8,((i+1)*0x1020304050607+j)&cpu.U64)
 if mode==0:
  if count<2:
   for j,v in enumerate(left):word(BUFFER+j*8,v)
  if count>=2:
   for j,v in enumerate(left):word(BUFFER+(count-2)*32+j*8,v)
   for j,v in enumerate(right):word(BUFFER+(count-1)*32+j*8,v)
 else:
  for j,v in enumerate(left):word(BUFFER+j*8,v)
 for j,v in enumerate(right):word(RIGHT+j*8,v)
 before=dict(m.mem);m.set_reg(cpu.RSP,STACK)
 if mode==0:m.set_reg(cpu.RDI,DESC)
 else:
  m.set_reg(cpu.RDI,OUT);m.set_reg(cpu.RSI,BUFFER);m.set_reg(cpu.RDX,RIGHT)
 m.pc=RANGES[mode][0]
 try:
  for _ in range(100):m.step()
  raise ValueError('addition instruction bound')
 except cpu.Done as end:
  if end.how!='ret':raise ValueError('unexpected original stop')
 status=m.get(cpu.RAX,64) if mode==0 else None
 if mode==0 and status is None:raise ValueError('unknown guarded status')
 if set(m.mem)!=set(before):raise ValueError('unknown output or escaped mutation')
 changed={a for a in before if before[a]!=m.mem[a]}
 allowed=set()
 if mode==0 and count>=2:allowed=set(range(DESC+0x30,DESC+0x38))|set(range(BUFFER+(count-2)*32,BUFFER+(count-1)*32))
 if mode!=0:allowed=set(range(BUFFER,BUFFER+32))|set(range(OUT,OUT+33))
 if not changed<=allowed:raise ValueError('unexpected original mutation')
 # Full defined fixture snapshot includes right operand, inactive rows/canaries,
 # descriptor and synthetic return word; RSP/flags/undefined RAX excluded.
 raw=b''.join(bytes(m.mem[a+i] for i in range(n)) for a,n in REGIONS)
 return ('-' if status is None else str(status))+':'+raw.hex(),m.seen

def stimuli():
 U=cpu.U64;rows=set();patterns=[(0,)*4,(U,)*4,(1,0,0,0),(U,0,0,0),(0,U,0,0),(0,0,U,0),(0,0,0,U),(U,U,0,0),(U,U,U,0),(0xaaaaaaaaaaaaaaaa,)*4,(0x5555555555555555,)*4]
 for a in patterns:
  for b in patterns:
   for count in [0,1,2,3,8]:rows.add((count,a,b))
 rng=random.Random(115298)
 for _ in range(512):rows.add((rng.choice([0,1,2,3,8]),tuple(rng.getrandbits(64) for _ in range(4)),tuple(rng.getrandbits(64) for _ in range(4))))
 return sorted(rows)
def cases():
 rows=stimuli()
 result=[(0,count,a,b) for count,a,b in rows]
 pairs=sorted({(a,b) for _,a,b in rows})
 for mode in [1,2]:result.extend((mode,2,a,b) for a,b in pairs)
 return result

def corpus(im):
 inputs=[];expected=[];seen=set()
 for mode,count,a,b in cases():
  outcome,trace=evaluate(im,mode,count,a,b);seen|=trace
  inputs.append('\t'.join(map(str,(mode,count,*a,*b)))+'\n');expected.append(outcome+'\n')
 return ''.join(inputs).encode(),''.join(expected).encode(),seen

def verify():
 record=json.loads((PACKET/'FREEZE.json').read_text());im=Image()
 try:
  if hashlib.sha256(im.data).hexdigest()!=SHA:raise ValueError('wrong115target')
  inputs,expected,seen=corpus(im)
  for label,data in [('input',inputs),('expected',expected)]:
   if hashlib.sha256(data).hexdigest()!=record[label+'_sha256']:raise ValueError('frozen '+label+' drift')
  if sorted(seen)!=record['visited_addresses']:raise ValueError('visited instruction drift')
  return inputs,expected
 finally:im.close()
if __name__=='__main__':
 a,b=verify();print('Original complete-leaf replay PASS',len(b.splitlines()),'observations')
