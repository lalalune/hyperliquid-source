"""Three qualified margin arithmetic point states; no opaque handler replacement."""
from pathlib import Path
import sys,hashlib,json,random
ROOT=Path(__file__).resolve().parents[3];PACKET=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'tools'))
import decimal_scaled_u64 as cpu
from elfview import View
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
TARGET=ROOT/'artifacts/node/115/hl-node'
RANGES=[(0x38b5592,0x38b55af),(0x38b55c0,0x38b55d4),(0x38b53e3,0x38b5406),(0x38b541c,0x38b5449),(0x38b5475,0x38b54a7)]
ENTRIES=[0x38b5592,0x38b53e3,0x38b5475]
FRONTIERS={0x38b55af:'B',0x38b5406:'B',0x38b5466:'H'}
ROW=cpu.INPUT+16
class Image:
 slots={};note_target=None;panic_targets=set()
 def __init__(self):self.view=View(TARGET);self.data=self.view.b;self.cache={}
 def read_only(self,a):return None
 def fetch(self,a):
  if not any(lo<=a<hi for lo,hi in RANGES):raise ValueError('margin CFG escape')
  if a not in self.cache:self.cache[a]=cpu.decode(self.data,self.view.offset(a),a)
  return self.cache[a]
 def close(self):
  if self.data is not self.view.b:self.data.close()
  self.view.b.close();self.view.file.close()
class Machine(cpu.Machine):
 def bounds(self,a,n):
  if not any(lo<=a and a+n<=hi for lo,hi in [(ROW-16,ROW),(cpu.STACK,cpu.STACK+0x70)]):raise ValueError('margin memory footprint')
 def load(self,a,n):self.bounds(a,n);return super().load(a,n)
 def reload(self,r,a,n):self.bounds(a,n);return super().reload(r,a,n)
 def store(self,*args):raise ValueError('margin write forbidden')
 def spill(self,*args):raise ValueError('margin write forbidden')
 def call(self,*args):raise ValueError('margin opaque call forbidden')
def evaluate(im,row):
 if len(row)!=4 or any(type(v) is not int or not 0<=v<=cpu.U64 for v in row):raise ValueError('four raw margin point words required')
 phase,n,b,c=row
 if phase>2 or not 1<=b<=255 or phase==2 and n!=0:raise ValueError('nonzero byte and canonical post-point input required')
 m=Machine(im)
 for i,v in enumerate(c.to_bytes(8,'little')+bytes([b])+b'\xa5'*7):m.mem[ROW-16+i]=v
 for i,v in enumerate(cpu.RETURN_MARK.to_bytes(8,'little')):m.mem[cpu.STACK+0x68+i]=v
 before=dict(m.mem);m.set_reg(cpu.RSP,cpu.STACK)
 if phase==0:m.set_reg(cpu.RCX,ROW);m.set_reg(cpu.RBX,n)
 else:
  m.set_reg(cpu.R14,ROW)
  if phase==1:m.set_reg(cpu.RBX,n)
 m.pc=ENTRIES[phase]
 for _ in range(100):
  if m.pc in FRONTIERS:return FRONTIERS[m.pc],m.seen
  try:m.step()
  except cpu.Done as done:
   v=m.get(cpu.RAX,64)
   if done.how!='ret' or v is None or m.get(cpu.RSP,64)!=cpu.STACK+0x70:raise ValueError('margin return drift')
   if m.mem!=before:raise ValueError('margin input modified')
   return f'V:{v}',m.seen
 raise ValueError('margin step bound')
def stimuli():
 U=cpu.U64;H=1<<63;rows=set()
 def add(phase,n,b,c):
  if 0<=n<=U and 0<=c<=U:rows.add((phase,n,b,c))
 for b in [1,2,3,7,31,127,128,254,255]:
  for n in [0,1,2,5,6,7,(1<<32)-1,1<<32,(1<<32)+1,H-2,H-1,H,H+1,U]:
   q=n//(2*b)
   for c in {0,1,2,U,U//(4*b),U//(4*b)+1,max(q-1,0),q,min(q+1,U)}:
    for phase in [0,1]:add(phase,n,b,c)
  for c in [0,1,2,U//(4*b),U//(4*b)+1,U-1,U]:add(2,0,b,c)
 for b in range(1,256):
  for phase in [0,1]:
   for n,c in [(0,0),(12*b,1),(12*b-1,1),(H-1,U),(1<<40,0)]:add(phase,n,b,c)
  add(2,0,b,U);add(2,0,b,0)
 rng=random.Random(115038)
 for _ in range(256):
  n,b,c=rng.getrandbits(64),rng.randrange(1,256),rng.getrandbits(64)
  for phase in [0,1]:add(phase,n,b,c)
  add(2,0,b,c)
 return sorted(rows)
def corpus(im):
 inputs=[];expected=[];seen=set()
 for row in stimuli():
  result,trace=evaluate(im,row);seen|=trace;inputs.append('\t'.join(map(str,row))+'\n');expected.append(result+'\n')
 return ''.join(inputs).encode(),''.join(expected).encode(),seen
def verify():
 record=json.loads((PACKET/'FREEZE.json').read_text());im=Image()
 try:
  if hashlib.sha256(im.data).hexdigest()!=SHA:raise ValueError('wrong115target')
  inputs,expected,seen=corpus(im)
  for name,data in [('input',inputs),('expected',expected)]:
   if hashlib.sha256(data).hexdigest()!=record[name+'_sha256']:raise ValueError('frozen '+name+' drift')
  if sorted(seen)!=record['visited_addresses'] or len(expected.splitlines())!=record['rows']:raise ValueError('margin denominator drift')
  return inputs,expected
 finally:im.close()
if __name__=='__main__':
 a,b=verify();print('Original margin points replay PASS',len(b.splitlines()),'observations')
