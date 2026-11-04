"""Original conditional postaggregate arithmetic; never substitutes a handler."""
from pathlib import Path
import sys,hashlib,random,json
ROOT=Path(__file__).resolve().parents[3];PACKET=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'tools'))
import decimal_scaled_u64 as cpu
from elfview import View
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
TARGET=ROOT/'artifacts/node/115/hl-node'
RANGES=[(0x2a824d6,0x2a82527),(0x2a82581,0x2a82598),(0x2a825aa,0x2a825b2)]
ENTRIES=[0x2a824d6,0x2a82581,0x2a825aa];END=0x2a82527;SUM_DIAG=0x2a82572;SECOND_DIAG=0x2a82598
HEAD=0x8000000000000018;SLOT=cpu.STACK+0x50
class Image:
 slots={};note_target=None;panic_targets=set()
 def __init__(self):self.view=View(TARGET);self.data=self.view.b;self.cache={}
 def read_only(self,a):return None
 def fetch(self,a):
  if not any(lo<=a<hi for lo,hi in RANGES):raise ValueError('threshold CFG escape')
  if a not in self.cache:self.cache[a]=cpu.decode(self.data,self.view.offset(a),a)
  return self.cache[a]
 def close(self):
  if self.data is not self.view.b:self.data.close()
  self.view.b.close();self.view.file.close()
class Machine(cpu.Machine):
 def bounds(self,a,n):
  if not SLOT<=a or a+n>SLOT+8:raise ValueError('threshold readonly slot footprint')
 def load(self,a,n):self.bounds(a,n);return super().load(a,n)
 def reload(self,r,a,n):self.bounds(a,n);return super().reload(r,a,n)
 def store(self,*args):raise ValueError('threshold write forbidden')
 def spill(self,*args):raise ValueError('threshold write forbidden')
 def call(self,*args):raise ValueError('opaque threshold handler forbidden')
def evaluate(im,row):
 if len(row)!=6 or any(type(v) is not int or not 0<=v<=cpu.U64 for v in row) or row[0]>2:raise ValueError('phase and five rawu64 inputs required')
 phase,a,p,b,bound,l=row
 if phase==2 and any([p,b,bound]):raise ValueError('retained sum phase needs canonical inactive zeros')
 m=Machine(im);m.set_reg(cpu.RSP,cpu.STACK);m.set_reg(cpu.R13,HEAD)
 for i,byte in enumerate(l.to_bytes(8,'little')):m.mem[SLOT+i]=byte
 if phase in [0,1]:
  for reg,value in [(cpu.R15,a),(cpu.RBP,p),(cpu.RBX,b),(cpu.R14,bound)]:m.set_reg(reg,value)
 else:m.set_reg(cpu.RBX,a)
 m.pc=ENTRIES[phase]
 for _ in range(80):
  if m.pc==SUM_DIAG:return 'A',m.seen
  if m.pc==SECOND_DIAG:return 'B',m.seen
  if m.pc==END:
   q,t,h=(m.get(r,64) for r in [cpu.RDX,cpu.RCX,cpu.R13])
   if any(v is None for v in [q,t,h]):raise ValueError('unknown threshold observation')
   return f'V:{q}:{t}:{h}',m.seen
  m.step()
 raise ValueError('threshold step bound')
def stimuli():
 U=cpu.U64;D=500000000;rows=set()
 def add(phase,a,p,b,bound,l):
  if all(0<=v<=U for v in [a,p,b,bound,l]):rows.add((phase,a,p,b,bound,l))
 sums={0,1,255,256,U,U-1,1<<32,1<<63}
 for q in [1,2,7,999,1000,3999,4000,4001,1<<20,U//D]:
  for delta in [-1,0,1,255,256,D-1]:
   v=q*D+delta
   if 0<=v<=U:sums.add(v)
 for total in sums:
  threshold=min(total//D,4000)+1000
  levels={0,999,1000,threshold-1,threshold,threshold+1,U}
  for l in levels:
   add(2,total,0,0,0,l)
   for a in {0,total,total//2}:
    for b,bound in [(0,0),(U,U),(1,0)]:
     for phase in [0,1]:add(phase,a,total-a,b,bound,l)
 for a,p in [(U,1),(U,U),(1<<63,1<<63),(U-10,11)]:
  for l in [0,1000,4999,5000,5001,U]:
   for b,bound in [(0,0),(U,U),(1,0)]:
    for phase in [0,1]:add(phase,a,p,b,bound,l)
 rng=random.Random(1152_824)
 for _ in range(256):
  a,p,b,bound,l=(rng.getrandbits(64) for _ in range(5))
  for phase in [0,1]:add(phase,a,p,b,bound,l)
  add(2,a,0,0,0,l)
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
  if len(expected.splitlines())!=record['rows'] or sorted(seen)!=record['visited_addresses']:raise ValueError('original extent/count drift')
  return inputs,expected
 finally:im.close()
if __name__=='__main__':
 a,b=verify();print('Original independent-point replay PASS',len(b.splitlines()),'observations')
