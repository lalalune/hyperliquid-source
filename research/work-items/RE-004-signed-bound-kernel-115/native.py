"""Original interior signed-cap kernel; no containing-function ABI claim."""
from pathlib import Path
import sys,hashlib,json,random
ROOT=Path(__file__).resolve().parents[3];PACKET=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'tools'));import decimal_scaled_u64 as cpu
from elfview import View
TARGET=ROOT/'artifacts/node/115/hl-node';SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
START=0x4483a08;END=0x4483b14;DIAGNOSTIC=0x4483b65;ROW=cpu.INPUT
RANGES=[(0x4483a08,0x4483a7a),(0x4483ac5,0x4483b14)]
class Image:
 slots={};note_target=None;panic_targets=set()
 def __init__(self):
  self.view=View(TARGET);self.data=self.view.b;self.cache={};self.text_va,self.text_off,self.text_size=self.view.sections['.text']
 def read_only(self,a):return None
 def fetch(self,a):
  if not any(lo<=a<hi for lo,hi in RANGES):raise ValueError('signed-cap CFG escape')
  if a not in self.cache:self.cache[a]=cpu.decode(self.data,self.view.offset(a),a)
  return self.cache[a]
 def close(self):
  if self.data is not self.view.b:self.data.close()
  self.view.b.close();self.view.file.close()
class Machine(cpu.Machine):
 def bounds(self,a,n):
  if not ROW<=a or a+n>ROW+48:raise ValueError('signed-cap input footprint')
 def load(self,a,n):self.bounds(a,n);return super().load(a,n)
 def reload(self,r,a,n):self.bounds(a,n);return super().reload(r,a,n)
 def store(self,*args):raise ValueError('signed-cap write forbidden')
 def spill(self,*args):raise ValueError('signed-cap write forbidden')
 def call(self,*args):raise ValueError('unclosed signed-cap call')
def evaluate(im,row):
 if len(row)!=6 or any(type(v) is not int or not 0<=v<=cpu.U64 for v in row):raise ValueError('six rawu64 fields required')
 m=Machine(im)
 for i,v in enumerate(row):
  for j,b in enumerate(v.to_bytes(8,'little')):m.mem[ROW+i*8+j]=b
 m.set_reg(cpu.R13,ROW);m.pc=START
 for _ in range(400):
  if m.pc==END:
   v=m.get(cpu.RBX,64)
   if v is None:raise ValueError('unknown cap')
   return 'C:'+str(v),m.seen
  if m.pc==DIAGNOSTIC:return 'N',m.seen
  m.step()
 raise ValueError('signed-cap step bound')
def stimuli():
 U=cpu.U64;M=(1<<63)-1;rows=set()
 def add(m,a,b,c,d,x):rows.add((m&U,a&U,b&U,c&U,d&U,x&U))
 pairs=[(0,0),(1,1),(0,100),(1,100),(10,100),(100,100),(100,101),(U,U),(100,U),(U,100),(M,M-1),((1<<32)-1,(1<<32)+17)]
 for m in [0,1,2,3,7,M-1,M,U]:
  for x in [0,1,-1,2,-2,M,-(1<<63),-(1<<63)+1]:
   for a,b in pairs:
    for d in [0,1,2,20,100,1<<32,U]:add(m,a,b,d,d,x)
 for x in [-1,0,1]:
  for c,d in [(20,10),(100,101),(0,1),(1,0)]:add(1,100,120,c,d,x)
 for mag in [1,2,3,7,31,1<<16,1<<31]:
  for threshold in [M-1,M,U]:
   for delta in [-1,0,1]:
    m=max(0,min(U,threshold//mag+delta));prod=(mag*m)&U
    for sign in [-1,1]:
     for d in [max(0,2*mag-1),2*mag,2*mag+1]:add(m,U,U,d,d,sign*mag)
     for opposite in [max(0,min(U,2*prod+delta))]:add(m,U,opposite,2*mag+3,2*mag+3,mag)
 for row in [(0,100,1,100,100,0), (1,10,100,20,20,1), (M-1,0,U,3,3,1), (1,13,29,0,0,1)]:rows.add(row)
 rng=random.Random(11544839)
 for _ in range(512):add(rng.randrange(8),rng.getrandbits(32),rng.getrandbits(32),rng.randrange(10000),rng.randrange(10000),rng.randrange(-128,129))
 for _ in range(256):rows.add(tuple(rng.getrandbits(64) for _ in range(6)))
 return sorted(rows)
def corpus(im):
 inputs=[];outputs=[];seen=set()
 for row in stimuli():
  result,trace=evaluate(im,row);seen|=trace;inputs.append('\t'.join(map(str,row))+'\n');outputs.append(result+'\n')
 return ''.join(inputs).encode(),''.join(outputs).encode(),seen
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
 a,b=verify();print('original replay PASS',len(b.splitlines()),'distinct rows; diagnostic',b.splitlines().count(b'N'))
