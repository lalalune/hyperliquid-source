"""Interpret the authenticated post-lookup integer prefix, not captured ELF execution."""
from pathlib import Path
import sys, hashlib, json, random
ROOT=Path(__file__).resolve().parents[3]; PACKET=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'tools'))
import decimal_scaled_u64 as cpu
from elfview import View
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
TARGET=ROOT/'artifacts/node/115/hl-node'
RANGES=[(0x2c7ff0e,0x2c7ffc4),(0x2c80078,0x2c8007e)]
ENTRY=0x2c7ff0e
FRONTIERS={0x2c804dd:'M',0x2c805e8:'E',0x2c80502:'S'}
NORMAL={0x2c800df:'N',0x2c7ffc4:'64',0x2c8007e:'32'}
SLOTS=[0x38,0x40,0x58,0x60,0x70,0x110]
class Image:
 slots={}; note_target=None; panic_targets=set()
 def __init__(self): self.view=View(TARGET); self.data=self.view.b; self.cache={}
 def read_only(self,a): return None
 def fetch(self,a):
  if not any(lo<=a<hi for lo,hi in RANGES): raise ValueError('position CFG escape')
  if a not in self.cache: self.cache[a]=cpu.decode(self.data,self.view.offset(a),a)
  return self.cache[a]
 def close(self):
  if self.data is not self.view.b:self.data.close()
  self.view.b.close();self.view.file.close()
class Machine(cpu.Machine):
 def bounds(self,a,n):
  if not any(cpu.STACK+s<=a and a+n<=cpu.STACK+s+8 for s in SLOTS):raise ValueError('position slot footprint')
 def load(self,a,n):self.bounds(a,n);return super().load(a,n)
 def reload(self,r,a,n):self.bounds(a,n);return super().reload(r,a,n)
 def store(self,a,n,v):self.bounds(a,n);return super().store(a,n,v)
 def spill(self,a,r,n):self.bounds(a,n);return super().spill(a,r,n)
 def call(self,*args):raise ValueError('position opaque call forbidden')
def evaluate(im,row):
 if len(row)!=3 or any(type(v) is not int or not 0<=v<=cpu.U64 for v in row) or row[0]==0:raise ValueError('nonzero size and three rawu64 words required')
 size,mark,entry=row;m=Machine(im);m.set_reg(cpu.RSP,cpu.STACK);m.set_reg(cpu.RAX,mark);m.set_reg(cpu.RDI,entry);m.store(cpu.STACK+0x40,8,size);m.pc=ENTRY
 for _ in range(100):
  if m.pc in FRONTIERS:return FRONTIERS[m.pc],m.seen
  if m.pc in NORMAL:
   product=m.get(cpu.RBP,64);pnl=m.load(cpu.STACK+0x38,8)
   if product is None or pnl is None:raise ValueError('unknown position observation')
   route=NORMAL[m.pc]
   if route=='N':
    if m.load(cpu.STACK+0x58,8)!=0:raise ValueError('unknown absent marker')
    return f'V:{product}:{pnl}:N',m.seen
   q,r=m.get(cpu.RAX,64),m.get(cpu.RDX,64)
   if q is None or r is None:raise ValueError('unknown division observation')
   return f'V:{product}:{pnl}:{route}:{q}:{r}',m.seen
  m.step()
 raise ValueError('position step bound')
def stimuli():
 U=cpu.U64;H=1<<63;rows=set()
 sizes={1,2,3,7,(1<<31)-1,1<<31,(1<<32)-1,1<<32,(1<<32)+1,(1<<53)-1,(1<<53)+1,H-1,H,H+1,U,U-1,U-2}
 marks={0,1,2,3,7,(1<<31)-1,1<<32,H-1,H,H+1,U}
 entries={0,1,2,3,7,(1<<32)-1,1<<32,(1<<32)+1,(1<<53)-1,(1<<53)+1,H-1,H,H+1,U}
 for s in sizes:
  mag=min(s,(-s)&U)
  es=entries|{v for v in [mag-1,mag,mag+1] if 0<=v<=U}
  for m in marks:
   for e in es:rows.add((s,m,e))
 rng=random.Random(115027)  # fixed synthetic seed, no user state
 for _ in range(256):
  s=rng.getrandbits(64) or 1;rows.add((s,rng.getrandbits(64),rng.getrandbits(64)))
  rows.add((s,0,rng.getrandbits(63)))
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
  if len(expected.splitlines())!=record['rows'] or sorted(seen)!=record['visited_addresses']:raise ValueError('position denominator drift')
  return inputs,expected
 finally:im.close()
if __name__=='__main__':
 a,b=verify();print('Original position replay PASS',len(b.splitlines()),'observations')
