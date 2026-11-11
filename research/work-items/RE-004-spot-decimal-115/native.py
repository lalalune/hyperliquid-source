"""Full ordinary spot-decimal leaf with actual RET and bounded diagnostic frontiers."""
from pathlib import Path
import sys,hashlib,json,random
ROOT=Path(__file__).resolve().parents[3];PACKET=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'tools'))
import decimal_scaled_u64 as cpu
from elfview import View
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
TARGET=ROOT/'artifacts/node/115/hl-node'
ENTRY=0x29aea00;END=0x29aeaf2;RANGES=[(ENTRY,0x29aeacf)]
FRONTIERS={0x29aeadc:'A',0x29aeacf:'B'}
DESC=cpu.INPUT;FIRST=DESC+0x100;SECOND=DESC+0x400;OUTPUT=DESC+0x1000
class Image:
 slots={};note_target=None;panic_targets=set()
 def __init__(self):self.view=View(TARGET);self.data=self.view.b;self.cache={}
 def read_only(self,a):return None
 def fetch(self,a):
  if not ENTRY<=a<0x29aeacf:raise ValueError('spot CFG escape')
  if a not in self.cache:self.cache[a]=cpu.decode(self.data,self.view.offset(a),a)
  return self.cache[a]
 def close(self):
  if self.data is not self.view.b:self.data.close()
  self.view.b.close();self.view.file.close()
class Machine(cpu.Machine):
 def __init__(self,im,nfirst,nsecond):
  super().__init__(im);self.regions=[(DESC,DESC+48),(FIRST,FIRST+32*nfirst),(SECOND,SECOND+344*nsecond),(OUTPUT,OUTPUT+16),(cpu.STACK-8,cpu.STACK+8)]
 def bounds(self,a,n,write=False):
  regions=self.regions[-2:] if write else self.regions
  if not any(lo<=a and a+n<=hi for lo,hi in regions):raise ValueError('spot memory footprint')
 def load(self,a,n):self.bounds(a,n);return super().load(a,n)
 def reload(self,r,a,n):self.bounds(a,n);return super().reload(r,a,n)
 def store(self,a,n,v):self.bounds(a,n,True);return super().store(a,n,v)
 def spill(self,a,r,n):self.bounds(a,n,True);return super().spill(a,r,n)
 def call(self,*args):raise ValueError('spot opaque call forbidden')
def encode(row):
 amount,index,first,decimals,seed=row
 return '\t'.join([str(amount),str(index),','.join(map(str,first)) or '-',bytes(decimals).hex() or '-',str(seed)])
def evaluate(im,row):
 amount,index,first,decimals,seed=row
 if not all(type(v) is int and 0<=v<=cpu.U64 for v in [amount,index,*first]) or not 0<=seed<=255 or len(first)>4 or len(decimals)>3 or any(not 0<=d<=255 for d in decimals):raise ValueError('spot synthetic fixture domain')
 m=Machine(im,len(first),len(decimals))
 for lo,hi in m.regions[:-1]:
  for a in range(lo,hi):m.mem[a]=(seed+(a-lo)*17)&255
 def word(a,v):
  for i,b in enumerate(v.to_bytes(8,'little')):m.mem[a+i]=b
 for a,v in [(DESC+8,FIRST),(DESC+0x10,len(first)),(DESC+0x20,SECOND),(DESC+0x28,len(decimals)),(cpu.STACK,cpu.RETURN_MARK)]:word(a,v)
 for i,v in enumerate(first):word(FIRST+32*i,v)
 for i,d in enumerate(decimals):m.mem[SECOND+344*i+0x48]=d
 before={a:v for a,v in m.mem.items() if a<OUTPUT}
 for reg,v in [(cpu.RDI,OUTPUT),(cpu.RSI,amount),(cpu.RDX,index),(cpu.RCX,DESC),(cpu.RSP,cpu.STACK)]:m.set_reg(reg,v)
 m.pc=ENTRY
 for _ in range(120):
  if m.pc in FRONTIERS:return FRONTIERS[m.pc],m.seen
  try:m.step()
  except cpu.Done as done:
   if done.how!='ret' or m.get(cpu.RAX,64)!=OUTPUT or m.get(cpu.RSP,64)!=cpu.STACK+8:raise ValueError('spot return drift')
   if any(m.mem[a]!=v for a,v in before.items()):raise ValueError('spot input modified')
   return 'O:'+bytes(m.mem[OUTPUT+i] for i in range(16)).hex(),m.seen
 raise ValueError('spot step bound')
def stimuli():
 U=cpu.U64;rows=set()
 def add(amount,index,first,decimals,seed=165):rows.add((amount,index,tuple(first),tuple(decimals),seed))
 for d in range(256):
  for amount in [0,1,2,99,100,99999999,100000000,100000001,(1<<32)-1,1<<32,(1<<32)+1,U]:add(amount,0,[0],[d])
 for d in range(9):
  divisor=10**(8-d)
  for q in [0,1,3,17,(1<<32)//divisor,U//divisor]:
   for delta in [-1,0,1]:
    amount=q*divisor+delta
    if 0<=amount<=U:
     for seed in [0,165,255]:add(amount,0,[0],[d],seed)
 for first in [[],[0],[1],[U],[2,0,1],[3,2,1,0]]:
  for decimals in [[],[0],[7,8],[1,8,9]]:
   for index in [0,1,2,3,4,U]:
    for amount in [0,100000000,U]:add(amount,index,first,decimals)
 rng=random.Random(115029)
 for _ in range(128):
  first=[rng.randrange(5) for _ in range(rng.randrange(5))];decimals=[rng.randrange(256) for _ in range(rng.randrange(4))]
  add(rng.getrandbits(64),rng.randrange(5),first,decimals,rng.randrange(256))
 return sorted(rows)
def corpus(im):
 inputs=[];expected=[];seen=set()
 for row in stimuli():
  result,trace=evaluate(im,row);seen|=trace;inputs.append(encode(row)+'\n');expected.append(result+'\n')
 return ''.join(inputs).encode(),''.join(expected).encode(),seen
def verify():
 record=json.loads((PACKET/'FREEZE.json').read_text());im=Image()
 try:
  if hashlib.sha256(im.data).hexdigest()!=SHA:raise ValueError('wrong115target')
  inputs,expected,seen=corpus(im)
  for name,data in [('input',inputs),('expected',expected)]:
   if hashlib.sha256(data).hexdigest()!=record[name+'_sha256']:raise ValueError('frozen '+name+' drift')
  if sorted(seen)!=record['visited_addresses'] or len(expected.splitlines())!=record['rows']:raise ValueError('spot denominator drift')
  return inputs,expected
 finally:im.close()
if __name__=='__main__':
 a,b=verify();print('Original spot replay PASS',len(b.splitlines()),'observations')
