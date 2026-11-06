"""Actual node115 complete200byte permutation; no high-level expected routine."""
from pathlib import Path
import hashlib,json,sys
ROOT=Path(__file__).resolve().parents[3];PACKET=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'tools'))
import decimal_scaled_u64 as cpu
from elfview import View
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
TARGET=ROOT/'artifacts/node/115/hl-node';OWNER=(0x5cda380,0x5cda902);TABLE=0x94c518;STATE=cpu.INPUT;SP=cpu.STACK;MASK=(1<<64)-1
SAVED=[cpu.RBX,cpu.RBP,cpu.R12,cpu.R13,cpu.R14,cpu.R15]
class Image:
 slots={};note_target=None;panic_targets=set()
 def __init__(self):self.view=View(TARGET);self.data=self.view.b;self.cache={};self.table_offset=self.view.offset(TABLE)
 def read_only(self,a):return self.data[self.table_offset+a-TABLE] if TABLE<=a<TABLE+192 else None
 def fetch(self,a):
  if not OWNER[0]<=a<OWNER[1]:raise ValueError('permutation CFG escape')
  if a not in self.cache:self.cache[a]=cpu.decode(self.data,self.view.offset(a),a)
  return self.cache[a]
 def close(self):
  if self.data is not self.view.b:self.data.close()
  self.view.b.close();self.view.file.close()
class Machine(cpu.Machine):
 def __init__(self,im):super().__init__(im);self.record=False;self.reads=set();self.writes=set()
 def bounds(self,a,n):
  if not any(lo<=a and a+n<=hi for lo,hi in [(STATE,STATE+200),(TABLE,TABLE+192),(SP-272,SP+8)]):raise ValueError('permutation undeclared memory '+hex(a))
 def load(self,a,n):
  self.bounds(a,n)
  if self.record:self.reads.update(range(a,a+n))
  return super().load(a,n)
 def reload(self,r,a,n):
  self.bounds(a,n)
  if self.record:self.reads.update(range(a,a+n))
  return super().reload(r,a,n)
 def writable(self,a,n):
  self.bounds(a,n)
  if not (STATE<=a and a+n<=STATE+200 or SP-272<=a and a+n<=SP+8):raise ValueError('permutation readonly table write')
  if self.record:self.writes.update(range(a,a+n))
 def store(self,a,n,v):
  if self.record:self.writable(a,n)
  return super().store(a,n,v)
 def spill(self,a,r,n):
  if self.record:self.writable(a,n)
  return super().spill(a,r,n)
 def shift(self,kind,value,count,bits):
  if kind!=0 or bits!=64:return super().shift(kind,value,count,bits)
  # Actual REX.W ROL forms only. ZF/SF unaffected; OF unknown for count>1.
  if value is None or count is None:self.flags=[None,self.flags[1],self.flags[2],None];return None
  count &= 63
  if count==0:return value
  result=((value<<count)|(value>>(64-count)))&MASK
  carry=bool(result&1);overflow=bool((result>>63)^int(carry)) if count==1 else None
  self.flags=[carry,self.flags[1],self.flags[2],overflow];return result
 def call(self,*args):raise ValueError('unexpected permutation helper CALL')
def evaluate(im,hexstate):
 raw=bytes.fromhex(hexstate)
 if len(raw)!=200:raise ValueError('permutation200byte input')
 m=Machine(im)
 for i,v in enumerate(raw):m.mem[STATE+i]=v
 for i in range(16):m.mem[STATE-16+i]=0xa5;m.mem[STATE+200+i]=0x5a
 m.store(SP,8,cpu.RETURN_MARK);m.set_reg(cpu.RDI,STATE);m.set_reg(cpu.RSP,SP)
 saved={r:0x9a00112233445566+17*r for r in SAVED}
 for r,v in saved.items():m.set_reg(r,v)
 m.record=True
 try:m.run(OWNER[0])
 except cpu.Done:pass
 m.record=False
 if (m.pc,m.get(cpu.RSP,64))!=(OWNER[1],SP+8):raise ValueError('not genuine permutation RET')
 if any(m.get(r,64)!=v for r,v in saved.items()):raise ValueError('callee-saved register not restored')
 if any(m.mem[STATE-16+i]!=0xa5 or m.mem[STATE+200+i]!=0x5a for i in range(16)):raise ValueError('state canary changed')
 if not set(range(STATE,STATE+200))<=m.writes:raise ValueError('not all200 output bytes written')
 values=[m.mem.get(STATE+i) for i in range(200)]
 if None in values:raise ValueError('unknown permutation output')
 return bytes(values).hex(),m.seen,m.steps
if __name__=='__main__':
 im=Image()
 try:
  if hashlib.sha256(im.data).hexdigest()!=SHA:raise ValueError('wrong115target')
  for raw in ['00'*200,bytes(range(200)).hex()]:
   out,seen,steps=evaluate(im,raw);print('PERMUTATION SMOKE',len(seen),steps,out[:32],flush=True)
 finally:im.close()
