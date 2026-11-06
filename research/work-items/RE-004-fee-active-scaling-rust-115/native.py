"""Actual node115 checked scaling instructions, no diagnostic helper answers.

Uses the project's MIT decimal_scaled_u64 instruction machine and the credited
user-admission ELF reader. All routine-specific state, corpus and observations
are independently authored here; imported captures remain read-only.
"""
from pathlib import Path
import itertools,json,sys
ROOT=Path(__file__).resolve().parents[3];PACKET=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'tools'))
import decimal_scaled_u64 as cpu
from elfview import View
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
TARGET=ROOT/'artifacts/node/115/hl-node';OWNER=(0x46a6860,0x46a69cf)
SRC=cpu.INPUT;OUT=SRC+0x1000;SP=cpu.STACK;FRAME=SP-88
MASK=(1<<64)-1;MIN=1<<63
LIMIT=MASK//100
STOPS={0x46a6973:'A',0x46a6982:'L',0x46a6991:'I'}
class Image:
 slots={};note_target=None;panic_targets=set()
 def __init__(self):self.view=View(TARGET);self.data=self.view.b;self.cache={}
 def read_only(self,a):return None
 def fetch(self,a):
  if not OWNER[0]<=a<OWNER[1]:raise ValueError('scaling CFG escape')
  if a not in self.cache:self.cache[a]=cpu.decode(self.data,self.view.offset(a),a)
  return self.cache[a]
 def close(self):
  if self.data is not self.view.b:self.data.close()
  self.view.b.close();self.view.file.close()
class Machine(cpu.Machine):
 def __init__(self,im):super().__init__(im);self.record=False;self.reads=set();self.writes=set()
 def bounds(self,a,n):
  if not any(lo<=a and a+n<=hi for lo,hi in [(SRC,SRC+120),(OUT,OUT+120),(FRAME,SP+8)]):raise ValueError('scaling undeclared memory '+hex(a))
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
  if not (OUT<=a and a+n<=OUT+120 or FRAME<=a and a+n<=SP+8):raise ValueError('scaling input write')
  if self.record:self.writes.update(range(a,a+n))
 def store(self,a,n,v):
  if self.record:self.writable(a,n)
  return super().store(a,n,v)
 def spill(self,a,r,n):
  if self.record:self.writable(a,n)
  return super().spill(a,r,n)
 def call(self,*args):raise ValueError('diagnostic helper executed')
def word(data,off):return int.from_bytes(data[off:off+8],'little')
def normalize(m,raw,kind):
 # Explicit, contract-level inactive-payload exclusion. Retained native knownness
 # is separate, so masking is neither silent nor a complete120B claim.
 excluded=set()
 if kind=='R':
  if word(raw,0)!=1:excluded.update(range(8,36))
  if word(raw,40)==MIN:excluded.update(range(56,92))
 values=[]
 for i in range(120):
  v=m.mem.get(OUT+i)
  if i in excluded:values.append('??')
  elif v is None:raise ValueError('unknown ACTIVE scaling output '+str(i))
  else:values.append(f'{v:02x}')
 return ''.join(values)
def evaluate(im,row):
 raw,seed=row;raw=bytes.fromhex(raw)
 if len(raw)!=120 or not 0<=seed<=255:raise ValueError('scaling raw input')
 m=Machine(im)
 for base,data in [(SRC,raw),(OUT,bytes([seed])*120)]:
  for i,v in enumerate(data):m.mem[base+i]=v
 m.store(SP,8,cpu.RETURN_MARK)
 for reg,value in [(cpu.RDI,OUT),(cpu.RSI,SRC),(cpu.RSP,SP)]:m.set_reg(reg,value)
 m.record=True;m.pc=OWNER[0]
 try:
  while m.pc not in STOPS:
   m.steps+=1
   if m.steps>500:raise ValueError('scaling nontermination')
   m.step()
  kind=STOPS[m.pc]
  if (m.get(cpu.RDI,64),m.get(cpu.RSP,64))!=(0x6493610,FRAME):raise ValueError('scaling diagnostic argument origin')
  if any(OUT<=a<OUT+120 for a in m.writes):raise ValueError('output written before diagnostic frontier')
 except cpu.Done:
  kind='R'
  if (m.pc,m.get(cpu.RSP,64),m.get(cpu.RAX,64))!=(0x46a696c,SP+8,OUT):raise ValueError('not genuine scaling RET')
 m.record=False
 return [kind,normalize(m,raw,kind)],m.seen
def stimulus(outer=1,inner=0,values=(0,0,0,0,0),pattern=7,seed=165):
 raw=bytearray((pattern+17*i)%256 for i in range(120));raw[:8]=outer.to_bytes(8,'little');raw[40:48]=inner.to_bytes(8,'little')
 for off,value in zip([96,104,8,64,112],values):raw[off:off+8]=value.to_bytes(8,'little')
 return [raw.hex(),seed]
def control_inputs():
 return [stimulus(outer=0,inner=MIN,values=(0,0,0,LIMIT+1,0)),stimulus(outer=1,inner=MIN,values=(0,0,0,LIMIT+1,0)),stimulus(),stimulus(outer=0),stimulus(outer=2),stimulus(inner=MIN),stimulus(inner=MIN+1),*[stimulus(values=tuple(1 if i==j else 0 for i in range(5))) for j in range(5)],*[stimulus(values=tuple(LIMIT+1 if i==j else 0 for i in range(5))) for j in range(5)],stimulus(values=(0,0,0,LIMIT+1,LIMIT+1))]
def stimuli():
 rows=[];bounds=[0,1,2,LIMIT-1,LIMIT,LIMIT+1,MIN-1,MIN,MIN+1,MASK]
 for outer,inner,seed in itertools.product([0,1,2,MIN,MASK],[0,1,MIN-1,MIN,MIN+1,MASK],[0,165,255]):
  rows.append(stimulus(outer,inner,seed=seed))
  for field,value in itertools.product(range(5),bounds):rows.append(stimulus(outer,inner,tuple(value if i==field else 1 for i in range(5)),seed=seed))
 for pattern in range(256):rows.append(stimulus(values=(2,3,5,7,11),pattern=pattern))
 # Every pair of potential overflow sites independently shows priority and
 # skipped optional fields; no diagnostic return is supplied.
 for outer,inner,mask in itertools.product([0,1,2],[0,MIN],range(32)):rows.append(stimulus(outer,inner,tuple(LIMIT+1 if mask&(1<<i) else LIMIT for i in range(5))))
 rows.extend(control_inputs());return list({json.dumps(x,separators=(',',':')):x for x in rows}.values())
def corpus(im):
 inputs=[];expected=[];seen=set();kinds={}
 for row in stimuli():
  value,trace=evaluate(im,row);seen|=trace;kinds[value[0]]=kinds.get(value[0],0)+1;inputs.append(json.dumps(row,separators=(',',':'))+'\n');expected.append(json.dumps(value,separators=(',',':'))+'\n')
 return ''.join(inputs).encode(),''.join(expected).encode(),seen,kinds
