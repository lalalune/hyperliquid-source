"""Original quantity-change entry and independent fresh post-lookup point.

Stop BEFORE every helper. Record actual ordered counter/total stores, RET or
call frontier; no supplied lookup/callback/logger return or composed trace.
"""
from pathlib import Path
import hashlib,sys
ROOT=Path(__file__).resolve().parents[3];PACKET=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'tools'))
import decimal_scaled_u64 as cpu
from elfview import View
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
TARGET=ROOT/'artifacts/node/115/hl-node'
COUNTER=cpu.INPUT;TOTAL=COUNTER+0x20;DESC=COUNTER+0x40;CONTEXT=COUNTER+0x100;LOOKUP=COUNTER+0x200
RANGES=[(0x4206f70,0x4206fe5),(0x4206ff2,0x4207061),(0x4207066,0x420709b),(0x42070ac,0x42070d0),(0x42070df,0x42070fe)]
FRONTIERS={0x4206fe5:'L',0x4207061:'N',0x420709b:'S',0x42070d0:'A',0x42070fe:'I'}
class Image:
 slots={};note_target=None;panic_targets=set()
 def __init__(self):self.view=View(TARGET);self.data=self.view.b;self.cache={}
 def read_only(self,a):return None
 def fetch(self,a):
  if not any(lo<=a<hi for lo,hi in RANGES):raise ValueError('quantity CFG escape '+hex(a))
  if a not in self.cache:self.cache[a]=cpu.decode(self.data,self.view.offset(a),a)
  return self.cache[a]
 def close(self):
  if self.data is not self.view.b:self.data.close()
  self.view.b.close();self.view.file.close()
class Machine(cpu.Machine):
 def __init__(self,im):
  super().__init__(im);self.regions=[(COUNTER,COUNTER+8),(TOTAL,TOTAL+8),(DESC,DESC+32),(cpu.STACK,cpu.STACK+0x90)];self.writes={COUNTER:[],TOTAL:[]}
 def bounds(self,a,n,write=False):
  allowed=self.regions[:2]+self.regions[3:] if write else self.regions
  if not any(lo<=a and a+n<=hi for lo,hi in allowed):raise ValueError('quantity memory footprint')
 def load(self,a,n):self.bounds(a,n);return super().load(a,n)
 def reload(self,r,a,n):self.bounds(a,n);return super().reload(r,a,n)
 def store(self,a,n,v):
  self.bounds(a,n,True)
  if a in self.writes:
   if n!=8 or v is None:raise ValueError('unknown/partial quantity store')
   self.writes[a].append(v)
  return super().store(a,n,v)
 def spill(self,a,r,n):
  self.bounds(a,n,True)
  if a in self.writes:
   v=self.get(r,64)
   if n!=8 or v is None:raise ValueError('unknown/partial quantity spill')
   self.writes[a].append(v)
  return super().spill(a,r,n)
 def call(self,*a):raise ValueError('quantity helper calls forbidden')
def payload(seed):return bytes((seed+17*i)&255 for i in range(20))
def evaluate(im,row):
 point,old,new,word,notify,seed=row
 if point not in [0,1,2] or any(not 0<=v<=cpu.U64 for v in [old,new,word,notify]) or not 0<=seed<=255:raise ValueError('qualified quantity words required')
 m=Machine(im)
 for lo,hi in m.regions:
  for a in range(lo,hi):m.mem[a]=(149+7*(a-lo))&255
 def putword(a,v):
  for i,b in enumerate(v.to_bytes(8,'little')):m.mem[a+i]=b
 putword(COUNTER,word if point!=2 else 0);putword(TOTAL,word if point==2 else 0)
 for i,b in enumerate(payload(seed)):m.mem[DESC+i]=b
 putword(DESC+0x18,notify);putword(cpu.STACK+0x88,cpu.RETURN_MARK)
 before={a:v for a,v in m.mem.items() if not cpu.STACK<=a<cpu.STACK+0x90}
 if point<2:
  m.pc=0x4206f70
  regs=[(cpu.RSP,cpu.STACK+0x88),(cpu.RDI,CONTEXT),(cpu.RSI,old),(cpu.RDX,new),(cpu.RCX,COUNTER),(cpu.R8,LOOKUP if point else 0),(cpu.R9,DESC)]
 else:
  m.pc=0x4206ff2
  regs=[(cpu.RSP,cpu.STACK+0x10),(cpu.R12,old),(cpu.RBX,new),(cpu.R14,CONTEXT),(cpu.R15,DESC),(cpu.RAX,TOTAL)]
 for r,v in regs:m.set_reg(r,v)
 def observe(kind):
  cell=TOTAL if point==2 else COUNTER;other=COUNTER if point==2 else TOTAL
  if m.writes[other]:raise ValueError('other cell modified')
  for a,v in before.items():
   if not cell<=a<cell+8 and m.mem[a]!=v:raise ValueError('unrelated input modified')
  value=m.load(cell,8);writes=','.join(map(str,m.writes[cell])) or '-'
  extra=''
  if kind=='N':
   sp=m.get(cpu.RSP,64);at=m.get(cpu.RSI,64)
   if sp!=cpu.STACK+0x10 or at!=sp+0x10 or m.get(cpu.RDX,64)!=CONTEXT:raise ValueError('notification argument footprint changed')
   raw_notify=m.get(cpu.RDI,64);raw_new=m.get(cpu.RCX,64)
   if raw_notify is None or raw_new is None:raise ValueError('unknown notification words')
   copied=bytes(m.mem[at+i] for i in range(20))
   extra=':'+str(raw_notify)+':'+str(raw_new)+':'+copied.hex()
  if kind in ['S','A']:
   pending=m.get(cpu.RBP if kind=='S' else cpu.R13,64)
   if pending is None:raise ValueError('unknown pending signed endpoint')
   extra=':'+str(pending)
  if kind=='L' and (m.get(cpu.RSI,64)!=LOOKUP or m.get(cpu.RDX,64)!=CONTEXT):raise ValueError('lookup arguments changed')
  return ('T' if point==2 else 'E')+':'+str(value)+':'+writes+':'+kind+extra
 for _ in range(200):
  if m.pc in FRONTIERS:return observe(FRONTIERS[m.pc]),m.seen
  try:m.step()
  except cpu.Done as done:
   if done.how!='ret' or m.get(cpu.RSP,64)!=cpu.STACK+0x90:raise ValueError('quantity return drift')
   return observe('R'),m.seen
 raise ValueError('quantity step bound')
def stimuli():
 rows=[];values=[0,1,2,(1<<63)-1,1<<63,cpu.U64];counters=[0,1,2,3,(1<<32)-1,1<<63,cpu.U64-1,cpu.U64]
 totals=[0,1,2,(1<<63)-2,(1<<63)-1,1<<63,(1<<63)+1,cpu.U64-1,cpu.U64]
 for point in [0,1,2]:
  for old in values:
   for new in values:
    for word in (totals if point==2 else counters):
     for notify in [0,1,cpu.U64]:rows.append((point,old,new,word,notify,90))
 state=0x918f1c02d7a3
 for _ in range(192):
  words=[]
  for _ in range(3):state=(state*6364136223846793005+1442695040888963407)&cpu.U64;words.append(state)
  rows.append((2,*words,1,90))
 for seed in range(256):rows.extend([(0,0,1,3,1,seed),(2,1,2,3,cpu.U64,seed)])
 return list(dict.fromkeys(rows))
def corpus(im):
 inputs=[];expected=[];seen=set()
 for row in stimuli():
  result,trace=evaluate(im,row);inputs.append('\t'.join(map(str,row))+'\n');expected.append(result+'\n');seen|=trace
 return ''.join(inputs).encode(),''.join(expected).encode(),seen
if __name__=='__main__':
 im=Image()
 try:
  if hashlib.sha256(im.data).hexdigest()!=SHA:raise ValueError('wrong115target')
  a,b,c=corpus(im);print('PROBE',len(a.splitlines()),len(c))
 finally:im.close()
