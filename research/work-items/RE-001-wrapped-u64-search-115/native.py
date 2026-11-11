"""Actual complete u64-key ring-search family, exact status/logical index."""
from pathlib import Path
import hashlib,itertools,json,sys
ROOT=Path(__file__).resolve().parents[3];PACKET=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'tools'))
import decimal_scaled_u64 as cpu
from elfview import View
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301';TARGET=ROOT/'artifacts/node/115/hl-node'
FAMILIES=[(0x2ee0640,0x2ee0761,32),(0x4551810,0x455192b,56)]
OBJ=cpu.INPUT;QUERY=OBJ+0x100;DATA=OBJ+0x1003;SP=cpu.STACK;MASK=(1<<64)-1
class Image:
 slots={};note_target=None;panic_targets=set()
 def __init__(self):self.view=View(TARGET);self.data=self.view.b;self.cache={}
 def read_only(self,a):return None
 def fetch(self,a):
  if not any(lo<=a<hi for lo,hi,_ in FAMILIES):raise ValueError('wrapped-search CFG escape')
  if a not in self.cache:self.cache[a]=cpu.decode(self.data,self.view.offset(a),a)
  return self.cache[a]
 def close(self):
  if self.data is not self.view.b:self.data.close()
  self.view.b.close();self.view.file.close()
class Machine(cpu.Machine):
 def __init__(self,im,live):super().__init__(im);self.record=False;self.live=live;self.regions=[(OBJ,OBJ+32),(SP,SP+8),(QUERY,QUERY+8),*[(p,p+8) for p in live]]
 def bounds(self,a,n):
  if not any(lo<=a and a+n<=hi for lo,hi in self.regions):raise ValueError('unused capacity/payload or footprint '+hex(a))
  if self.record and not self.live and QUERY<=a<QUERY+8:raise ValueError('empty search read needle')
 def load(self,a,n):self.bounds(a,n);return super().load(a,n)
 def reload(self,r,a,n):self.bounds(a,n);return super().reload(r,a,n)
 def store(self,a,n,v):
  if self.record:raise ValueError('write in read-only search')
  return super().store(a,n,v)
 def spill(self,a,r,n):
  if self.record:raise ValueError('spill in read-only search')
  return super().spill(a,r,n)
 def call(self,*args):raise ValueError('call in call-free search')
def evaluate(im,row):
 if len(row)!=5 or row[0] not in [0,1]:raise ValueError('family/geometry/keys/query required')
 family,capacity,head,keys,query=row;start,end,stride=FAMILIES[family];count=len(keys)
 if not 0<=count<=capacity<=32 or not (0<=head<2*capacity if capacity else head==0) or not 0<=query<=MASK or any(not 0<=k<=MASK for k in keys) or keys!=sorted(keys):raise ValueError('qualified sorted bounded geometry')
 h=head-capacity if head>=capacity else head
 live={DATA+stride*((h+i)%capacity):k for i,k in enumerate(keys)}
 m=Machine(im,live)
 for off,value in [(0,capacity),(8,DATA),(16,head),(24,count)]:m.store(OBJ+off,8,value)
 if count:m.store(QUERY,8,query)
 for at,k in live.items():m.store(at,8,k)
 m.store(SP,8,cpu.RETURN_MARK);m.set_reg(cpu.RDI,OBJ);m.set_reg(cpu.RSI,QUERY);m.set_reg(cpu.RSP,SP);m.record=True
 try:m.run(start)
 except cpu.Done:
  if not start<m.pc<=end or im.fetch(m.pc-1).key!=0xc3 or m.get(cpu.RSP,64)!=SP+8:raise ValueError('not genuine search RET')
 result=[m.get(cpu.RAX,64),m.get(cpu.RDX,64)]
 if None in result:raise ValueError('unknown status/index')
 return result,m.seen

def stimuli():
 rows=[]
 def add(keys,queries):
  n=len(keys)
  for c in sorted({n,min(32,n+2)}):
   for h in sorted({0,c//2,max(0,c-1),c,c+c//2,max(0,2*c-1)} if c else {0}):
    for q in queries:
     for family in [0,1]:rows.append([family,c,h,keys,q])
 for size in range(6):
  for seq in itertools.combinations_with_replacement([0,1,MASK],size):add(list(seq),[0,1,2,1<<63,MASK])
 for n in [7,16,30,32]:
  for seq in [[0]*n,[MASK]*n,list(range(n)),[0]*(n//2)+[MASK]*(n-n//2),[(1<<63)+i//2 for i in range(n)]]:add(seq,[0,1,2,(1<<63)-1,1<<63,MASK])
 return list({json.dumps(x,separators=(',',':')):x for x in rows}.values())
def corpus(im):
 inputs=[];expected=[];seen=set()
 for row in stimuli():
  result,trace=evaluate(im,row);seen|=trace;inputs.append(json.dumps(row,separators=(',',':'))+'\n');expected.append(json.dumps(result,separators=(',',':'))+'\n')
 return ''.join(inputs).encode(),''.join(expected).encode(),seen
