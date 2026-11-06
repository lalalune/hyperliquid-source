"""Complete actual indirect-triplet insertion, including encoded UD2 guard."""
from pathlib import Path
import hashlib,itertools,json,sys
ROOT=Path(__file__).resolve().parents[3];PACKET=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'tools'))
import decimal_scaled_u64 as cpu
from elfview import View
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301';TARGET=ROOT/'artifacts/node/115/hl-node';OWNER=(0x26d4280,0x26d4376)
DATA=cpu.INPUT+0x1003;KEYS=DATA+0x2000;SP=cpu.STACK;MASK=(1<<64)-1
class Trap(Exception):pass
class Image:
 slots={};note_target=None;panic_targets=set()
 def __init__(self):self.view=View(TARGET);self.data=self.view.b;self.cache={}
 def read_only(self,a):return None
 def fetch(self,a):
  if not OWNER[0]<=a<OWNER[1]:raise ValueError('triplet CFG escape')
  if a not in self.cache:self.cache[a]=cpu.decode(self.data,self.view.offset(a),a)
  return self.cache[a]
 def close(self):
  if self.data is not self.view.b:self.data.close()
  self.view.b.close();self.view.file.close()
class Machine(cpu.Machine):
 def __init__(self,im,count,ids):
  super().__init__(im);self.count=count;self.record=False;self.reads=set();self.writes=set();self.regions=[(DATA,DATA+16*count),(SP-16,SP+8),*[(KEYS+16*i,KEYS+16*i+12) for i in ids]]
 def bounds(self,a,n):
  if not any(lo<=a and a+n<=hi for lo,hi in self.regions):raise ValueError('triplet undeclared footprint '+hex(a))
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
  if not (DATA<=a and a+n<=DATA+16*self.count or SP-16<=a and a+n<=SP+8):raise ValueError('triplet changed immutable key')
  if self.record:self.writes.update(range(a,a+n))
 def store(self,a,n,v):
  if self.record:self.writable(a,n)
  return super().store(a,n,v)
 def spill(self,a,r,n):
  if self.record:self.writable(a,n)
  return super().spill(a,r,n)
 def call(self,*args):raise ValueError('call in call-free insertion')
 def two_byte(self,ins,key,bits,rexr,here):
  if key==(0x0f,0x0b):raise Trap(here)
  return super().two_byte(ins,key,bits,rexr,here)
def evaluate(im,row):
 if len(row)!=3:raise ValueError('k/records/keytable required')
 k,records,keys=row;n=len(records)
 if not 0<=k<=MASK or n>16 or len(keys)>16 or any(len(key)!=3 or any(not 0<=x<=0xffffffff for x in key) for key in keys) or any(len(r)!=2 or not 0<=r[0]<=MASK or not 0<=r[1]<len(keys) for r in records):raise ValueError('qualified finite records/key origins')
 ids={r[1] for r in records};m=Machine(im,n,ids)
 for i,(payload,key) in enumerate(records):m.store(DATA+16*i,8,payload);m.store(DATA+16*i+8,8,KEYS+16*key)
 for key in ids:
  for word,value in enumerate(keys[key]):m.store(KEYS+16*key+4*word,4,value)
 m.store(SP,8,cpu.RETURN_MARK);m.set_reg(cpu.RDI,DATA);m.set_reg(cpu.RSI,n);m.set_reg(cpu.RDX,k);m.set_reg(cpu.RSP,SP);m.record=True;kind=None
 try:m.run(OWNER[0])
 except Trap as e:
  if e.args!=(0x26d4374,) or m.get(cpu.RSP,64)!=SP or m.reads or m.writes:raise ValueError('not pristine entry UD2 guard')
  kind=1
 except cpu.Done:
  if m.pc!=0x26d4374 or m.get(cpu.RSP,64)!=SP+8:raise ValueError('not real insertion RET')
  kind=0
 if kind is None:raise ValueError('missing terminal state')
 if k==n and 1<=k and (m.writes or any(DATA<=a<DATA+16*n or KEYS<=a<KEYS+256 for a in m.reads)):raise ValueError('k==n touched records/keys')
 m.record=False;after=[]
 for i in range(n):
  payload=m.load(DATA+16*i,8);ptr=m.load(DATA+16*i+8,8)
  if payload is None or ptr is None or ptr<KEYS or (ptr-KEYS)%16 or (ptr-KEYS)//16>=len(keys):raise ValueError('unknown payload or changed key origin')
  after.append([payload,(ptr-KEYS)//16])
 return [kind,after],m.seen

def stimuli():
 rows=[];tables=[[[0x80000000,0xffffffff,0xffffffff],[0,0x80000000,0xffffffff],[0x7fffffff,0,0]],[[0,0,0],[0,0x80000000,0],[0,0xffffffff,0]],[[0,0,0],[0,0,0x80000000],[0,0,0xffffffff]],[[7,11,13]]*3]
 for table in tables:
  for size in range(6):
   for seq in itertools.product(range(3),repeat=size):
    records=[[0x1000+i*29,key] for i,key in enumerate(seq)]
    for k in sorted({0,*range(1,size+1),size+1,MASK}):rows.append([k,records,table])
 for size in [7,16]:
  table=[[0xffffffff if i%3==0 else 0x80000000 if i%3==1 else 0,i//3,(i*0x9e3779b9)&0xffffffff] for i in range(size)]
  for order in [list(range(size)),list(reversed(range(size))),[(i*5)%size for i in range(size)],[0]*size]:
   records=[[(MASK-i*0x100000001)&MASK,key] for i,key in enumerate(order)]
   for k in [0,1,2,size//2,size,size+1,MASK]:rows.append([k,records,table])
 return list({json.dumps(x,separators=(',',':')):x for x in rows}.values())
def corpus(im):
 inputs=[];expected=[];seen=set();traps=0
 for row in stimuli():
  result,trace=evaluate(im,row);seen|=trace;traps+=result[0];inputs.append(json.dumps(row,separators=(',',':'))+'\n');expected.append(json.dumps(result,separators=(',',':'))+'\n')
 return ''.join(inputs).encode(),''.join(expected).encode(),seen,traps
