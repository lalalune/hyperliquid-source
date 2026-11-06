"""Actual node115 fee-window instructions, exact return and cursor state."""
from pathlib import Path
import hashlib,itertools,json,struct,sys
ROOT=Path(__file__).resolve().parents[3];PACKET=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'tools'))
import decimal_scaled_u64 as cpu
from elfview import View
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301';TARGET=ROOT/'artifacts/node/115/hl-node';OWNER=(0x36e1b10,0x36e1b81)
OBJ=cpu.INPUT;DATA=OBJ+0x1003;SP=cpu.STACK;MASK=(1<<64)-1
class Image:
 slots={};note_target=None;panic_targets=set()
 def __init__(self):self.view=View(TARGET);self.data=self.view.b;self.cache={}
 def read_only(self,a):return None
 def fetch(self,a):
  if not OWNER[0]<=a<OWNER[1]:raise ValueError('fee owner CFG escape')
  if a not in self.cache:self.cache[a]=cpu.decode(self.data,self.view.offset(a),a)
  return self.cache[a]
 def close(self):
  if self.data is not self.view.b:self.data.close()
  self.view.b.close();self.view.file.close()
def nan(x):return x&0x7ff0000000000000==0x7ff0000000000000 and x&0xfffffffffffff!=0
def snan(x):return nan(x) and not x&0x8000000000000
def relation(left,right):
 # Exact binary64 ordered relation, DAZ clear. Quiet NaNs set C/Z; PF unused.
 if snan(left) or snan(right):raise ValueError('signaling NaN exception outside contract')
 if nan(left) or nan(right):return [True,True,False,False]
 equal=left==right or left&0x7fffffffffffffff==0 and right&0x7fffffffffffffff==0
 def order(x):return (~x&MASK) if x>>63 else x^(1<<63)
 return [not equal and order(left)<order(right),equal,False,False]
class Machine(cpu.Machine):
 def __init__(self,im,n):super().__init__(im);self.n=n;self.regions=[(OBJ,OBJ+24),(DATA,DATA+8*n),(SP-8,SP+8)];self.record=False;self.writes=set()
 def bounds(self,a,n):
  if not any(lo<=a and a+n<=hi for lo,hi in self.regions):raise ValueError('fee footprint '+hex(a))
 def load(self,a,n):self.bounds(a,n);return super().load(a,n)
 def reload(self,r,a,n):self.bounds(a,n);return super().reload(r,a,n)
 def store(self,a,n,v):
  self.bounds(a,n)
  if self.record:
   if DATA<=a<DATA+8*self.n:raise ValueError('fee wrote immutable input')
   self.writes.update(range(a,a+n))
  return super().store(a,n,v)
 def spill(self,a,r,n):self.bounds(a,n);return super().spill(a,r,n)
 def call(self,*args):raise ValueError('opaque diagnostic call outside normal contract')
 def two_byte(self,ins,key,bits,rexr,here):
  if key==(0x0f,0x10) and ins.rep==0xf2:
   reg=((self.image.data[ins.modrm]>>3)&7)|rexr;op=self.operand(ins)
   if op[0]!='m':raise ValueError('unqualified MOVSD register form')
   v=self.load(self.address(op),8)
   if v is None:raise ValueError('unknown MOVSD input')
   self.xmm[reg]=struct.pack('<Q',v)+bytes(8);return
  if key==(0x0f,0x2e):
   if not ins.wide16 or ins.rep:raise ValueError('unqualified UCOMISD')
   reg=((self.image.data[ins.modrm]>>3)&7)|rexr;op=self.operand(ins)
   if op[0]!='m' or self.xmm[reg] is None:raise ValueError('unqualified UCOMISD operand')
   right=self.load(self.address(op),8)
   if right is None:raise ValueError('unknown compare input')
   left=struct.unpack('<Q',self.xmm[reg][:8])[0];self.flags=relation(left,right);return
  return super().two_byte(ins,key,bits,rexr,here)
def evaluate(im,row):
 width,words=row
 if not 0<=width<=MASK or len(words)>32 or any(not 0<=x<=MASK or snan(x) for x in words):raise ValueError('outside qualified input')
 if width<2 and words:raise ValueError('nonempty invalid width diagnostic excluded')
 m=Machine(im,len(words));m.store(OBJ,8,DATA);m.store(OBJ+8,8,len(words));m.store(OBJ+16,8,width);m.store(SP,8,cpu.RETURN_MARK)
 for i,v in enumerate(words):m.store(DATA+8*i,8,v)
 m.set_reg(cpu.RDI,OBJ);m.set_reg(cpu.RSP,SP);m.record=True
 try:m.run(OWNER[0])
 except cpu.Done:
  if m.pc not in [0x36e1b53,0x36e1b5c] or m.get(cpu.RSP,64)!=SP+8:raise ValueError('not real fee RET')
 m.record=False;answer=m.get(cpu.RAX,8);ptr=m.load(OBJ,8);remaining=m.load(OBJ+8,8)
 if answer not in [0,1] or ptr is None or not DATA<=ptr<=DATA+8*len(words) or (ptr-DATA)%8 or m.load(OBJ+16,8)!=width:raise ValueError('unqualified result')
 if [m.load(DATA+8*i,8) for i in range(len(words))]!=words:raise ValueError('changed input')
 return [answer,(ptr-DATA)//8,remaining],m.seen

def stimuli():
 rows=[];core=[0,0x8000000000000000,0x3ff0000000000000,0x7ff8000000000001]
 for n in range(6):
  for words in itertools.product(core,repeat=n):
   for width in sorted({2,3,n,n+1}):
    if width>=2 or not words:rows.append([width,list(words)])
 edge=[0,1,0xfffffffffffff,0x10000000000000,0x3ff0000000000000,0x7fefffffffffffff,0x7ff0000000000000,0x7ff8000000000001,0x7fffffffffffffff]
 edge+= [x|(1<<63) for x in edge]
 for a,b in itertools.product(edge,repeat=2):
  for width in [2,3]:rows.append([width,[a,b]])
 state=0x13579bdf2468ace0
 for n in [3,7,16,32]:
  for repeat in range(48):
   words=[]
   for i in range(n):
    state=(state*6364136223846793005+1442695040888963407)&MASK;v=state
    if snan(v):v|=0x8000000000000
    words.append(v)
   for width in [2,n,n+1,MASK]:rows.append([width,words])
 rows += [[w,[]] for w in [0,1,2,3,MASK]]
 return list({json.dumps(x,separators=(',',':')):x for x in rows}.values())
def corpus(im):
 inputs=[];expected=[];seen=set()
 for row in stimuli():
  answer,trace=evaluate(im,row);seen|=trace;inputs.append(json.dumps(row,separators=(',',':'))+'\n');expected.append(json.dumps(answer,separators=(',',':'))+'\n')
 return ''.join(inputs).encode(),''.join(expected).encode(),seen
