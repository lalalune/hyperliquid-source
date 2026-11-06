"""Actual private free-entry prefix, stopping BEFORE either lookup call.

Only raw2 is a real native return. Lookup/guards are named analysis frontiers;
no helper return, numeric calculation, counter update or composed trace.
"""
from pathlib import Path
import hashlib,json,sys
ROOT=Path(__file__).resolve().parents[3];PACKET=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'tools'))
import decimal_scaled_u64 as cpu
from elfview import View
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
TARGET=ROOT/'artifacts/node/115/hl-node';OWNER=(0x2c80670,0x2c80a3d)
SPANS=[(0x2c80670,0x2c8074b),(0x2c80774,0x2c80780),(0x2c809c5,0x2c809e6),(0x2c80a20,0x2c80a27),(0x2c80a2d,0x2c80a37)]
FRONTIERS={0x2c8074b:'A',0x2c80780:'B',0x2c80a27:'P',0x2c80a37:'S'}
ARG=cpu.INPUT;CTX=ARG+0x1000;OWNERCTX=ARG+0x2000;OBJ=ARG+0x3000
PRIMARY=ARG+0x10000;SECONDARY=ARG+0x20000;INDICES=ARG+0x30000;OUT=ARG+0x40000
STACK=cpu.STACK;SP=STACK+0x588;FRAME=SP-0x528
class Image:
 slots={};note_target=None;panic_targets=set()
 def __init__(self):self.view=View(TARGET);self.data=self.view.b;self.cache={}
 def read_only(self,a):return None
 def fetch(self,a):
  if not any(lo<=a<hi for lo,hi in SPANS):raise ValueError('bole prefix CFG escape '+hex(a))
  if a not in self.cache:self.cache[a]=cpu.decode(self.data,self.view.offset(a),a)
  return self.cache[a]
 def close(self):
  if self.data is not self.view.b:self.data.close()
  self.view.b.close();self.view.file.close()
class Machine(cpu.Machine):
 def __init__(self,im,nprimary,nsecondary,nindices):
  super().__init__(im);self.regions=[(ARG,ARG+24),(CTX,CTX+8),(OWNERCTX,OWNERCTX+24),(OBJ,OBJ+0x6e8),(PRIMARY,PRIMARY+nprimary*344),(SECONDARY,SECONDARY+nsecondary*32),(INDICES,INDICES+nindices*8),(OUT,OUT+16),(STACK,SP+8)]
 def bounds(self,a,n):
  if not any(lo<=a and a+n<=hi for lo,hi in self.regions):raise ValueError('bole prefix footprint '+hex(a))
 def load(self,a,n):self.bounds(a,n);return super().load(a,n)
 def reload(self,r,a,n):self.bounds(a,n);return super().reload(r,a,n)
 def store(self,a,n,v):self.bounds(a,n);return super().store(a,n,v)
 def spill(self,a,r,n):self.bounds(a,n);return super().spill(a,r,n)
 def call(self,*args):raise ValueError('bole prefix must stop before every call')
 def two_byte(self,ins,key,bits,rexr,here):
  # Only the two genuine F2 MOVSD memory copies before lookup. No floating
  # arithmetic is assigned. Loading m64 clears upper XMM64; stores low64.
  if key in [(0x0f,0x10),(0x0f,0x11)] and ins.rep==0xf2:
   reg=((self.image.data[ins.modrm]>>3)&7)|rexr;operand=self.operand(ins)
   if operand[0]!='m':raise ValueError('unexpected scalar SIMD form')
   a=self.address(operand);self.bounds(a,8)
   if key[1]==0x10:self.xmm[reg]=[self.load(a+i,1) for i in range(8)]+[0]*8
   else:
    if self.xmm[reg] is None:raise ValueError('undefined XMM source')
    for i,v in enumerate(self.xmm[reg][:8]):self.store(a+i,1,v)
   return
  return super().two_byte(ins,key,bits,rexr,here)
def evaluate(im,row):
 index,length,indices,occupied,rep,maplen,aux,fbits=row
 if not 0<=length<=16 or len(indices)>32 or len(occupied)>16 or any(not isinstance(v,int) or not 0<=v<=cpu.U64 for v in [index,rep,maplen,aux,fbits,*indices,*occupied]):raise ValueError('invalid canonical finite premise')
 m=Machine(im,length,len(occupied),len(indices))
 init=[(ARG,index),(ARG+8,aux),(ARG+16,fbits),(CTX,OWNERCTX),(OWNERCTX,OBJ),(OBJ+0xb0,PRIMARY),(OBJ+0xb8,length),(OBJ+0x98,SECONDARY),(OBJ+0xa0,len(occupied)),(OBJ+0x6c8,rep),(OBJ+0x6d0,maplen),(OBJ+0x6d8,0x12340000),(OBJ+0x38,41),(SP,cpu.RETURN_MARK),(OUT,0xa5a5a5a5a5a5a5a5)]
 if index<length:init.extend([(PRIMARY+index*344+0x58,INDICES),(PRIMARY+index*344+0x60,len(indices))])
 init.extend((INDICES+j*8,v) for j,v in enumerate(indices));init.extend((SECONDARY+j*32+8,v) for j,v in enumerate(occupied))
 for a,v in init:m.store(a,8,v)
 def incoming():return {a:v for a,v in m.mem.items() if any(lo<=a<hi for lo,hi in m.regions[:-2])}
 before=incoming()
 m.set_reg(cpu.RDI,OUT);m.set_reg(cpu.RSI,CTX);m.set_reg(cpu.RDX,ARG);m.set_reg(cpu.RSP,SP);m.pc=OWNER[0]
 for _ in range(1500):
  if m.pc in FRONTIERS:
   lane=FRONTIERS[m.pc]
   if lane=='P':result=['P',index,length]
   elif lane=='S':result=['S',m.get(cpu.R14,64),len(occupied)]
   else:
    if m.get(cpu.RSP,64)!=FRAME or m.load(FRAME+8,8)!=OUT or m.load(FRAME+0x20,8)!=index or m.load(FRAME,8)!=fbits:raise ValueError('lookup frame corruption')
    if lane=='A':
     if [m.get(r,64) for r in [cpu.RDI,cpu.RSI,cpu.RDX,cpu.RCX]]!=[FRAME+0x270,maplen,0x12340000,FRAME+0x20]:raise ValueError('first actual lookup args')
    elif [m.get(r,64) for r in [cpu.RDI,cpu.RSI]]!=[OBJ+0x6c8,FRAME+0x20]:raise ValueError('second actual lookup args')
    result=[lane,index,m.get(cpu.R14,64),m.get(cpu.RBX,64),m.load(FRAME,8)]
   break
  try:m.step()
  except cpu.Done:
   if m.pc!=0x2c809e6 or m.get(cpu.RSP,64)!=SP+8 or m.get(cpu.RAX,64)!=OUT or m.load(OUT,8)!=2:raise ValueError('not genuine raw2 RET')
   result=['R'];break
 else:raise ValueError('bole prefix step bound')
 if incoming()!=before:raise ValueError('prefix changed incoming objects or later counter')
 if any(v is None for v in result):raise ValueError('unknown active frontier field')
 return result,m.seen
def stimuli():
 rows=[]
 def add(index,length,indices,occupied,rep=0,maplen=0,aux=17,fbits=0x7ff8000000000042):rows.append([index,length,indices,occupied,rep,maplen,aux,fbits])
 for length in [0,1,2,3,8]:
  for index in [0,1,2,length,max(0,length-1),cpu.U64]:
   for occupied in [[],[0],[1],[0,1,0],[1,1,0],[1,1,1],[cpu.U64,0,7,0]]:
    for indices in [[],[0],[1],[2],[0,1,2],[2,1,0],[0,0,1],[cpu.U64],[0,cpu.U64],[1,2,1,0]]:
     for rep,maplen in [(0,0),(1,1),(1<<63,0),(1<<63,1)]:add(index,length,indices,occupied,rep,maplen)
 for n in range(1,9):
  for stop in range(n+1):
   occupied=[1 if j<stop else 0 for j in range(n)]
   for rep in [0,1,7,(1<<63)-1,1<<63,(1<<63)+1,cpu.U64]:
    for maplen in [0,1,cpu.U64]:add(1,2,list(range(n)),occupied,rep,maplen)
 for aux in [0,1,cpu.U64]:
  for fbits in [0,1,1<<63,0x3ff0000000000000,0x7ff0000000000000,0xfff0000000000000,0x7ff8000000000042,cpu.U64]:
   for rep,maplen in [(0,0),(1<<63,0),(1<<63,1)]:add(1,2,[1,0],[1,0],rep,maplen,aux,fbits)
 return [json.loads(s) for s in dict.fromkeys(json.dumps(r,separators=(',',':')) for r in rows)]
def corpus(im):
 inputs=[];expected=[];seen=set()
 for row in stimuli():
  result,trace=evaluate(im,row);inputs.append(json.dumps(row,separators=(',',':'))+'\n');expected.append(json.dumps(result,separators=(',',':'))+'\n');seen|=trace
 return ''.join(inputs).encode(),''.join(expected).encode(),seen
if __name__=='__main__':
 im=Image()
 try:
  if hashlib.sha256(im.data).hexdigest()!=SHA:raise ValueError('wrong target')
  for row in [[0,0,[],[],0,0,17,0],[1,2,[0,1],[1,0],0,0,17,42],[1,2,[0],[0],1<<63,0,17,42]]:print(row,evaluate(im,row)[0])
 finally:im.close()
