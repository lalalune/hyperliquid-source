"""Complete actual SIMD compaction leaf; compare full old-length backing tail."""
from pathlib import Path
import hashlib,itertools,json,sys
ROOT=Path(__file__).resolve().parents[3];PACKET=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'tools'))
import decimal_scaled_u64 as cpu
from elfview import View
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
TARGET=ROOT/'artifacts/node/115/hl-node';OWNER=(0x5b2d510,0x5b2d648)
OBJ=cpu.INPUT;BUFFER=OBJ+0x1003;SP=cpu.STACK
class Image:
 slots={};note_target=None;panic_targets=set()
 def __init__(self):self.view=View(TARGET);self.data=self.view.b;self.cache={}
 def read_only(self,a):return None
 def fetch(self,a):
  if not OWNER[0]<=a<OWNER[1]:raise ValueError('adjacent leaf CFG escape')
  if a not in self.cache:self.cache[a]=cpu.decode(self.data,self.view.offset(a),a)
  return self.cache[a]
 def close(self):
  if self.data is not self.view.b:self.data.close()
  self.view.b.close();self.view.file.close()
class Machine(cpu.Machine):
 def __init__(self,im,n):
  super().__init__(im);self.regions=[(OBJ,OBJ+24),(BUFFER,BUFFER+n*32),(SP,SP+8)];self.writes=set();self.reads=set();self.record=False
 def bounds(self,a,n):
  if not any(lo<=a and a+n<=hi for lo,hi in self.regions):raise ValueError('adjacent footprint '+hex(a))
 def load(self,a,n):
  self.bounds(a,n)
  if self.record:self.reads.update(range(a,a+n))
  return super().load(a,n)
 def reload(self,r,a,n):
  self.bounds(a,n)
  if self.record:self.reads.update(range(a,a+n))
  return super().reload(r,a,n)
 def store(self,a,n,v):
  self.bounds(a,n)
  if self.record:self.writes.update(range(a,a+n))
  return super().store(a,n,v)
 def spill(self,a,r,n):
  self.bounds(a,n)
  if self.record:self.writes.update(range(a,a+n))
  return super().spill(a,r,n)
 def call(self,*args):raise ValueError('call in call-free adjacent leaf')
 def two_byte(self,ins,key,bits,rexr,here):
  if key in [(0x0f,0x6e),(0x0f,0x74),(0x0f,0xdb),(0x0f,0xd7)]:
   if not ins.wide16 or ins.rex&8:raise ValueError('unqualified SIMD width')
   reg=((self.image.data[ins.modrm]>>3)&7)|rexr;operand=self.operand(ins)
   if key[1]==0x6e:
    value=self.read(operand,32)
    if value is None:raise ValueError('unknown MOVD input')
    self.xmm[reg]=value.to_bytes(4,'little')+bytes(12);return
   if operand[0]!='r':raise ValueError('unqualified SIMD memory form')
   value=self.xmm[operand[1]]
   if value is None:raise ValueError('unknown SIMD source')
   if key[1]==0xd7:
    self.put(reg,32,sum((b>>7)<<i for i,b in enumerate(value)));return
   previous=self.xmm[reg]
   if previous is None:raise ValueError('unknown SIMD destination')
   if key[1]==0x74:self.xmm[reg]=bytes(255 if a==b else 0 for a,b in zip(previous,value))
   else:self.xmm[reg]=bytes(a&b for a,b in zip(previous,value))
   return
  return super().two_byte(ins,key,bits,rexr,here)
def evaluate(im,hexdata):
 raw=bytes.fromhex(hexdata)
 if len(raw)%32 or len(raw)>32*32:raise ValueError('bounded complete32-byte records required')
 n=len(raw)//32;m=Machine(im,n);m.store(OBJ+8,8,BUFFER);m.store(OBJ+16,8,n);m.store(SP,8,cpu.RETURN_MARK)
 for i,b in enumerate(raw):m.mem[BUFFER+i]=b
 m.set_reg(cpu.RDI,OBJ);m.set_reg(cpu.RSP,SP);m.record=True
 try:m.run(OWNER[0])
 except cpu.Done:
  if m.pc not in [0x5b2d57e,0x5b2d648] or m.get(cpu.RSP,64)!=SP+8:raise ValueError('not genuine adjacent RET')
 m.record=False
 length=m.load(OBJ+16,8)
 if length is None or m.load(OBJ+8,8)!=BUFFER:raise ValueError('unknown length or changed buffer pointer')
 after=bytes(m.mem[BUFFER+i] for i in range(len(raw)))
 if not m.writes <= set(range(BUFFER,BUFFER+len(raw)))|set(range(OBJ+16,OBJ+24)):raise ValueError('unexpected adjacent store')
 if n<2 and (m.writes or set(range(OBJ+8,OBJ+16))&m.reads):raise ValueError('short leaf read pointer or wrote state')
 return [length,after.hex()],m.seen,m.writes
def records(keys,seed=0):
 out=[]
 for i,key in enumerate(keys):
  leading=bytes((key*47+j*13)%256 for j in range(20));payload=bytes((seed+i*29+j*7)%256 for j in range(12));out.append(leading+payload)
 return b''.join(out)
def stimuli():
 rows=[]
 for size in range(8):
  for keys in itertools.product(range(3),repeat=size):rows.append(records(keys).hex())
 for keys in [[0]*32,list(range(32)),[i//2 for i in range(32)],[i%3 for i in range(32)],[0,0,1,2,2,3,0,0],[0,1,2,2],[0,0,1,2],[0,1,0],[0,0,0]]:
  for seed in [0,7,255]:rows.append(records(keys,seed).hex())
 base=records([1,1])
 for at in range(32):
  for bit in [1,0x80]:
   raw=bytearray(base);raw[32+at]^=bit;rows.append(raw.hex())
 for size in [2,3,4,7,16,32]:
  raw=bytes([0xa5])*(size*32);rows.append(raw.hex())
 return list(dict.fromkeys(rows))
def corpus(im):
 inputs=[];expected=[];seen=set();write_rows=0
 for row in stimuli():
  result,trace,writes=evaluate(im,row);inputs.append(row+'\n');expected.append(json.dumps(result,separators=(',',':'))+'\n');seen|=trace;write_rows+=bool(writes)
 return ''.join(inputs).encode(),''.join(expected).encode(),seen,write_rows
if __name__=='__main__':
 im=Image()
 try:
  if hashlib.sha256(im.data).hexdigest()!=SHA:raise ValueError('wrong target')
  for keys in [[],[1],[1,1],[1,1,2,3,3],[1,2,1]]:
   result,_,writes=evaluate(im,records(keys).hex());print(keys,result[0],len(writes))
 finally:im.close()
