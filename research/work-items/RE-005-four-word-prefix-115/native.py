"""Private decoder and its actual scalar/slow/error CALL/RET graph.

Canonical mode 0/1, little endian, disjoint valid bounded objects only.
This is an offline instruction evaluator, never a captured executable.
"""
from pathlib import Path
import hashlib, json, struct, sys
ROOT=Path(__file__).resolve().parents[3]; PACKET=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'tools'))
import decimal_scaled_u64 as cpu
from elfview import View
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
TARGET=ROOT/'artifacts/node/115/hl-node'
RANGES=[(0x2ce1730,0x2ce198a),(0x2cd7ac0,0x2cd7ba5),(0x58225c0,0x58226fc),(0x5822700,0x582270e)]
TABLES=[(0x60be8c,16),(0x935c24,16)]
STATE=cpu.INPUT; DATA=STATE+0x1000; OUT=STATE+0x2000; STACK=cpu.STACK
SP=STACK+0x88
class Image:
 note_target=None; panic_targets=set()
 def __init__(self):
  self.view=View(TARGET); self.data=self.view.b; self.cache={}; self.slots={}
  _,off,n=self.view.sections['.rela.dyn']
  for p in range(off,off+n,24):
   slot,kind,add=struct.unpack_from('<QQq',self.data,p)
   if slot in [0x64e6c38,0x64e6c40,0x64e7f78]:
    if kind!=8:raise ValueError('non RELATIVE helper')
    self.slots[slot]=add
  if self.slots!={0x64e6c38:0x58225c0,0x64e6c40:0x5822700,0x64e7f78:0x5822700}:raise ValueError('changed bindings')
 def fetch(self,a):
  if not any(lo<=a<hi for lo,hi in RANGES):raise ValueError('decoder CFG escape '+hex(a))
  if a not in self.cache:self.cache[a]=cpu.decode(self.data,self.view.offset(a),a)
  return self.cache[a]
 def read_only(self,a):
  if any(lo<=a<lo+n for lo,n in TABLES):return self.data[self.view.offset(a)]
  return None
 def close(self):
  if self.data is not self.view.b:self.data.close()
  self.view.b.close(); self.view.file.close()
class Machine(cpu.Machine):
 def __init__(self,im,n):
  super().__init__(im);self.regions=[(STATE,STATE+40),(DATA,DATA+n),(OUT,OUT+48),(STACK-0x200,SP+8)];self.calls=[]
 def bounds(self,a,n):
  if not any(lo<=a and a+n<=hi for lo,hi in self.regions) and not any(lo<=a and a+n<=lo+size for lo,size in TABLES):raise ValueError('decoder footprint '+hex(a))
 def load(self,a,n):self.bounds(a,n);return super().load(a,n)
 def reload(self,r,a,n):self.bounds(a,n);return super().reload(r,a,n)
 def store(self,a,n,v):
  self.bounds(a,n)
  if DATA<=a<DATA+0x1000:raise ValueError('input write')
  return super().store(a,n,v)
 def spill(self,a,r,n):self.bounds(a,n);return super().spill(a,r,n)
 def call(self,target,where):
  if target not in [0x2cd7ac0,0x58225c0,0x5822700]:raise ValueError('uncertified call')
  self.calls.append((where,target));return super().call(target,where)
 def step(self):
  ins=self.image.fetch(self.pc)
  if ins.key==0x89 and ins.wide16:
   operand=self.operand(ins)
   if operand[0]!='m':raise ValueError('unexpected narrow MOV')
   self.seen.add(self.pc);self.pc+=ins.size
   reg=((self.image.data[ins.modrm]>>3)&7)|((ins.rex&4)<<1)
   self.spill(self.address(operand),reg,2);return
  return super().step()
 def two_byte(self,insn,key,bits,rexr,here):
  if key in [(0x0f,0xb6),(0x0f,0xb7)]:
   operand=self.operand(insn)
   if operand[0]=='m':
    reg=((self.image.data[insn.modrm]>>3)&7)|rexr
    self.reload(reg,self.address(operand),1 if key[1]==0xb6 else 2);return
  if len(key)==2 and 0xc8<=key[1]<=0xcf:
   reg=(key[1]&7)|((insn.rex&1)<<3);value=self.get(reg,bits)
   if value is None:raise ValueError('BSWAP unknown value')
   self.put(reg,bits,int.from_bytes(value.to_bytes(bits//8,'little'),'big'))
   return
  # Existing helper drops all 16 bytes when one half is unknown. Actual
  # MOVUPS copies every byte, including known active fields beside padding.
  # Keep a per-byte unknown mask locally; do not initialize inactive padding.
  if key in [(0x0f,0x10),(0x0f,0x11)]:
   reg=((self.image.data[insn.modrm]>>3)&7)|rexr;operand=self.operand(insn)
   if operand[0]!='m':raise ValueError('unexpected MOVUPS register form')
   a=self.address(operand);self.bounds(a,16)
   if key[1]==0x10:self.xmm[reg]=[self.load(a+i,1) for i in range(16)]
   else:
    if self.xmm[reg] is None:raise ValueError('undefined SIMD register')
    for i,v in enumerate(self.xmm[reg]):self.store(a+i,1,v)
   return
  return super().two_byte(insn,key,bits,rexr,here)
 def shift(self,kind,value,count,width):
  if kind==0 and width==16 and count==8:
   # Actual slow-reader ROL CX,8. Its following TEST overwrites flags;
   # CF is the resulting low bit, OF is undefined for this count.
   if value is None:raise ValueError('rotate of unknown value')
   result=((value<<8)|(value>>8))&0xffff
   self.flags[0]=bool(result&1);self.flags[3]=None
   return result
  return super().shift(kind,value,count,width)
def evaluate(im,row):
 raw,limit,charged=row; raw=bytes.fromhex(raw)
 if len(raw)>128 or not 0<=charged<=cpu.U64 or limit is not None and not 0<=limit<=cpu.U64:raise ValueError('invalid premise')
 m=Machine(im,len(raw))
 for a,v in [(STATE,int(limit is not None)),(STATE+8,limit or 0),(STATE+16,DATA),(STATE+24,len(raw)),(STATE+32,charged),(SP,cpu.RETURN_MARK)]:m.store(a,8,v)
 for i,b in enumerate(raw):m.mem[DATA+i]=b
 # Output canary is caller-owned storage, not native initialization. Stack
 # starts unknown; only logical active fields may be projected.
 for i in range(48):m.mem[OUT+i]=0xa5
 m.set_reg(cpu.RSP,SP);m.set_reg(cpu.RDI,OUT);m.set_reg(cpu.RSI,STATE)
 try:m.run(RANGES[0][0])
 except cpu.Done as stop:
  if m.pc!=0x2ce198a or m.get(cpu.RSP,64)!=SP+8 or m.get(cpu.RAX,64)!=OUT:raise ValueError('not genuine outer RET') from stop
 head=m.load(OUT,8)
 if head in [0,1]:
  fields=[m.load(OUT+i,8) for i in [16,24,32,40]];tail=m.load(OUT+8,8) if head else None
  if None in fields or head and tail is None:raise ValueError('unknown active success')
  result=['ok',fields,tail]
 elif head==2:
  tag=m.load(OUT+8,1)
  if tag==0:result=['end',m.load(OUT+16,8)]
  elif tag==2:result=['limit']
  elif tag==3:result=['invalid',m.load(OUT+9,1),m.load(OUT+10,1)]
  elif tag==5:result=['mode',m.load(OUT+9,1)]
  else:raise ValueError('unknown active error '+str(tag))
  if m.load(OUT+40,8)!=0xa5a5a5a5a5a5a5a5:raise ValueError('failure changed inactive fourth slot')
 else:raise ValueError('unknown outer discriminant')
 pos=m.load(STATE+16,8)-DATA;remaining=m.load(STATE+24,8);count=m.load(STATE+32,8)
 if not 0<=pos<=len(raw) or pos+remaining!=len(raw) or any(m.mem.get(DATA+i)!=b for i,b in enumerate(raw)):raise ValueError('cursor/input invariant')
 if any(v is None for v in result[1:]):
  if result[0]!='ok':raise ValueError('unknown active error '+repr((row,result)))
 return [result,pos,count],m.seen,m.calls
def enc(v,width=0):
 if not width and v<251:return bytes([v])
 width=width or (2 if v<1<<16 else 4 if v<1<<32 else 8)
 return bytes([{2:251,4:252,8:253}[width]])+v.to_bytes(width,'little')
def stimuli():
 cases=[]
 def add(raw,limit=None,count=0):cases.append((raw.hex(),limit,count))
 base=b''.join(enc(v) for v in [17,29,43,61])
 # Every truncation and marker at every one of five read positions; suffix
 # length crosses both fast/slow boundaries. Both option modes are retained.
 for pos in range(5):
  prefix=base[:pos] if pos<4 else base+b'\x01'
  for marker in [0,1,17,250,251,252,253,254,255]:
   for n in range(12):
    suffix=bytes([marker])+bytes((i*37+5)%256 for i in range(n))
    for limit in [None,0,8*pos,8*pos+8,33,41]:add(prefix+suffix,limit)
 for mode in [0,1,2,5,254,255]:
  raw=base+bytes([mode])+enc(cpu.U64,8)+b'\x89\xab'
  for n in range(len(raw)+1):
   for limit in [None,7,8,15,16,24,31,32,33,40,41,cpu.U64]:add(raw[:n],limit)
 for count in [1,7,cpu.U64-41,cpu.U64-40,cpu.U64-33,cpu.U64-32,cpu.U64-31,cpu.U64-8,cpu.U64-7,cpu.U64]:
  for mode in [0,1,2]:
   for limit in [None,0,32,33,41,cpu.U64]:add(base+bytes([mode])+enc(73),limit,count)
 for values in [[0]*4,[250,251,65536,cpu.U64],[cpu.U64]*4,[1,2,3,4]]:
  for width in [0,2,4,8]:
   if width and any(v>=1<<(width*8) for v in values):continue
   prefix=b''.join(enc(v,width) for v in values)
   for tail in [b'\x00',b'\x01'+enc(cpu.U64),b'\x02']:
    for extra in [b'',b'\x7a'*12]:add(prefix+tail+extra)
 return list(dict.fromkeys(cases))
def corpus(im):
 inputs=[];expected=[];seen=set();calls=set()
 for row in stimuli():
  result,trace,edges=evaluate(im,row);inputs.append(json.dumps(row,separators=(',',':'))+'\n');expected.append(json.dumps(result,separators=(',',':'))+'\n');seen|=trace;calls.update(edges)
 return ''.join(inputs).encode(),''.join(expected).encode(),seen,calls
if __name__=='__main__':
 im=Image()
 try:
  if hashlib.sha256(im.data).hexdigest()!=SHA:raise ValueError('wrong target')
  for row in [(b'\x11\x1d\x2b\x3d\x00'.hex(),None,0),(b'\x11\x1d\x2b\x3d\x01\x49'.hex(),8,0),('fb',None,0)]:print(row,evaluate(im,row)[0])
 finally:im.close()
