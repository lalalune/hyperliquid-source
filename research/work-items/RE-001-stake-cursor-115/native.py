"""Actual cursor prefix and independently fresh post-helper arithmetic point.

The C5 cleanup follows original instructions through actual CALL/RET. Other
helpers stop before invocation. Four observed columns are a qualified domain,
not a recovered bound on the original context byte or enum.
"""
from pathlib import Path
import hashlib,sys
ROOT=Path(__file__).resolve().parents[3];PACKET=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'tools'))
import decimal_scaled_u64 as cpu
from elfview import View
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
TARGET=ROOT/'artifacts/node/115/hl-node'
OBJ=cpu.INPUT;MATCH=OBJ+0x40;IDENTITY=OBJ+0x50;SELECTOR=OBJ+0x70;CONTEXT=OBJ+0x100;COLUMN=CONTEXT+0xb9a;OUT=OBJ+0x900
TABLE=0x602d1c;ROWS=[0x457d00,0x457b00,0x457f00,0x457d00]
CLEANUP=0x29ec3c0;DROP_TABLE=0x600b50;DROP_SLOT=0x600d70
RANGES=[(0x294ceb0,0x294cf34),(0x294cf39,0x294cfab),(CLEANUP,0x29ec3ec),(0x29ec55f,0x29ec567)]
PAYLOAD=bytes((37+19*i)&255 for i in range(20))
class Image:
 slots={};note_target=None;panic_targets=set()
 def __init__(self):self.view=View(TARGET);self.data=self.view.b;self.cache={}
 def read_only(self,a):
  if any(lo<=a<hi for lo,hi in [(TABLE,TABLE+16),(DROP_SLOT,DROP_SLOT+4),*[(p,p+32) for p in set(ROWS)]]):return self.data[self.view.offset(a)]
  return None
 def fetch(self,a):
  if not any(lo<=a<hi for lo,hi in RANGES):raise ValueError('stake cursor CFG escape '+hex(a))
  if a not in self.cache:self.cache[a]=cpu.decode(self.data,self.view.offset(a),a)
  return self.cache[a]
 def close(self):
  if self.data is not self.view.b:self.data.close()
  self.view.b.close();self.view.file.close()
class Machine(cpu.Machine):
 def __init__(self,im):
  super().__init__(im);self.regions=[(OBJ,OBJ+48),(MATCH,MATCH+1),(IDENTITY,IDENTITY+20),(SELECTOR,SELECTOR+1),(COLUMN,COLUMN+1),(OUT,OUT+24),(cpu.STACK-0x20,cpu.STACK+0xb0)];self.cursor_writes=0;self.out_writes=0;self.cleanup_calls=0
 def bounds(self,a,n,write=False):
  allowed=[(OBJ+0x20,OBJ+0x28),(OUT,OUT+2),self.regions[-1]] if write else self.regions+[(TABLE,TABLE+16),(DROP_SLOT,DROP_SLOT+4),*[(p,p+32) for p in set(ROWS)]]
  if not any(lo<=a and a+n<=hi for lo,hi in allowed):raise ValueError('stake cursor memory footprint')
 def load(self,a,n):self.bounds(a,n);return super().load(a,n)
 def reload(self,r,a,n):self.bounds(a,n);return super().reload(r,a,n)
 def record(self,a,n):
  if a==OBJ+0x20:
   if n!=8:raise ValueError('partial cursor store')
   self.cursor_writes+=1
  if a==OUT:
   if n!=2:raise ValueError('unexpected output store')
   self.out_writes+=1
 def store(self,a,n,v):self.bounds(a,n,True);self.record(a,n);return super().store(a,n,v)
 def spill(self,a,r,n):self.bounds(a,n,True);self.record(a,n);return super().spill(a,r,n)
 def call(self,target,where):
  if target!=CLEANUP or self.load(self.get(cpu.RDI,64),2)!=0xc5:raise ValueError('unclosed helper call forbidden')
  self.cleanup_calls+=1
  return super().call(target,where)
def evaluate(im,row):
 point,index,word,aux,mode,tag=row
 if point not in [0,1] or any(not 0<=v<=cpu.U64 for v in [index,word]) or not 0<=tag<=65535:raise ValueError('qualified stake words required')
 if (point==0 and (not 0<=aux<=255 or not 0<=mode<=255)) or (point==1 and (not 0<=index<4 or aux not in [0,1] or not 0<=mode<4)):raise ValueError('outside qualified point domain')
 m=Machine(im)
 for lo,hi in m.regions:
  for a in range(lo,hi):m.mem[a]=(91+13*(a-lo))&255
 def put(a,v,n=8):
  for i,b in enumerate(v.to_bytes(n,'little')):m.mem[a+i]=b
 for a,v in [(OBJ,MATCH),(OBJ+8,CONTEXT),(OBJ+0x10,IDENTITY),(OBJ+0x18,SELECTOR),(OBJ+0x20,index),(OBJ+0x28,word if point==0 else 0),(cpu.STACK+0xa8,cpu.RETURN_MARK)]:put(a,v)
 put(OUT,tag,2);m.mem[MATCH]=aux if point==0 else 0;m.mem[SELECTOR]=mode if point==0 else 0;m.mem[COLUMN]=mode if point==1 else 0
 for i,b in enumerate(PAYLOAD):m.mem[IDENTITY+i]=b
 before={a:v for a,v in m.mem.items() if not cpu.STACK-0x20<=a<cpu.STACK+0xb0}
 regs=[(cpu.RSP,cpu.STACK+0xa8),(cpu.RDI,OBJ),(cpu.RDX,OUT)] if point==0 else [(cpu.RSP,cpu.STACK+0x10),(cpu.RAX,word),(cpu.R12,aux),(cpu.R14,index),(cpu.R15,CONTEXT),(cpu.RBX,OUT)]
 for r,v in regs:m.set_reg(r,v)
 m.pc=0x294ceb0 if point==0 else 0x294cf39
 def unchanged():
  for a,v in before.items():
   if (point==0 and OBJ+0x20<=a<OBJ+0x28) or (point==1 and OUT<=a<OUT+2):continue
   if m.mem[a]!=v:raise ValueError('unrelated stake input modified')
 def observe(kind,tail=''):
  unchanged()
  if point==0:
   if m.out_writes:raise ValueError('entry changed output record')
   return f'E:{m.load(OBJ+0x20,8)}:{m.cursor_writes}:{m.load(OUT,2)}:{kind}'+tail
  if m.cursor_writes:raise ValueError('fresh post-helper point changed cursor')
  return f'P:{m.load(OUT,2)}:{m.out_writes}:{kind}'+tail
 for _ in range(300):
  if m.pc==0x294cf34:
   if point!=0 or m.get(cpu.RDI,64)!=index or m.get(cpu.RSI,64)!=CONTEXT or m.get(cpu.RDX,64)!=cpu.STACK+0x10:raise ValueError('helper argument footprint')
   raw=bytes(m.mem[cpu.STACK+0x10+i] for i in range(20));bonus=m.get(cpu.R12,64);selector=m.get(cpu.RCX,64)
   if bonus is None or selector is None:raise ValueError('unknown helper arguments')
   return observe('H',f':{index}:{bonus}:{selector}:'+raw.hex()),m.seen,m.cleanup_calls
  if m.pc==0x294cfab:return observe('D'),m.seen,m.cleanup_calls
  if m.pc==0x294cf96 and m.load(OUT,2)!=0xc5:return observe('X'),m.seen,m.cleanup_calls
  try:m.step()
  except cpu.Done as done:
   if done.how!='ret' or m.get(cpu.RSP,64)!=cpu.STACK+0xb0:raise ValueError('stake return drift')
   status=m.get(cpu.RAX,8)
   if point==0:
    if status!=2 or m.get(cpu.RDX,64)!=index:raise ValueError('terminal cursor return drift')
    return observe('T',':'+str(index)),m.seen,m.cleanup_calls
   if status==1:
    product=m.get(cpu.RDX,64)
    if product is None or m.cleanup_calls!=1:raise ValueError('product/actual cleanup missing')
    return observe('Y',':'+str(product)),m.seen,m.cleanup_calls
   if status==0:
    if m.get(cpu.RDX,64)!=index:raise ValueError('inactive failure register changed')
    return observe('F'),m.seen,m.cleanup_calls
   raise ValueError('unexpected stake status')
 raise ValueError('stake step bound')
def stimuli(im):
 rows=[];indices=[0,1,2,3,4,5,1<<63,cpu.U64-1,cpu.U64];offsets=[0,1,2,3,4,5,cpu.U64-5,cpu.U64-1,cpu.U64]
 for i in indices:
  for offset in offsets:
   active=i<4 and offset+i+1<5
   for byte in ([0,1,2,3,4,255] if active else [0]):
    for selector in ([0,1,255] if active else [0]):rows.append((0,i,offset,byte,selector,0x1a2))
 for i in range(4):
  for column in range(4):
   multiplier=int.from_bytes(im.view.read(ROWS[i]+column*8,8),'little');q=cpu.U64//multiplier
   for bonus in [0,1]:
    words={0,1,2,cpu.U64-1,cpu.U64}
    words.update(q+d for d in [-3,-2,-1,0,1,2,3] if 0<=q+d<=cpu.U64)
    for word in sorted(words):
     for tag in [0xc5,0x1a2,0]:rows.append((1,i,word,bonus,column,tag))
 return list(dict.fromkeys(rows))
def corpus(im):
 inputs=[];expected=[];seen=set();calls=0
 for row in stimuli(im):
  result,trace,count=evaluate(im,row);inputs.append('\t'.join(map(str,row))+'\n');expected.append(result+'\n');seen|=trace;calls+=count
 return ''.join(inputs).encode(),''.join(expected).encode(),seen,calls
if __name__=='__main__':
 im=Image()
 try:
  if hashlib.sha256(im.data).hexdigest()!=SHA:raise ValueError('wrong115target')
  a,b,c,d=corpus(im);print('PROBE',len(a.splitlines()),len(c),'actual_cleanup_calls',d)
 finally:im.close()
