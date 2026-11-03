"""Small discovery probe only; unknown registers/lanes fail closed."""
from pathlib import Path
import sys,math,struct
ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'tools'));sys.path.insert(0,str(ROOT.parent))
import gas_auction_price as cpu
from elfview import View
U64=(1<<64)-1;U128=(1<<128)-1
OUT=cpu.HEAP_BASE;FIELDS=cpu.HEAP_BASE+64
class Image:
 def __init__(self):
  self.view=View(ROOT/'artifacts/node/115/hl-node');self.blob=self.view.b;self.offset=self.view.offset;self.named={k:{'address':a,'offset':o,'size':n} for k,(a,o,n) in self.view.sections.items()}
class Memory(cpu.Memory):
 def permitted(self,a,n,write=False):
  if OUT<=a and a+n<=OUT+16:return
  if not write and FIELDS<=a and a+n<=FIELDS+64:return
  s=self.image.named['.rodata']
  if not write and s['address']<=a and a+n<=s['address']+s['size']:return
  raise ValueError(f'outside selected data footprint {a:#x}/{n}/{write}')
 def bytes_at(self,a,n):self.permitted(a,n);return super().bytes_at(a,n)
 def write(self,a,n,v):self.permitted(a,n,True);return super().write(a,n,v)
class Machine(cpu.Machine):
 def __init__(self,image):
  super().__init__(image);self.memory=Memory(image);self.gknown=[0]*16;self.xknown=[0]*16
  self.regs=[cpu.POISON]*16;self.cf=self.zf=self.of=self.sf=self.pf=None
 def set_reg(self,r,v):self.regs[r]=v;self.gknown[r]=U64
 def address(self,o):
  if o[1] is not None and self.gknown[o[1]]!=U64:raise ValueError('unknown address base')
  if o[2] is not None and self.gknown[o[2]]!=U64:raise ValueError('unknown address index')
  return super().address(o)
 def get(self,o,w):
  if o[0]=='r' and self.gknown[o[1]]&cpu.MASK[w]!=cpu.MASK[w]:raise ValueError('unknown GPR read')
  return super().get(o,w)
 def put(self,o,w,v):
  super().put(o,w,v)
  if o[0]=='r':self.gknown[o[1]]=U64 if w>=4 else self.gknown[o[1]]|cpu.MASK[w]
 def low(self,o):
  if o[0]=='x' and self.xknown[o[1]]&U64!=U64:raise ValueError('unknown low lane')
  return super().low(o)
 def vector(self,o):
  if o[0]=='x' and self.xknown[o[1]]!=U128:raise ValueError('unknown packed lane')
  return super().vector(o)
 def set_low(self,r,v):super().set_low(r,v);self.xknown[r]|=U64
 def condition(self,c):
  deps={0:[self.of],1:[self.cf],2:[self.zf],3:[self.cf,self.zf],4:[self.sf],5:[self.pf],6:[self.sf,self.of],7:[self.zf,self.sf,self.of]}[c>>1]
  if any(x is None for x in deps):raise ValueError('unknown condition flags')
  return super().condition(c)
 def step(self,row):
  op=row.op
  if op=='xor' and row.a==row.b:
   self.put(row.a,row.width,0);self.set_logic(0,row.width);return row.next
  if op=='xorps' and row.a==row.b:
   self.xmm[row.a[1]]=0;self.xknown[row.a[1]]=U128;return row.next
  if op=='movx' and row.a[0]=='x' and row.b[0]=='x':
   self.xmm[row.a[1]]=self.xmm[row.b[1]];self.xknown[row.a[1]]=self.xknown[row.b[1]];return row.next
  if op=='movq' and row.b[0]=='x':self.low(row.b)
  if op=='punpckldq':self.low(row.a)
  if op in ('subpd','unpckhpd'):self.vector(row.a)
  if op in ('call','calli','ret'):raise ValueError('calls/returns excluded')
  result=super().step(row)
  if op in ('movq','movx','punpckldq','subpd','unpckhpd') and row.a[0]=='x':self.xknown[row.a[1]]=U128
  if op in ('sar','shr','shl'):self.of=None  # selected multi-bit shifts: OF must remain unusable
  return result

def evaluate(image,bits,bucket,start,floor,patch=None):
 m=Machine(image);m.patches=patch or {};m.set_reg(cpu.RBX,OUT);m.set_reg(cpu.R15,FIELDS);m.set_reg(cpu.R14,FIELDS+16)
 m.xmm[0]=bits|(cpu.POISON<<64);m.xknown[0]=U64
 for off,value in [(16,bucket),(40,start),(56,floor)]:cpu.Memory.write(m.memory,FIELDS+off,8,value)
 cpu.Memory.put_bytes(m.memory,OUT,b'\xa5'*16)
 pc=0x3be586d;seen=set()
 for _ in range(150):
  if pc==0x3be57ad:
   tag=m.memory.read(OUT,2)
   if tag==0xc4:return 'E',seen
   if tag==0x1a2:return 'O\t'+str(m.memory.read(OUT+8,8)),seen
   raise ValueError('unexpected result tag')
  if not (0x3be586d<=pc<0x3be59f9 or pc==0x3be57aa):raise ValueError('escaped suffix')
  row=cpu.decode(m.read_code,pc);seen.add(pc);pc=m.step(row)
 raise ValueError('step bound')

def model(bits,bucket,start,floor):
 if start<floor:return 'E'
 def sat(x):return 0 if not math.isfinite(x) or x<=0 else U64 if x>=2**64 else int(x)
 elapsed=sat(cpu.to_float(bits));raw=1.0-cpu.fdiv(float(elapsed),float(bucket));factor=raw if raw>0 else 0.0
 value=sat(factor*float(start-floor))+floor
 return 'O\t'+str(value if value<=U64 else floor)

def stimuli():
 bits={0,1,1<<63,(1<<63)+1,0x7fefffffffffffff,0xffefffffffffffff,0x7ff0000000000000,0xfff0000000000000,0x7ff8000000000001,0xfff8000000000042}
 for x in [0.5,1.0,999.0,15000.0,59999.0,60000.0,60001.0,float(1<<53),float(1<<63),float(1<<64)]:
  word=cpu.to_bits(x);bits.update(word+d for d in [-2,-1,0,1,2])
 buckets=[0,1,2,1000,60000,(1<<32)-1,1<<32,(1<<53)+3,1<<63,U64]
 pairs=[(0,0),(1,0),(1,1),(99,100),(100,100),(1000,100),((1<<53)+1,0),((1<<53)+3,0),(U64,0),(U64,1),(U64,2048),(U64,U64-1000),(1<<63,1<<40)]
 stimuli=list((b,k,s,f) for b in sorted(bits) for k in buckets for s,f in pairs);state=0x115ac710
 for _ in range(512):
  values=[]
  for _ in range(4):state=(state*6364136223846793005+1442695040888963407)&U64;values.append(state)
  b,k,s,f=values
  if b&0x7ff0000000000000==0x7ff0000000000000:b|=1<<51
  stimuli.append((b,k,s,f))
 return sorted(set(stimuli))


def corpus(image):
 inputs=[];outputs=[];seen=set()
 for b,k,s,f in stimuli():
  actual,trace=evaluate(image,b,k,s,f);seen|=trace
  inputs.append(f'{b}\t{k}\t{s}\t{f}\n');outputs.append(actual+'\n')
 return ''.join(inputs).encode(),''.join(outputs).encode(),seen

def verify():
 import hashlib,json
 image=Image();record=json.loads((Path(__file__).resolve().parent/'FREEZE.json').read_text())
 if hashlib.sha256(image.blob).hexdigest()!=record['target_sha256']:raise ValueError('node115 identity mismatch')
 inputs,expected,seen=corpus(image)
 if hashlib.sha256(inputs).hexdigest()!=record['input_sha256'] or hashlib.sha256(expected).hexdigest()!=record['expected_sha256'] or sorted(seen)!=record['visited_addresses']:raise ValueError('frozen native corpus changed')
 return inputs,expected
