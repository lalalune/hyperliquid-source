from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[3];sys.path.insert(0,str(ROOT/'tools'))
PACKET=Path(__file__).resolve().parent
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
TARGET=ROOT/'artifacts/node/115/hl-node'
import decimal_scaled_u64 as cpu
from elfview import View
SITES=[0x2d1d600,0x5185200,0x5185480]
class Image:
 def __init__(self):
  self.view=View(TARGET);self.data=self.view.b;self.text_va,self.text_off,self.text_size=self.view.sections['.text'];self.rodata=self.view.sections['.rodata'];self.slots={};self.cache={}
 def fetch(self,va):
  if va not in self.cache:self.cache[va]=cpu.decode(self.data,self.view.offset(va),va)
  return self.cache[va]
 def read_only(self,va):return self.view.read(va,1)[0]
class Machine(cpu.Machine):
 def address_bounds(self,at,n,write=False):
  allow=[(cpu.INPUT+0x20,16),(cpu.STACK+0x30,16),(cpu.STACK+0x50,1)]
  if not any(a<=at and at+n<=a+size for a,size in allow):raise ValueError('outside bounded footprint')
 def load(self,at,n):self.address_bounds(at,n);return super().load(at,n)
 def store(self,at,n,value):self.address_bounds(at,n,True);return super().store(at,n,value)
 def call(self,*args):raise ValueError('helper calls excluded')
def evaluate(image,which,raw,divisor,previous):
 if not all(type(x) is int and 0<=x<=cpu.U64 for x in (raw,divisor,previous)):raise ValueError('raw u64 inputs required')
 a=SITES[which];m=Machine(image);m.set_reg(cpu.RCX,raw);m.set_reg(cpu.R12,cpu.INPUT);m.set_reg(cpu.RSP,cpu.STACK)
 m.store(cpu.INPUT+0x20,8,divisor);m.store(cpu.INPUT+0x28,8,previous);m.pc=a+0x198;bucket=None
 for _ in range(40):
  if m.pc in (a+0x1b4,a+0x222):
   insn=image.fetch(m.pc)
   if insn.key!=0xf7 or (image.data[insn.modrm]>>3)&7!=6 or insn.wide16:raise ValueError('unexpected divide boundary')
   width=64 if insn.rex&8 else 32
   if m.read(m.operand(insn),width)==0:
    # Actual decoded divisor, not the supplied parameter: stop BEFORE DIV0.
    return ('Z',width),m.seen
  if m.pc==a+0x1c6:bucket=m.get(cpu.RAX,64)
  if m.pc==a+0x1e3:
   if bucket is None:raise ValueError('quotient not observed')
   return (bucket,m.load(cpu.INPUT+0x28,8),m.load(cpu.STACK+0x50,1),32 if a+0x222 in m.seen else 64),m.seen
  if not (a+0x198<=m.pc<a+0x1e3 or a+0x220<=m.pc<=a+0x22e):raise ValueError(f'escaped {m.pc:#x}')
  m.step()
 raise ValueError('step bound')
def select(image,which,bypass,raw,divisor,previous):
 if type(bypass) is not int or not 0<=bypass<256:raise ValueError('raw bypass byte required')
 if not all(type(x) is int and 0<=x<=cpu.U64 for x in (raw,divisor,previous)):raise ValueError('raw u64 inputs required')
 a=SITES[which];m=Machine(image);m.set_reg(cpu.RBP,bypass);m.pc=a+0xdb
 for _ in range(4):
  if m.pc==a+0xe0:return ('D',),m.seen
  if m.pc==a+0xf6:
   # Fresh post-calendar-conversion boundary: no conversion/helper is stubbed.
   result,seen=evaluate(image,which,raw,divisor,previous)
   return (result if result[0]=='Z' else ('T',*result)),m.seen|seen
  if not a+0xdb<=m.pc<a+0xe0:raise ValueError('bypass gate escaped')
  m.step()
 raise ValueError('bypass gate budget')


def stimuli():
 raws=sorted({0,1,2,59,60,61,999,1000,1001,cpu.U64}|{(1<<32)+j for j in range(-3,4)}|{(1<<63)+j for j in range(-3,4)}|{cpu.U64-j for j in range(4)})
 divisors=sorted({0,1,2,59,60,1000,cpu.U64}|{(1<<32)+j for j in range(-2,3)}|{(1<<63)+j for j in range(-1,2)})
 cases=set()
 for raw in raws:
  for d in divisors:
   old_values={0,1,2,1<<63,cpu.U64}
   if d:
    q=(raw if raw<1<<63 else 0)//d;old_values|={q,max(0,q-1),min(cpu.U64,q+1)}
   for old in old_values:cases.add((raw,d,old))
 state=0x115b0c
 for _ in range(512):
  values=[]
  for _ in range(3):state=(state*6364136223846793005+1442695040888963407)&cpu.U64;values.append(state)
  cases.add(tuple(values))
 ordered=sorted(cases)
 bypass_cases=ordered[::max(1,len(ordered)//32)]
 return [(which,flag,*args) for which in range(3) for flag,args in [(0,x) for x in ordered]+[(flag,x) for flag in [1,2,127,128,254,255] for x in bypass_cases]]

def corpus(image):
 inputs=[];full=[];semantic=[];seen=set()
 for which,flag,raw,d,old in stimuli():
  result,trace=select(image,which,flag,raw,d,old);seen|=trace
  inputs.append(f'{which}\t{flag}\t{raw}\t{d}\t{old}\n');full.append('\t'.join(map(str,result))+'\n');semantic.append('\t'.join(map(str,result[:4] if result[0]=='T' else result[:1]))+'\n')
 return ''.join(inputs).encode(),''.join(full).encode(),''.join(semantic).encode(),seen

def verify():
 import hashlib,json
 image=Image();record=json.loads((PACKET/'FREEZE.json').read_text())
 if hashlib.sha256(image.data).hexdigest()!=SHA or record['target_sha256']!=SHA:raise ValueError('node115 identity mismatch')
 inputs,full,semantic,seen=corpus(image)
 for raw,key in [(inputs,'input_sha256'),(full,'expected_sha256'),(semantic,'semantic_projection_sha256')]:
  if hashlib.sha256(raw).hexdigest()!=record[key]:raise ValueError('frozen native stream changed')
 if len(inputs.splitlines())!=record['rows'] or sorted(seen)!=record['visited_addresses']:raise ValueError('native denominator changed')
 return inputs,semantic
