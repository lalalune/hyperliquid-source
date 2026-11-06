"""Actual unqualified symbol lane, stopping BEFORE allocator invocation.

Fresh lane selection/frame are premises. No split/metadata/helper result is
supplied, no original helper is called and no complete resolution is claimed.
"""
from pathlib import Path
import hashlib,json,sys
ROOT=Path(__file__).resolve().parents[3];PACKET=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'tools'))
import decimal_scaled_u64 as cpu
from elfview import View
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
TARGET=ROOT/'artifacts/node/115/hl-node'
ENTRY=0x46dbd05;FRONTIER=0x46dbf19;TABLE=0x46ea12
# Exclude cleanup and the unreachable empty-after-sign block. The public
# certificate separately records selected starts not visited by this corpus.
RANGES=[(ENTRY,0x46dbd4d),(0x46dbd5b,0x46dbee4),(0x46dbeee,FRONTIER)]
class Image:
 slots={};note_target=None;panic_targets=set()
 def __init__(self):self.view=View(TARGET);self.data=self.view.b;self.cache={}
 def read_only(self,a):
  if TABLE<=a<TABLE+200:return self.data[self.view.offset(a)]
  return None
 def fetch(self,a):
  if not any(lo<=a<hi for lo,hi in RANGES):raise ValueError('symbol prefix CFG escape '+hex(a))
  if a not in self.cache:self.cache[a]=cpu.decode(self.data,self.view.offset(a),a)
  return self.cache[a]
 def close(self):
  if self.data is not self.view.b:self.data.close()
  self.view.b.close();self.view.file.close()
class Machine(cpu.Machine):
 def __init__(self,im,length):
  super().__init__(im);self.regions=[(cpu.INPUT,cpu.INPUT+length),(cpu.STACK,cpu.STACK+0x150)]
 def bounds(self,a,n,write=False):
  allowed=self.regions[1:] if write else self.regions+[(TABLE,TABLE+200)]
  if not any(lo<=a and a+n<=hi for lo,hi in allowed):raise ValueError('symbol prefix memory footprint')
 def load(self,a,n):self.bounds(a,n);return super().load(a,n)
 def reload(self,r,a,n):self.bounds(a,n);return super().reload(r,a,n)
 def store(self,a,n,v):self.bounds(a,n,True);return super().store(a,n,v)
 def spill(self,a,r,n):self.bounds(a,n,True);return super().spill(a,r,n)
 def call(self,*a):raise ValueError('symbol helper calls forbidden')
 def step(self):
  ins=self.image.fetch(self.pc)
  if ins.key not in [(0x0f,0x6e),(0x0f,0x7e),(0x0f,0xc4)]:return super().step()
  if not ins.wide16 or ins.rep or ins.rex&8:raise ValueError('unsupported scalar SSE form')
  self.seen.add(self.pc);self.steps+=1;self.pc+=ins.size
  reg=((self.image.data[ins.modrm]>>3)&7)|((ins.rex&4)<<1);operand=self.operand(ins)
  if ins.key==(0x0f,0x6e):
   value=self.read(operand,32)
   if value is None:raise ValueError('MOVD unknown source')
   self.xmm[reg]=value.to_bytes(4,'little')+bytes(12)
  elif ins.key==(0x0f,0x7e):
   if self.xmm[reg] is None:raise ValueError('MOVD unknown vector')
   self.write(operand,32,int.from_bytes(self.xmm[reg][:4],'little'))
  else:
   value=self.read(operand,16);old=self.xmm[reg]
   if value is None or old is None:raise ValueError('PINSRW unknown operand')
   lane=self.image.data[ins.off+ins.size-1]&7;value=value.to_bytes(2,'little')
   self.xmm[reg]=old[:2*lane]+value+old[2*lane+2:]
def evaluate(im,raw):
 if not isinstance(raw,bytes) or len(raw)>256:raise ValueError('synthetic input bytes length0..256 required')
 m=Machine(im,len(raw));m.pc=ENTRY
 for i,b in enumerate(raw):m.mem[cpu.INPUT+i]=b
 for i in range(0x150):m.mem[cpu.STACK+i]=(73+11*i)&255
 for i,b in enumerate(cpu.RETURN_MARK.to_bytes(8,'little')):m.mem[cpu.STACK+0x148+i]=b
 for reg,value in [(cpu.R14,cpu.INPUT),(cpu.R15,len(raw)),(cpu.RSP,cpu.STACK)]:m.set_reg(reg,value)
 for _ in range(20000):
  if m.pc==FRONTIER:
   value=m.get(cpu.R15,64);length=m.get(cpu.R13,64);index=m.get(cpu.RBX,64)
   if None in [value,length,index] or not 1<=length<=20 or index!=20-length:raise ValueError('invalid canonical stack range')
   canonical=bytes(m.mem[cpu.STACK+index+0x10+i] for i in range(length))
   if bytes(m.mem[cpu.INPUT+i] for i in range(len(raw)))!=raw:raise ValueError('input modified')
   return 'A:'+str(value)+':'+canonical.hex(),m.seen
  try:m.step()
  except cpu.Done as done:
   if done.how!='ret' or m.get(cpu.RSP,64)!=cpu.STACK+0x150:raise ValueError('symbol return drift')
   tag=m.get(cpu.RAX,64)
   if bytes(m.mem[cpu.INPUT+i] for i in range(len(raw)))!=raw:raise ValueError('input modified')
   if tag==0:return 'R',m.seen
   if tag==1 and m.get(cpu.RDX,64) in [0,1]:return 'D:'+str(m.get(cpu.RDX,64)),m.seen
   raise ValueError('unexpected symbol return')
 raise ValueError('symbol step bound')
def stimuli():
 rows=[b'',b'USDC',b'PURR',b'usdc',b'purR',b'ABCD',b'outcomeToken']
 for length in [0,1,2,3,4,5,11,12,13,16,17,18,19,20,21,24,64,128,244]:rows.append(b'x'*length)
 values=set(range(180))|{cpu.U64-d for d in range(24)}
 for k in range(1,20):values.update(10**k+d for d in [-2,-1,0,1,2] if 0<=10**k+d<=cpu.U64)
 for n in sorted(values):
  digits=str(n).encode()
  rows.extend(b'outcomeToken'+prefix+digits for prefix in [b'',b'+',b'0',b'00',b'+00',b'-'])
 for suffix in [b'',b'+',b'-',b'++1',b'+-1',b'-0',b'1 ',b' 1',b'1.0',b'1e1',b'\x00',b'18446744073709551616',b'18446744073709551619',b'99999999999999999999',b'0'*200,b'0'*199+b'1',b'0'*200+str(cpu.U64).encode(),b'0'*200+b'18446744073709551616',b'+'+b'0'*200+b'1']:
  rows.append(b'outcomeToken'+suffix)
 for pos in [0,1,8,11,12,13,27,28,30]:
  base=bytearray(b'outcomeToken1234567890123456789')
  for b in range(256):
   if pos<len(base):changed=base.copy();changed[pos]=b;rows.append(bytes(changed))
 return list(dict.fromkeys(rows))
def corpus(im):
 inputs=[];expected=[];seen=set()
 for raw in stimuli():
  value,trace=evaluate(im,raw);inputs.append(raw.hex()+'\n');expected.append(value+'\n');seen|=trace
 return ''.join(inputs).encode(),''.join(expected).encode(),seen
def verify():
 im=Image()
 try:
  proof=json.loads((PACKET/'FREEZE.json').read_text())
  if hashlib.sha256(im.data).hexdigest()!=SHA:raise ValueError('wrong115target')
  owner=proof['owner'];lo,hi=int(owner['start'],16),int(owner['end'],16)
  if im.view.fde(lo)!=(lo,hi) or hashlib.sha256(im.view.read(lo,hi-lo)).hexdigest()!=owner['sha256']:raise ValueError('owner mismatch')
  table=proof['digit_pair_table']
  if im.view.read(TABLE,200).hex()!=table['hex']:raise ValueError('digit-pair table mismatch')
  inputs,expected,seen=corpus(im)
  if len(set(inputs.splitlines()))!=proof['rows'] or len(expected.splitlines())!=proof['rows']:raise ValueError('input denominator changed')
  if hashlib.sha256(inputs).hexdigest()!=proof['input_sha256'] or hashlib.sha256(expected).hexdigest()!=proof['expected_sha256']:raise ValueError('original stream changed')
  if sorted(seen)!=proof['visited_addresses']:raise ValueError('visitation changed')
  if hashlib.sha256(im.data).hexdigest()!=SHA:raise ValueError('capture changed')
  return inputs,expected
 finally:im.close()
if __name__=='__main__':
 im=Image()
 try:
  if hashlib.sha256(im.data).hexdigest()!=SHA:raise ValueError('wrong115target')
  a,b,c=corpus(im);print('PROBE',len(a.splitlines()),len(c),{tag:sum(s.startswith(tag.encode()) for s in b.splitlines()) for tag in ['A','D','R']})
 finally:im.close()
