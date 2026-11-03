"""Original-byte fresh u64-key hash with authentic bounded writer CALL/RET."""
import hashlib,json,random,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3];PACKET=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'tools'));import decimal_scaled_u64 as cpu
from elfview import View
TARGET=ROOT/'artifacts/node/115/hl-node';SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
START,END=0x47172c0,0x4717433
WRITER,WRITER_END=0x45927a0,0x4592977
class Image:
 slots={};panic_targets=set();note_target=None
 def __init__(self):
  self.view=View(TARGET);self.data=self.view.b;self.cache={};self.text_va,self.text_off,self.text_size=self.view.sections['.text']
 def read_only(self,a):return None
 def fetch(self,a):
  if not (START<=a<END or WRITER<=a<WRITER_END):raise ValueError('hash CFG escaped')
  if a not in self.cache:self.cache[a]=cpu.decode(self.data,self.view.offset(a),a)
  return self.cache[a]
 def close(self):
  if self.data is not self.view.b:self.data.close()
  self.view.b.close();self.view.file.close()
class Machine(cpu.Machine):
 def bounds(self,a,n):
  if not cpu.STACK-1024<=a or a+n>cpu.STACK+8:raise ValueError('hash stack footprint escaped')
 def load(self,a,n):self.bounds(a,n);return super().load(a,n)
 def reload(self,r,a,n):self.bounds(a,n);return super().reload(r,a,n)
 def store(self,a,n,v):self.bounds(a,n);return super().store(a,n,v)
 def spill(self,a,r,n):self.bounds(a,n);return super().spill(a,r,n)
 def shift(self,kind,value,count,bits):
  # Active task blocker: maintained evaluator lacks the actual ROL64 opcode.
  # Preserve ZF/SF, bind CF, and leave multi-bit OF unknown; shared tool unchanged.
  if kind==0 and bits==64:
   if count is None:raise ValueError('unknown ROL count')
   count &= 63
   if count==0:return value
   if value is None:self.flags[0]=self.flags[3]=None;return None
   result=((value<<count)|(value>>(64-count)))&cpu.U64
   self.flags[0]=bool(result&1);self.flags[3]=bool((result>>63)^(result&1)) if count==1 else None
   return result
  return super().shift(kind,value,count,bits)
 def call(self,target,where):
  if (where,target)!=(0x471733b,WRITER):raise ValueError('unclosed hash call')
  self.calls+=1;return super().call(target,where)
def evaluate(im,row):
 m=Machine(im);m.calls=0;m.pc=START;m.set_reg(cpu.RDI,row[0]);m.set_reg(cpu.RSI,row[1]);m.set_reg(cpu.RDX,row[2]);m.set_reg(cpu.RSP,cpu.STACK);m.store(cpu.STACK,8,cpu.RETURN_MARK)
 for _ in range(4000):
  try:m.step()
  except cpu.Done as e:
   if e.how!='ret' or m.calls!=1:raise ValueError('wrong hash stop')
   result=m.get(cpu.RAX,64)
   if result is None:raise ValueError('unknown result')
   return result,m.seen
 raise ValueError('hash step bound')
def stimuli():
 edge=[0,1,2,7,8,255,1<<32,1<<63,cpu.U64-1,cpu.U64];rows={(a,b,c) for a in edge for b in edge for c in edge}
 for k in range(64):
  for j in range(3):
   r=[0,0,0];r[j]=1<<k;rows.add(tuple(r));r=[cpu.U64]*3;r[j]^=1<<k;rows.add(tuple(r))
 rng=random.Random(11547172)
 for _ in range(256):rows.add(tuple(rng.getrandbits(64) for _ in range(3)))
 return sorted(rows)
def corpus(im):
 inputs=[];answers=[];seen=set()
 for row in stimuli():
  result,trace=evaluate(im,row);seen|=trace;inputs.append('\t'.join(map(str,row))+'\n');answers.append(str(result)+'\n')
 return ''.join(inputs).encode(),''.join(answers).encode(),seen
def verify():
 im=Image()
 try:
  if hashlib.sha256(im.data).hexdigest()!=SHA:raise ValueError('wrong115target')
  inputs,answers,seen=corpus(im);f=json.loads((PACKET/'FREEZE.json').read_text())
  if hashlib.sha256(inputs).hexdigest()!=f['input_sha256'] or hashlib.sha256(answers).hexdigest()!=f['expected_sha256'] or sorted(seen)!=f['visited_addresses']:raise ValueError('frozen hash stream changed')
  return inputs,answers
 finally:im.close()
if __name__=='__main__':
 im=Image()
 try:
  for row in [(0,0,0),(1,2,3),(cpu.U64,0,cpu.U64)]:print(row,evaluate(im,row)[0])
 finally:im.close()
