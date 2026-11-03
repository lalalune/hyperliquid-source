"""Node115 packed three-word time conversion, independent instruction oracle.
Read-only original bytes; explicit raw-word boundary, no captured execution.
"""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[3]
PACKET=Path(__file__).resolve().parent
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
TARGET=ROOT/'artifacts/node/115/hl-node'
sys.path.insert(0,str(ROOT/'tools'))
import decimal_scaled_u64 as cpu
from elfview import View
# (complete FDE, selected start/end, input-pointer register, field displacement)
SPECS=[(0x3673a10,0x3673b80,0x3673a38,0x3673ae7,cpu.RSI,0),
 (0x42306f0,0x423091b,0x4230772,0x4230818,cpu.RCX,0),
 (0x2d1d600,0x2d1d876,0x2d1d6f6,0x2d1d7a1,cpu.R14,0x60),
 (0x5185200,0x5185476,0x51852f6,0x51853a1,cpu.R14,0x60),
 (0x5185480,0x51856f6,0x5185576,0x5185621,cpu.R14,0x60)]
class Image:
 note_target=None
 panic_targets=set()
 slots={}
 def __init__(self):
  self.view=View(TARGET);self.data=self.view.b;self.cache={};self.text_va,self.text_off,self.text_size=self.view.sections['.text']
 def fetch(self,va):
  if va not in self.cache:self.cache[va]=cpu.decode(self.data,self.view.offset(va),va)
  return self.cache[va]
 def read_only(self,va):return None
 def close(self):
  if self.data is not self.view.b:self.data.close()
  self.view.b.close();self.view.file.close()
class Machine(cpu.Machine):
 def bounds(self,at,n):
  if not cpu.INPUT<=at<at+n<=cpu.INPUT+12:raise ValueError('outside three input words')
 def load(self,at,n):
  self.bounds(at,n);return super().load(at,n)
 def reload(self,reg,at,n):
  self.bounds(at,n);return super().reload(reg,at,n)
 def spill(self,*args):raise ValueError('conversion memory spills excluded')
 def store(self,*args):raise ValueError('conversion memory writes excluded')
 def call(self,*args):raise ValueError('conversion calls excluded')
def evaluate(image,owner,words):
 if type(owner) is not int or not 0<=owner<len(SPECS) or len(words)!=3 or any(type(x) is not int or not 0<=x<1<<32 for x in words):raise ValueError('owner and three raw u32 required')
 _,_,start,end,reg,disp=SPECS[owner];m=Machine(image);m.set_reg(reg,cpu.INPUT-disp)
 # Original423070b XOR EDX,EDX; audit checks prelude preservation to4230772.
 if owner==1:m.set_reg(cpu.RDX,0)
 for index,word in enumerate(words):
  for k,byte in enumerate(word.to_bytes(4,'little')):m.mem[cpu.INPUT+index*4+k]=byte
 m.pc=start
 for _ in range(100):
  if m.pc==end:
   raw=m.get(cpu.RCX,64);clamped=m.get(cpu.RAX,64)
   if raw is None or clamped is None:raise ValueError('unknown conversion result')
   return (raw-(1<<64) if raw>>63 else raw,clamped),m.seen
  if not start<=m.pc<end:raise ValueError('conversion CFG escaped')
  m.step()
 raise ValueError('conversion step bound')
def stimuli():
 cases=set()
 years=[-262144,-262143,-401,-400,-399,-101,-100,-99,-1,0,1,4,100,400,1582,1899,1900,1901,1968,1969,1970,1971,1999,2000,2001,2038,2100,2400,262142,262143]
 def put(year,ordinal,seconds=0,nanos=0,flags=0):cases.add((((year<<13)|(ordinal<<4)|flags)&0xffffffff,seconds,nanos))
 for year in years:
  for ordinal in [0,1,2,28,29,31,59,60,61,365,366,367,510,511]:put(year,ordinal)
 for year in [-262144,-1,0,1900,1970,2000,262143]:
  for ordinal in range(512):put(year,ordinal)
 for year in [-1,0,1970,2000,262143]:
  for flags in range(16):
   for ordinal in [0,1,60,366,511]:put(year,ordinal,123,123456789,flags)
 seconds=[0,1,59,60,86399,86400,86401,(1<<31)-1,1<<31,(1<<32)-1]
 nanos=[0,1,999999,1000000,1000001,999999999,1000000000,1999999999,2000000000,(1<<31)-1,1<<31,(1<<32)-1]
 for year in [-262144,-1,1969,1970,2000,262143]:
  for sec in seconds:
   for nano in nanos:put(year,365 if year==1969 else 1,sec,nano)
 state=0x115ca1e
 for _ in range(1024):
  words=[]
  for _ in range(3):state=(1664525*state+1013904223)&0xffffffff;words.append(state)
  cases.add(tuple(words))
 return sorted(cases)
def corpus(image):
 inputs=[];expected=[];seen=[set() for _ in SPECS]
 for words in stimuli():
  for owner in range(len(SPECS)):
   result,trace=evaluate(image,owner,words);seen[owner]|=trace
   inputs.append('\t'.join(map(str,(owner,*words)))+'\n');expected.append('\t'.join(map(str,result))+'\n')
 return ''.join(inputs).encode(),''.join(expected).encode(),seen


def verify():
 import hashlib,json
 im=Image()
 try:
  record=json.loads((PACKET/'FREEZE.json').read_text())
  if hashlib.sha256(im.data).hexdigest()!=SHA or record['target_sha256']!=SHA:raise ValueError('wrong target115')
  inputs,expected,seen=corpus(im)
  if hashlib.sha256(inputs).hexdigest()!=record['input_sha256'] or hashlib.sha256(expected).hexdigest()!=record['expected_sha256'] or [sorted(x) for x in seen]!=record['visited_addresses']:raise ValueError('frozen conversion corpus changed')
  return inputs,expected
 finally:im.close()
