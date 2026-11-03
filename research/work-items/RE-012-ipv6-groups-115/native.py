"""Whole group reader with real numeric/IPv4 CALL/RET; no import substitutes."""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[3];PACKET=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'tools'));import decimal_scaled_u64 as cpu
from elfview import View
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301';TARGET=ROOT/'artifacts/node/115/hl-node'
START,END=0x1686080,0x168625d
RANGES=[(START,END),(0x167ccb0,0x167d082),(0x167c8b0,0x167cb14)]
STATE=cpu.INPUT+0x1000;BUF=cpu.INPUT+0x2000;OUT=cpu.INPUT+0x3000
class Image:
 note_target=None
 panic_targets=set()
 slots={}
 def __init__(self):self.view=View(TARGET);self.data=self.view.b;self.cache={};self.text_va,self.text_off,self.text_size=self.view.sections['.text']
 def fetch(self,va):
  if va not in self.cache:self.cache[va]=cpu.decode(self.data,self.view.offset(va),va)
  return self.cache[va]
 def read_only(self,va):return None
 def close(self):
  if self.data is not self.view.b:self.data.close()
  self.view.b.close();self.view.file.close()
class Machine(cpu.Machine):
 def __init__(self,image,size):super().__init__(image);self.size=size
 def bounds(self,a,n,write=False):
  spans=[(cpu.STACK-4096,4160),(STATE,16),(OUT,16)]
  if not write:spans.append((BUF,self.size))
  if not any(lo<=a and a+n<=lo+size for lo,size in spans):raise ValueError('group reader footprint')
 def load(self,a,n):self.bounds(a,n);return super().load(a,n)
 def reload(self,r,a,n):self.bounds(a,n);return super().reload(r,a,n)
 def store(self,a,n,v):self.bounds(a,n,True);return super().store(a,n,v)
 def spill(self,a,r,n):self.bounds(a,n,True);return super().spill(a,r,n)
 def call(self,target,where):
  if (where,target) not in {(0x16860b9,0x167ccb0),(0x16861a6,0x167ccb0),(0x1686112,0x167c8b0),(0x168620e,0x167c8b0)}:raise ValueError(f'unclosed helper {target:#x}')
  return super().call(target,where)
 def shift(self,kind,value,count,bits):
  if kind==0 and bits==16:
   if value is None or count is None:raise ValueError('unknown ROL16')
   count=(count&31)%16
   if not count:return value
   result=((value<<count)|(value>>(16-count)))&0xffff
   self.flags[0]=bool(result&1);self.flags[3]=bool((result>>15)^(result&1)) if count==1 else None
   return result
  return super().shift(kind,value,count,bits)
def evaluate(image,data,cap,canary=0):
 if type(cap) is not int or not 0<=cap<=8 or canary not in (0,1):raise ValueError('capacity0..8/canary0..1 required')
 m=Machine(image,len(data));m.set_reg(cpu.RDI,STATE);m.set_reg(cpu.RSI,OUT);m.set_reg(cpu.RDX,cap);m.set_reg(cpu.RSP,cpu.STACK)
 m.store(STATE,8,BUF);m.store(STATE+8,8,len(data));m.store(cpu.STACK,8,cpu.RETURN_MARK)
 for k,b in enumerate(data):m.mem[BUF+k]=b
 for k in range(8):m.store(OUT+2*k,2,0x5a00+k if canary else 0)
 m.pc=START
 try:
  for _ in range(20000):
   if not any(lo<=m.pc<hi for lo,hi in RANGES):raise ValueError('escaped helper closure')
   m.step()
  raise ValueError('step limit')
 except cpu.Done as done:
  if done.how!='ret':raise
 n=m.get(cpu.RAX,64);flag=m.get(cpu.RDX,8);ptr=m.load(STATE,8);rest=m.load(STATE+8,8)
 if None in (n,flag,ptr,rest) or not 0<=n<=cap or not BUF<=ptr<=BUF+len(data):raise ValueError('invalid/unknown group result')
 result=(n,flag&1,ptr-BUF,rest,*[m.load(OUT+2*k,2) for k in range(8)])
 return result,m.seen
if __name__=='__main__':
 im=Image()
 for data in [b'',b'1',b'1:2',b'::1',b'2001:db8:0:1',b'1.2.3.4',b'1:2:192.0.2.1',b'00001',b'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',b'1:bad:x']:
  print(repr(data),evaluate(im,data,8,1)[0])
 im.close()


def stimuli():
 cases={b'',b':',b'::',b'::1',b'1',b'1:',b'1::2',b'1:2:3:4:5:6:7:8',b'1:2:3:4:5:6:7:8:9',b'2001:db8:0:1',b'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',b'1.2.3.4',b'1:2:192.0.2.1',b'1:2:01.2.3.4',b'1;2',b'1:f',b'00001',b'1:00001',b'ff',b'1:bad:x',b'1:2:3:4:5:6:1.2.3.4',b'1:2:3:4:5:6:7:1.2.3.4'}
 for slot in range(8):
  for word in [b'0',b'1',b'9',b'a',b'f',b'F',b'10',b'ff',b'100',b'fff',b'ffff',b'10000',b'00000',b'01',b'0000',b'x',b'']:
   parts=[b'1']*8;parts[slot]=word;cases.add(b':'.join(parts))
 for byte in range(256):cases.add(bytes([byte]))
 for value in [0,1,9,10,99,100,127,128,254,255,256,257,999]:
  for slot in range(4):
   parts=[b'1',b'2',b'3',b'4'];parts[slot]=str(value).encode();ip=b'.'.join(parts);cases.add(ip);cases.add(b'1:2:'+ip)
 for byte in b'0123456789abcdefABCDEF:.x\x00\n-':
  for pos in range(5):cases.add(b'1:f:2'[:pos]+bytes([byte])+b'1:f:2'[pos+1:])
 for seed in [b'1:2:3:4:5:6:7:8',b'1:2:192.0.2.1']:
  for pos in range(len(seed)+1):cases.add(seed[:pos])
  for tail in [b'x',b':',b'::',b'\x00',b'\n',b'.5']:cases.add(seed+tail)
 state=0x11516860
 for i in range(128):
  row=bytearray()
  for _ in range(i%22):state=(1664525*state+1013904223)&0xffffffff;row.append(state>>24)
  cases.add(bytes(row))
 return sorted(cases)
def corpus(image):
 inputs=[];expected=[];seen=set()
 for data in stimuli():
  for cap in range(9):
   for canary in (0,1):
    result,trace=evaluate(image,data,cap,canary);seen|=trace
    inputs.append(f'{cap}\t{canary}\t{data.hex()}\n');expected.append('\t'.join(map(str,result))+'\n')
 return ''.join(inputs).encode(),''.join(expected).encode(),seen

def verify():
 import hashlib,json
 im=Image()
 try:
  record=json.loads((PACKET/'FREEZE.json').read_text())
  if hashlib.sha256(im.data).hexdigest()!=SHA:raise ValueError('wrong115target')
  inputs,expected,seen=corpus(im)
  if hashlib.sha256(inputs).hexdigest()!=record['input_sha256'] or hashlib.sha256(expected).hexdigest()!=record['expected_sha256'] or sorted(seen)!=record['visited_addresses']:raise ValueError('frozen group stream changed')
  return inputs,expected
 finally:im.close()
