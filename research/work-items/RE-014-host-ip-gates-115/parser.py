"""Bounded instruction interpretation of the actual leaf and its caller CALL/RET."""
from native import *
BUF=cpu.INPUT+0x2000
STATE=cpu.INPUT+0x1000
LEAF,LEAF_END=0x167ccb0,0x167d082
class ParserMachine(cpu.Machine):
 def __init__(self,image,data,composed=False):
  super().__init__(image);self.size=len(data);self.composed=composed;self.calls=0
 def bounds(self,a,n,write=False):
  spans=[(cpu.STACK-64,128),(STATE,16)]
  if not write:spans.extend([(BUF,self.size),(cpu.STACK+0x178,8)])
  if not any(lo<=a and a+n<=lo+size for lo,size in spans):raise ValueError(f'parser footprint {a:#x}/{n}/{write}')
 def load(self,a,n):self.bounds(a,n);return super().load(a,n)
 def reload(self,r,a,n):self.bounds(a,n);return super().reload(r,a,n)
 def store(self,a,n,v):self.bounds(a,n,True);return super().store(a,n,v)
 def spill(self,a,r,n):self.bounds(a,n,True);return super().spill(a,r,n)
 def call(self,target,where):
  if not self.composed or target!=LEAF or where!=0x1562c17:raise ValueError('unclosed call')
  self.calls+=1;return super().call(target,where)
def evaluate(image,data,composed=False):
 m=ParserMachine(image,data,composed);m.set_reg(cpu.RSP,cpu.STACK)
 for k,b in enumerate(data):m.mem[BUF+k]=b
 if composed:
  m.set_reg(cpu.R13,len(data));m.set_reg(cpu.R15,cpu.STACK+0x10);put(m,cpu.STACK+0x178,BUF)
  state=cpu.STACK+0x10;m.pc=0x1562bf5
 else:
  state=STATE;m.set_reg(cpu.RDI,state);m.store(state,8,BUF);m.store(state+8,8,len(data));m.store(cpu.STACK,8,cpu.RETURN_MARK);m.pc=LEAF
 try:
  for _ in range(800):
   if composed and m.pc in (0x1562c2d,0x1562d31):break
   if not (LEAF<=m.pc<LEAF_END or composed and (0x1562bf5<=m.pc<0x1562c2d)):raise ValueError('escaped reviewed CFG')
   m.step()
  else:raise ValueError('step bound')
 except cpu.Done as done:
  if composed or done.how!='ret':raise
 if composed and not m.calls:return 'B',m.seen
 tag=m.get(cpu.RAX,8);full=m.get(cpu.RAX,64);ptr=m.load(state,8);rest=m.load(state+8,8)
 if tag not in (0,1) or ptr is None or rest is None or not BUF<=ptr<=BUF+len(data):raise ValueError('unknown/outside parser result')
 payload=(full>>8)&0xffffffff if tag else 0
 route=('A' if m.pc==0x1562c2d else 'R') if composed else str(tag)
 return f'{route},{payload},{ptr-BUF},{rest}',m.seen

def byte_stimuli():
 cases={b'1234567890123456',b'',b'1.2.3.4',b'0.0.0.0',b'255.255.255.255',b'256.0.0.0',b'1:2.3.4',b'01.2.3.4'}
 for slot in range(4):
  for value in range(301):
   octets=[b'1',b'2',b'3',b'4'];octets[slot]=str(value).encode();cases.add(b'.'.join(octets))
  for value in [b'00',b'01',b'001',b'0001',b'0255']:
   octets=[b'1',b'2',b'3',b'4'];octets[slot]=value;cases.add(b'.'.join(octets))
 for seed,alphabet in [(b'1.2.3.4',range(256)),(b'255.255.255.255',b'0123456789.: x\n\x00+-')]:
  for pos in range(len(seed)):
   for byte in alphabet:cases.add(seed[:pos]+bytes([byte])+seed[pos+1:])
  for pos in range(len(seed)+1):cases.add(seed[:pos])
  for suffix in [b' ',b'\n',b'\x00',b'x',b'.5',b'00',b':80',b'\r\n']:cases.add(seed+suffix)
 state=0x115167ccb0
 for i in range(512):
  row=bytearray()
  for _ in range(i%21):state=(state*6364136223846793005+1442695040888963407)&cpu.U64;row.append(state>>56)
  cases.add(bytes(row))
 return sorted(cases)
def corpus(image):
 inputs=[];expected=[];seen=set()
 for data in byte_stimuli():
  for op in ('P','C'):
   result,trace=evaluate(image,data,op=='C');seen|=trace
   inputs.append(op+'\t'+data.hex()+'\n');expected.append(result+'\n')
 return ''.join(inputs).encode(),''.join(expected).encode(),seen

def verify():
 import hashlib,json
 image=Image();record=json.loads((PACKET/'PARSER-FREEZE.json').read_text())
 if hashlib.sha256(image.data).hexdigest()!=SHA:raise ValueError('node115 identity mismatch')
 inputs,expected,seen=corpus(image)
 if hashlib.sha256(inputs).hexdigest()!=record['input_sha256'] or hashlib.sha256(expected).hexdigest()!=record['expected_sha256'] or sorted(seen)!=record['visited_addresses']:raise ValueError('parser frozen corpus changed')
 return inputs,expected
