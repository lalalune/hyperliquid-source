"""Actual post-callback ring tail. No callback execution, return or composed trace."""
from pathlib import Path
import sys,hashlib,json
ROOT=Path(__file__).resolve().parents[3];PACKET=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'tools'))
import decimal_scaled_u64 as cpu
from elfview import View
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
TARGET=ROOT/'artifacts/node/115/hl-node'
BASES=[0x5911890,0x5911b30]
LEVEL=cpu.INPUT;BUFFER=LEVEL+0x200
class Image:
 slots={};note_target=None;panic_targets=set()
 def __init__(self):self.view=View(TARGET);self.data=self.view.b;self.cache={}
 def read_only(self,a):return None
 def fetch(self,a):
  if not any(base+lo<=a<base+hi for base in BASES for lo,hi in [(0x1f0,0x204),(0x212,0x259)]):raise ValueError('ring tail CFG escape')
  if a not in self.cache:self.cache[a]=cpu.decode(self.data,self.view.offset(a),a)
  return self.cache[a]
 def close(self):
  if self.data is not self.view.b:self.data.close()
  self.view.b.close();self.view.file.close()
class Machine(cpu.Machine):
 def __init__(self,im,capacity):
  super().__init__(im);self.regions=[(LEVEL,LEVEL+0x50),(BUFFER,BUFFER+capacity*32),(cpu.STACK,cpu.STACK+0x1b0)]
 def bounds(self,a,n):
  if not any(lo<=a and a+n<=hi for lo,hi in self.regions):raise ValueError('ring tail memory footprint')
 def load(self,a,n):self.bounds(a,n);return super().load(a,n)
 def reload(self,r,a,n):self.bounds(a,n);return super().reload(r,a,n)
 def store(self,a,n,v):self.bounds(a,n);return super().store(a,n,v)
 def spill(self,a,r,n):self.bounds(a,n);return super().spill(a,r,n)
 def call(self,*args):raise ValueError('ring grow/callback forbidden')
def evaluate(im,row):
 alias,cap,head,length,saved,cached=row
 if alias not in [0,1] or not 0<=cap<=8 or not 0<=length<=cap or not (head==0 if cap==0 else 0<=head<cap) or any(not 0<=v<=cpu.U64 for v in [saved,cached]):raise ValueError('qualified ring fixture required')
 m=Machine(im,cap)
 for lo,hi in m.regions:
  for a in range(lo,hi):m.mem[a]=(165+17*(a-lo))&255
 def word(a,v):
  for i,b in enumerate(v.to_bytes(8,'little')):m.mem[a+i]=b
 for a,v in [(LEVEL+0x28,cached),(LEVEL+0x30,cap),(LEVEL+0x38,BUFFER),(LEVEL+0x40,head),(LEVEL+0x48,length),(cpu.STACK+0x1a8,cpu.RETURN_MARK)]:word(a,v)
 for i in range(16):m.mem[cpu.STACK+0x68+i]=(13+i*7)&255
 for reg,v in [(cpu.R14,LEVEL),(cpu.R15,saved),(cpu.RBP,0x12345678),(cpu.RBX,0x33445566),(cpu.RSP,cpu.STACK)]:m.set_reg(reg,v)
 m.pc=BASES[alias]+0x1f0;base=BASES[alias]
 before={a:v for a,v in m.mem.items() if a>=LEVEL}
 for _ in range(100):
  if m.pc==base+0x204:
   if any(m.mem[a]!=v for a,v in before.items()):raise ValueError('ring grow frontier wrote memory')
   return 'G',m.seen
  try:m.step()
  except cpu.Done as done:
   if done.how!='ret' or m.get(cpu.RAX,64)!=0x33445566 or m.get(cpu.RSP,64)!=cpu.STACK+0x1b0:raise ValueError('ring return drift')
   level=bytes(m.mem[LEVEL+i] for i in range(0x50));buffer=bytes(m.mem[BUFFER+i] for i in range(cap*32))
   return 'V:'+level.hex()+':'+buffer.hex(),m.seen
 raise ValueError('ring step bound')
def stimuli():
 rows=[]
 for alias in [0,1]:
  for cap in range(9):
   for head in range(cap or 1):
    for length in range(cap+1):
     for saved,cached in [(0,1),(17,900),(cpu.U64,0)]:rows.append((alias,cap,head,length,saved,cached))
 return rows
def corpus(im):
 inputs=[];expected=[];seen=set()
 for row in stimuli():
  result,trace=evaluate(im,row);seen|=trace;inputs.append('\t'.join(map(str,row))+'\n');expected.append(result+'\n')
 return ''.join(inputs).encode(),''.join(expected).encode(),seen
def check_declared_source(report):
 im=Image()
 try:
  if hashlib.sha256(im.data).hexdigest()!=SHA:raise ValueError('wrong115target')
  observations=[]
  for alias in [0,1]:
   row=(alias,2,1,0,17,900);value,seen=evaluate(im,row)
   raw=bytes.fromhex(value.split(':')[2]);actual=int.from_bytes(raw[32:40],'little')
   observations.append(dict(alias=alias,saved_order_word=17,cached_level_word=900,actual_field0=actual))
  append=report['trace']['append'];origin=append.get('element0_origin',{})
  declared=append['element_fields'][0]['source']
  for item in observations:
   if declared=='the qword cached at level +0x28':item['declared_prediction']=item['cached_level_word']
   elif origin.get('object')=='order' and origin.get('offset')=='0xf0':item['declared_prediction']=item['saved_order_word']
   else:raise ValueError('unsupported source attribution '+declared)
  if any(x['actual_field0']!=x['declared_prediction'] for x in observations):raise ValueError('recorded ring field0 source contradicts original '+json.dumps(observations))
  return observations
 finally:im.close()
if __name__=='__main__':
 report=json.loads((ROOT/'research/work-items/RE-006-node115-book-ring-append/records.json').read_text());print(check_declared_source(report))
