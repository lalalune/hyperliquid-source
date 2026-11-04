from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[3];sys.path.insert(0,str(ROOT/'tools'))
PACKET=Path(__file__).resolve().parent
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
TARGET=ROOT/'artifacts/node/115/hl-node'
START,END=0x1562670,0x1563a5c
import decimal_scaled_u64 as cpu
from elfview import View
class Image:
 note_target=None
 panic_targets=set()
 slots={}
 def read_only(self,va):return None
 def __init__(self):
  self.view=View(TARGET);self.data=self.view.b;self.text_va,self.text_off,self.text_size=self.view.sections['.text'];self.cache={}
 def close(self):
  if self.data is not self.view.b:self.data.close()
  self.view.b.close();self.view.file.close()
 def fetch(self,va):
  if va not in self.cache:self.cache[va]=cpu.decode(self.data,self.view.offset(va),va)
  return self.cache[va]
class Machine(cpu.Machine):
 def load(self,at,n):
  if (at,n) not in [(cpu.STACK+0x18,8),(cpu.STACK+0x218,8)]:raise ValueError('outside selected reader-result slots')
  return super().load(at,n)
 def store(self,*a):raise ValueError('all writes excluded')
 def call(self,*a):raise ValueError('all helper calls excluded')
def put(m,at,value):
 for k,b in enumerate(value.to_bytes(8,'little')):m.mem[at+k]=b
def drive(m,start,end,reject):
 m.pc=start
 for _ in range(10):
  if m.pc==end:return True,m.seen
  if m.pc==reject:return False,m.seen
  if not start<=m.pc<end:raise ValueError('escaped selected phase')
  m.step()
 raise ValueError('step budget')
def admission(image,length,al,remaining):
 if not all(type(x) is int and 0<=x<=cpu.U64 for x in (length,remaining)) or type(al) is not int or not 0<=al<256:raise ValueError('raw caller words/byte required')
 before=Machine(image);before.set_reg(cpu.R13,length);passed,seen=drive(before,0x1562bf5,0x1562bff,0x1562d31)
 if not passed:return 'B',seen
 # Fresh, explicit normal-return boundary. No parser call is substituted/run.
 after=Machine(image);after.set_reg(cpu.RAX,al);after.set_reg(cpu.RSP,cpu.STACK);put(after,cpu.STACK+0x18,remaining)
 passed,trace=drive(after,0x1562c1c,0x1562c2d,0x1562d31)
 return ('A' if passed else 'R'),seen|trace
def override(image,word):
 if type(word) is not int or not 0<=word<=cpu.U64:raise ValueError('raw override word required')
 m=Machine(image);m.set_reg(cpu.RSP,cpu.STACK);put(m,cpu.STACK+0x218,word)
 # Real MOVABS R12,MIN is interpreted before CMP/JNE.
 fallthrough,seen=drive(m,0x15627e8,0x1562800,0x1562903)
 return int(fallthrough),seen

def stimuli():
 lengths=sorted(set(range(33))|{(1<<32)-1,1<<32,(1<<32)+1,(1<<63)-1,1<<63,(1<<63)+1,cpu.U64})
 flags=[0,1,2,3,4,7,15,127,128,129,254,255]
 remaining=[0,1,2,15,16,(1<<32)-1,1<<32,cpu.U64]
 rows=[('M',length,flag,rest) for length in lengths for flag in flags for rest in remaining]
 state=0x1151f00d
 for _ in range(1024):
  state=(state*6364136223846793005+1442695040888963407)&cpu.U64;length=state
  state=(state*6364136223846793005+1442695040888963407)&cpu.U64;flag=state&255
  state=(state*6364136223846793005+1442695040888963407)&cpu.U64;rows.append(('M',length,flag,state))
 words={0,1,2,cpu.U64}|{(1<<63)+j for j in range(-8,9)}
 for _ in range(512):state=(state*6364136223846793005+1442695040888963407)&cpu.U64;words.add(state)
 rows.extend(('O',word) for word in sorted(words))
 return rows

def corpus(image):
 inputs=[];expected=[];seen=set()
 for row in stimuli():
  result,trace=admission(image,*row[1:]) if row[0]=='M' else override(image,row[1]);seen|=trace
  inputs.append('\t'.join(map(str,row))+'\n');expected.append(str(result)+'\n')
 return ''.join(inputs).encode(),''.join(expected).encode(),seen

def verify():
 import hashlib,json
 image=Image();record=json.loads((PACKET/'FREEZE.json').read_text())
 if hashlib.sha256(image.data).hexdigest()!=SHA or record['target_sha256']!=SHA:raise ValueError('node115 identity mismatch')
 inputs,expected,seen=corpus(image)
 if hashlib.sha256(inputs).hexdigest()!=record['input_sha256'] or hashlib.sha256(expected).hexdigest()!=record['expected_sha256'] or sorted(seen)!=record['visited_addresses']:raise ValueError('frozen corpus changed')
 return inputs,expected
