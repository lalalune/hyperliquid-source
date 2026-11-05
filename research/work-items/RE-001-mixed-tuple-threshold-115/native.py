"""Complete100-byte node115 mixed-sign lexicographic/saturating selector."""
from pathlib import Path
import hashlib,itertools,json,sys
ROOT=Path(__file__).resolve().parents[3];PACKET=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'tools'))
import decimal_scaled_u64 as cpu
from elfview import View
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301';TARGET=ROOT/'artifacts/node/115/hl-node';OWNER=(0x55ff9e0,0x55ffa44)
OBJ=cpu.INPUT;SP=cpu.STACK;MASK=(1<<64)-1
FIELDS=[(0x60,4),(0x64,4),(0x68,4),(0x4294,4),(0x4298,4),(0x429c,4),(0x28,8),(0x10,8),(0x4228,8)]
ALTERNATE=[(0x60,4),(0x64,4),(0x68,4),(0x4e04,4),(0x4e08,4),(0x4e0c,4),(0x28,8),(0x10,8),(0x4d98,8)]
FAMILIES=[(*OWNER,FIELDS),(0x2c6f290,0x2c6f2f4,FIELDS),(0x55ff970,0x55ff9d4,ALTERNATE)]
class Image:
 slots={};note_target=None;panic_targets=set()
 def __init__(self):self.view=View(TARGET);self.data=self.view.b;self.cache={}
 def read_only(self,a):return None
 def fetch(self,a):
  if not any(lo<=a<hi for lo,hi,_ in FAMILIES):raise ValueError('lex owner CFG escape')
  if a not in self.cache:self.cache[a]=cpu.decode(self.data,self.view.offset(a),a)
  return self.cache[a]
 def close(self):
  if self.data is not self.view.b:self.data.close()
  self.view.b.close();self.view.file.close()
class Machine(cpu.Machine):
 def __init__(self,im,fields):super().__init__(im);self.record=False;self.fields=fields
 def bounds(self,a,n):
  if not any(OBJ+off<=a and a+n<=OBJ+off+size for off,size in self.fields) and not (SP<=a and a+n<=SP+8):raise ValueError('lex undeclared memory read '+hex(a))
 def load(self,a,n):self.bounds(a,n);return super().load(a,n)
 def reload(self,r,a,n):self.bounds(a,n);return super().reload(r,a,n)
 def store(self,a,n,v):
  if self.record:raise ValueError('store in read-only selector')
  return super().store(a,n,v)
 def spill(self,a,r,n):
  if self.record:raise ValueError('spill in read-only selector')
  return super().spill(a,r,n)
 def call(self,*args):raise ValueError('call in call-free selector')
def evaluate(im,row):
 if len(row)!=10 or row[0] not in range(3):raise ValueError('family and nine raw words required')
 lo,hi,fields=FAMILIES[row[0]];values=row[1:]
 if any(not 0<=x<(1<<(size*8)) for x,(_,size) in zip(values,fields)):raise ValueError('field width')
 m=Machine(im,fields)
 for x,(off,size) in zip(values,fields):m.store(OBJ+off,size,x)
 m.store(SP,8,cpu.RETURN_MARK);m.set_reg(cpu.RDI,OBJ);m.set_reg(cpu.RSP,SP);m.record=True
 try:m.run(lo)
 except cpu.Done:
  if m.pc!=hi or m.get(cpu.RSP,64)!=SP+8:raise ValueError('not genuine selector RET')
 result=m.get(cpu.RAX,8)
 if result is None:raise ValueError('unknown AL')
 return result,m.seen

def stimuli():
 edges=[0,1,0x7fffffff,0x80000000,0xffffffff];tuples=[]
 for at in range(3):
  for a,b in itertools.product(edges,repeat=2):
   left=[0,0xffffffff,0x80000000];right=list(left);left[at]=a;right[at]=b;tuples.append(left+right)
 state=0x2468ace013579bdf
 for i in range(32):
  t=[]
  for j in range(6):state=(state*6364136223846793005+1)&MASK;t.append(state&0xffffffff)
  tuples.append(t)
 scalars=[]
 for x in [0,1,MASK-5001,MASK-5000,MASK-4999,MASK]:
  threshold=min(x+5000,MASK)
  for t in {max(0,threshold-1),threshold,min(MASK,threshold+1),0}:
   for c in {max(0,t-1),t,min(MASK,t+1)}:scalars.append([t,x,c])
 rows=[words+scalar for words,scalar in itertools.product(tuples,scalars)]
 for i in range(384):
  row=[]
  for j in range(9):state=(state*6364136223846793005+1442695040888963407)&MASK;row.append(state&0xffffffff if j<6 else state)
  rows.append(row)
 return list({json.dumps(x,separators=(',',':')):x for x in rows}.values())
def corpus(im):
 inputs=[];expected=[];seen=set()
 for row in ([family,*values] for family in range(3) for values in stimuli()):
  answer,trace=evaluate(im,row);seen|=trace;inputs.append(json.dumps(row,separators=(',',':'))+'\n');expected.append(str(answer)+'\n')
 return ''.join(inputs).encode(),''.join(expected).encode(),seen
