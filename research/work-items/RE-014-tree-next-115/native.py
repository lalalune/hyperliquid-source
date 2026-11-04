from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[3];PACKET=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'tools'));import decimal_scaled_u64 as cpu
from elfview import View
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301';TARGET=ROOT/'artifacts/node/115/hl-node';START,END=0x37c4430,0x37c4644
STATE=cpu.INPUT;NODES=cpu.INPUT+0x10000;STRIDE=512
class Image:
 note_target=None;panic_targets=set();slots={}
 def __init__(self):self.view=View(TARGET);self.data=self.view.b;self.cache={};self.text_va,self.text_off,self.text_size=self.view.sections['.text']
 def read_only(self,a):return None
 def fetch(self,a):
  if a not in self.cache:self.cache[a]=cpu.decode(self.data,self.view.offset(a),a)
  return self.cache[a]
 def close(self):
  if self.data is not self.view.b:self.data.close()
  self.view.b.close();self.view.file.close()
class Machine(cpu.Machine):
 def __init__(self,im,nodes):super().__init__(im);self.nodes=nodes
 def bounds(self,a,n,write=False):
  if any(lo<=a and a+n<=lo+size for lo,size in [(STATE,72),(cpu.STACK-64,128)]):return
  if not write and a>=NODES and (a-NODES)//STRIDE<self.nodes and (a-NODES)%STRIDE+n<=416:return
  raise ValueError(f'iterator footprint{a:#x}/{n}')
 def load(self,a,n):self.bounds(a,n);return super().load(a,n)
 def reload(self,r,a,n):self.bounds(a,n);return super().reload(r,a,n)
 def store(self,a,n,v):self.bounds(a,n,True);return super().store(a,n,v)
 def spill(self,a,r,n):self.bounds(a,n,True);return super().spill(a,r,n)
 def call(self,*args):raise ValueError('unclosed iterator panic')
def put(m,a,n,v):
 for k,b in enumerate(v.to_bytes(n,'little')):m.mem[a+k]=b
def addr(node):return 0 if node is None else NODES+node*STRIDE
def fixture(im,height=0,fan=2,leaf=2,tag=1,shape=0,seed=1000,ready=-1,index=0,level=0,remaining=None):
 nodes=[]
 def make(depth,parent=None,edge=0,tower=False):
  me=len(nodes);n=(0 if tower else fan-1) if depth else leaf
  nodes.append(dict(parent=parent,edge=edge,n=n,kids=[],level=depth))
  if depth:nodes[me]['kids']=[make(depth-1,me,i,tower) for i in range(1 if tower else fan)]
  return me
 if shape:
  nodes.append(dict(parent=None,edge=0,n=1,kids=[],level=height));nodes[0]['kids']=[make(height-1,0,i,True) for i in range(2)]
 else:make(height)
 m=Machine(im,len(nodes))
 for i,node in enumerate(nodes):
  base=addr(i);put(m,base,8,addr(node['parent']));put(m,base+0x13c,2,node['edge']);put(m,base+0x13e,2,node['n'])
  for j in range(node['n']):
   put(m,base+8+j*8,8,seed^((i*0x9e3779b97f4a7c15+j)&cpu.U64))
   for k in range(20):put(m,base+0x60+j*20+k,1,(seed+i*13+j*23+k)&255)
  for j,child in enumerate(node['kids']):put(m,base+0x140+j*8,8,addr(child))
 words=[tag,0 if ready<0 else addr(ready),addr(0) if ready<0 else level,height if ready<0 else index,0x111,0x222,0x333,0x444,sum(n['n'] for n in nodes) if remaining is None else remaining]
 for i,w in enumerate(words):put(m,STATE+i*8,8,w)
 m.set_reg(cpu.RDI,STATE);return m,nodes
def step(m):
 m.set_reg(cpu.RSP,cpu.STACK);put(m,cpu.STACK,8,cpu.RETURN_MARK);m.pc=START
 try:
  for _ in range(5000):
   if m.pc in (0x37c462d,0x37c463c):return ('PARENT' if m.pc==0x37c462d else 'TAG'),None
   if not START<=m.pc<END:raise ValueError('iterator CFG escaped')
   m.step()
  raise ValueError('iterator stepbound')
 except cpu.Done as e:
  if e.how!='ret':raise
 key=m.get(cpu.RAX,64)
 if key is None:raise ValueError('unknown iterator result')
 if key==0:return 'NONE',None
 value=m.get(cpu.RDX,64)
 return 'ITEM',((key-NODES)//STRIDE,(key-NODES)%STRIDE,(value-NODES)//STRIDE,(value-NODES)%STRIDE,m.load(value,8),bytes(m.load(key+i,1) for i in range(20)).hex())
if __name__=='__main__':
 im=Image()
 for height,fan,leaf in [(0,2,0),(0,2,3),(1,2,2),(2,3,1)]:
  m,nodes=fixture(im,height,fan,leaf);items=[]
  for _ in range(sum(n['n'] for n in nodes)+2):
   tag,result=step(m);items.append((tag,result))
   if tag!='ITEM':break
  print(height,fan,leaf,items)
 im.close()


def snapshot(m):
 words=[m.load(STATE+8*i,8) for i in range(9)]
 if words[1]:words[1]=(words[1]-NODES)//STRIDE+1
 elif words[2]:words[2]=(words[2]-NODES)//STRIDE+1
 return words

def evaluate(image,row):
 shape,h,fan,leaf,seed,tag,ready,index,level,remaining,walk=row
 m,nodes=fixture(image,h,fan,leaf,tag,shape,seed,ready,index,level,remaining)
 results=[]
 for _ in range(sum(n['n'] for n in nodes)+2 if walk else 1):
  kind,item=step(m);state=snapshot(m)
  fields=[kind]
  if item is not None:fields.extend(map(str,item))
  fields.extend(map(str,state));results.append(','.join(fields))
  if kind!='ITEM':break
 else:
  if walk:raise ValueError('walk transcript bound')
 return ';'.join(results),m.seen

def stimuli():
 rows=set();shapes=[]
 for h in (0,1,2,3):
  for fan in (2,3,4):
   if h==3 and fan>2:continue
   for leaf in (1,2,5,11):shapes.append((0,h,fan,leaf))
 shapes.extend((0,h,6,leaf) for h in (1,2) for leaf in (5,11))
 shapes.extend((0,0,2,0) for _ in range(1))
 shapes.extend((1,h,2,leaf) for h in (1,2,3,7,8,9,15,16,17) for leaf in (1,2,11))
 for shape,h,fan,leaf in shapes:
  for seed in (0,1000,cpu.U64):
   m,nodes=fixture(None,h,fan,leaf,shape=shape,seed=seed);total=sum(n['n'] for n in nodes)
   rows.add((shape,h,fan,leaf,seed,1,-1,0,0,total,1))
   for tag in (0,2,1<<32|1,1<<63|1):rows.add((shape,h,fan,leaf,seed,tag,-1,0,0,total,0))
   for rem in (0,1,total+1,cpu.U64):rows.add((shape,h,fan,leaf,seed,1,-1,0,0,rem,0))
   for node_id in sorted({0,len(nodes)-1,min(1,len(nodes)-1)}):
    node=nodes[node_id]
    for index in sorted({0,max(0,node['n']-1),node['n']}):
     rows.add((shape,h,fan,leaf,seed,1,node_id,index,node['level'],total or 1,0))
    if node_id==0:rows.add((shape,h,fan,leaf,seed,(1<<32)|1,node_id,0,node['level'],total or 1,0))
 return sorted(r for r in rows if not (r[0]==0 and r[1]==0 and (r[2]!=2 or (r[3]==0 and r[4]!=1000))))

def corpus(image):
 inputs=[];expected=[];seen=set()
 for row in stimuli():
  result,trace=evaluate(image,row);seen|=trace
  inputs.append('\t'.join(map(str,row))+'\n');expected.append(result+'\n')
 return ''.join(inputs).encode(),''.join(expected).encode(),seen

def verify():
 import hashlib,json
 im=Image()
 try:
  record=json.loads((PACKET/'FREEZE.json').read_text())
  if hashlib.sha256(im.data).hexdigest()!=SHA:raise ValueError('wrong115target')
  inputs,expected,seen=corpus(im)
  if hashlib.sha256(inputs).hexdigest()!=record['input_sha256'] or hashlib.sha256(expected).hexdigest()!=record['expected_sha256'] or sorted(seen)!=record['visited_addresses']:raise ValueError('frozen iterator stream changed')
  return inputs,expected
 finally:im.close()
