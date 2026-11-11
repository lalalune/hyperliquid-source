"""Actual ready-global/inline-tree selection and pre-call frontiers.

Synthetic runtime rows/guard/header are premises, never original global data.
The real split-ring search CALL/RET is evaluated; no initializer or diagnostic result is supplied.
"""
from pathlib import Path
import hashlib,json,sys
ROOT=Path(__file__).resolve().parents[3];PACKET=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'tools'))
import decimal_scaled_u64 as cpu
from elfview import View
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
TARGET=ROOT/'artifacts/node/115/hl-node';OWNER=(0x3c43150,0x3c432f4)
HELPER=(0x4556c50,0x4556d6b)
SPANS=[(0x3c43150,0x3c431ff),(0x3c43200,0x3c432d9),(0x3c432e7,0x3c432ee),HELPER]
FRONTIERS={0x3c432d9:'I',0x3c432ee:'M'}
OBJ=cpu.INPUT;NODES=OBJ+0x10000;OUT=OBJ+0x20000;GUARD=0x64fd8f0;GLOBAL=0x64fb8f0
RING=OBJ+0x30000
STACK=cpu.STACK;SP=STACK+0x88;FRAME=SP-0x38
class Image:
 slots={};note_target=None;panic_targets=set()
 def __init__(self):self.view=View(TARGET);self.data=self.view.b;self.cache={}
 def read_only(self,a):return None
 def fetch(self,a):
  if not any(lo<=a<hi for lo,hi in SPANS):raise ValueError('tier selector CFG escape '+hex(a))
  if a not in self.cache:self.cache[a]=cpu.decode(self.data,self.view.offset(a),a)
  return self.cache[a]
 def close(self):
  if self.data is not self.view.b:self.data.close()
  self.view.b.close();self.view.file.close()
class Machine(cpu.Machine):
 def __init__(self,im,nodes,capacity):
  super().__init__(im);self.calls=[];self.regions=[(OBJ,OBJ+0x60),(GUARD,GUARD+4),(NODES,NODES+nodes*0x400),(RING,RING+capacity*72),(OUT,OUT+32),(STACK,SP+8)]
 def bounds(self,a,n):
  if not any(lo<=a and a+n<=hi for lo,hi in self.regions):raise ValueError('tier footprint '+hex(a))
 def load(self,a,n):self.bounds(a,n);return super().load(a,n)
 def reload(self,r,a,n):self.bounds(a,n);return super().reload(r,a,n)
 def store(self,a,n,v):self.bounds(a,n);return super().store(a,n,v)
 def spill(self,a,r,n):self.bounds(a,n);return super().spill(a,r,n)
 def call(self,target,where):
  if target!=HELPER[0] or where!=0x3c4322c:raise ValueError('unqualified tier call')
  self.calls.append((where,target));return super().call(target,where)
def validate(row):
 key,desc,guard,retained,root,height,nodes,ring=row
 if not 0<=key<1<<32 or not 0<=guard<1<<32 or not 0<=desc<=cpu.U64 or not 0<=retained<=cpu.U64 or not 0<=height<=3 or len(nodes)>16 or not -1<=root<len(nodes):raise ValueError('invalid finite premise')
 for keys,children,values in nodes:
  if len(keys)>11 or len(values)!=len(keys) or keys!=sorted(set(keys)) or any(not 0<=k<1<<32 for k in keys) or len(children) not in [0,len(keys)+1] or any(not 0<=c<len(nodes) for c in children):raise ValueError('invalid node shape')
  if any(len(v)!=3 or any(not 0<=w<=cpu.U64 for w in v) for v in values):raise ValueError('invalid raw fields')
 def walk(i,h,path):
  if i in path:raise ValueError('cyclic premise')
  keys,children,_=nodes[i]
  if h:
   if len(children)!=len(keys)+1:raise ValueError('missing children')
   for child in children:walk(child,h-1,path|{i})
  elif children:raise ValueError('leaf has children')
 if root>=0:walk(root,height,set())
 if desc==1<<63:
  if ring is not None:raise ValueError('tree has ring storage')
 else:
  if not 0<=desc<=16 or ring is None:raise ValueError('unqualified ring capacity')
  head,keys,values,count=ring
  if len(keys)!=desc or len(values)!=desc or not 0<=count<=desc or not (0<=head<desc if desc else head==0):raise ValueError('invalid ring shape')
  if any(not 0<=k<1<<32 for k in keys) or any(len(v)!=3 or any(not 0<=w<=cpu.U64 for w in v) for v in values):raise ValueError('invalid ring fields')
  logical=[keys[(head+i)%desc] for i in range(count)]
  if logical!=sorted(set(logical)):raise ValueError('ring not strictly sorted')

def evaluate(im,row):
 validate(row);key,desc,guard,retained,root,height,nodes,ring=row;capacity=0 if desc==1<<63 else desc;m=Machine(im,len(nodes),capacity)
 for a,n,v in [(OBJ+0x30,8,desc),(OBJ+0x38,8,0 if root<0 else NODES+root*0x400),(OBJ+0x40,8,height),(OBJ+0x58,8,retained),(GUARD,4,guard),(SP,8,cpu.RETURN_MARK)]:m.store(a,n,v)
 if ring is not None:
  head,keys,values,count=ring;m.store(OBJ+0x38,8,RING);m.store(OBJ+0x40,8,head);m.store(OBJ+0x48,8,count)
  # Unused capacity stays unknown; the actual search must not read it.
  for i in range(count):
   j=(head+i)%capacity;base=RING+j*72;m.store(base,4,keys[j])
   for off,v in zip([16,24,64],values[j]):m.store(base+off,8,v)
 else:m.store(OBJ+0x48,8,0)
 for j,(keys,children,values) in enumerate(nodes):
  base=NODES+j*0x400;m.store(base+0x2f6,2,len(keys))
  for k,v in enumerate(keys):m.store(base+0x2c8+k*4,4,v)
  for k,fields in enumerate(values):
   for off,v in zip([8,16,56],fields):m.store(base+k*64+off,8,v)
  for k,c in enumerate(children):m.store(base+0x2f8+k*8,8,NODES+c*0x400)
 for off in range(0,32,8):m.store(OUT+off,8,0xa5a5a5a5a5a5a5a5)
 def incoming():return {a:v for a,v in m.mem.items() if any(lo<=a<hi for lo,hi in m.regions[:-2])}
 before=incoming();m.set_reg(cpu.RDI,OUT);m.set_reg(cpu.RSI,OBJ);m.set_reg(cpu.RDX,key);m.set_reg(cpu.RSP,SP);m.pc=OWNER[0]
 for _ in range(2500):
  if m.pc in FRONTIERS:
   kind=FRONTIERS[m.pc]
   if m.get(cpu.RSP,64)!=FRAME:raise ValueError('unexpected frame')
   if kind=='I':
    if [m.get(r,64) for r in [cpu.RDI,cpu.RSI,cpu.RDX,cpu.RCX,cpu.R8,cpu.R15]]!=[GUARD,1,FRAME+24,0x646ea10,0x646ea38,OUT] or m.load(FRAME+16,8)!=GLOBAL or m.load(FRAME+24,8)!=FRAME+16:raise ValueError('initializer actual args')
    result=['I',m.get(cpu.R14,64),m.get(cpu.RBX,64)]
   else:
    if m.get(cpu.RDI,64)!=0x64768c0:raise ValueError('actual diagnostic Location')
    result=['M']
   if any(m.load(OUT+off,8)!=0xa5a5a5a5a5a5a5a5 for off in range(0,32,8)):raise ValueError('pre-call output mutation')
   break
  try:m.step()
  except cpu.Done:
   if m.pc!=0x3c4329e or m.get(cpu.RSP,64)!=SP+8 or m.get(cpu.RAX,64)!=OUT:raise ValueError('not genuine tier RET')
   a,b,ptr,c=[m.load(OUT+off,8) for off in range(0,32,8)]
   if None in [a,b,ptr,c]:raise ValueError('unknown returned field')
   if GLOBAL<=ptr<GLOBAL+0x2000:origin=['G',(ptr-GLOBAL)//32,(ptr-GLOBAL)%32]
   elif RING<=ptr<RING+capacity*72:origin=['B',(ptr-RING)//72,(ptr-RING)%72]
   elif NODES<=ptr<NODES+len(nodes)*0x400:
    delta=ptr-NODES;origin=['T',delta//0x400,(delta%0x400)//64,delta%64]
   else:raise ValueError('unqualified returned pointer identity')
   result=['R',a,b,origin,c];break
 else:raise ValueError('tier step bound')
 if incoming()!=before:raise ValueError('tier mutated input/guard/nodes')
 if any(v is None for v in result):raise ValueError('unknown active result')
 return result,m.seen,m.calls
def fields(keys,node,seed):return [[seed^(0x11110000+node*256+j),seed^(0x22220000+node*256+j),seed^(0x33330000+node*256+j)] for j in range(len(keys))]
def leaf(keys,seed):return [[keys,[],fields(keys,0,seed)]]
def balanced(height,seed):
 nodes=[]
 def make(h,lo,hi):
  i=len(nodes);mid=(lo+hi)//2;nodes.append(None)
  children=[make(h-1,lo,mid-1),make(h-1,mid+1,hi)] if h else []
  nodes[i]=[[mid],children,fields([mid],i,seed)];return i
 make(height,50,(1<<32)-1);return nodes
def ring_storage(capacity,head,logical,seed):
 keys=[0]*capacity;values=[[0,0,0] for _ in range(capacity)]
 for i,key in enumerate(logical):
  j=(head+i)%capacity;keys[j]=key;values[j]=[seed^(0x11110000+j),seed^(0x22220000+j),seed^(0x33330000+j)]
 return [head,keys,values,len(logical)]
def stimuli():
 rows=[]
 for key in range(50):
  for guard in [0,1,(1<<32)-1]:
   for desc in [0,1<<63]:
    for retained in [0,17,cpu.U64]:rows.append([key,desc,guard,retained,-1,0,[],None if desc==1<<63 else ring_storage(0,0,[],0)])
 for seed in [0,0x12345678,cpu.U64]:
  graphs=[(leaf(keys,seed),0) for keys in [[],[50],[50,51,100],[49,50,99,(1<<31)-1,1<<31,(1<<32)-1],list(range(50,61))]]
  graphs.extend((balanced(h,seed),h) for h in [1,2,3])
  for nodes,h in graphs:
   probes={0,1,49,50,51,60,61,99,100,101,(1<<31)-1,1<<31,(1<<31)+1,(1<<32)-1}
   for keys,_,_ in nodes:
    for key in keys:probes.update(v for v in [key-1,key,key+1] if 0<=v<1<<32)
   for key in sorted(probes):rows.append([key,1<<63,0,17,0,h,nodes,None])
 for capacity in list(range(9))+[16]:
  heads=range(capacity) if 0<capacity<=8 else [0,1,7,15] if capacity else [0]
  counts=range(capacity+1) if capacity<=8 else [0,1,2,8,15,16]
  for head in heads:
   for count in counts:
    logical=[50+17*i for i in range(count)];ring=ring_storage(capacity,head,logical,(capacity<<48)|(head<<32)|(count<<16))
    probes={49,50,51,67,68,(1<<32)-1}
    if logical:
     for key in [logical[0],logical[len(logical)//2],logical[-1]]:probes.update([key-1,key,key+1])
    for key in sorted(probes):rows.append([key,capacity,0,cpu.U64,-1,0,[],ring])
 for capacity in [4,8]:
  for head in range(capacity):
   logical=[50,(1<<31)-1,1<<31,(1<<32)-1];ring=ring_storage(capacity,head,logical,cpu.U64)
   for key in [49,50,51,(1<<31)-2,(1<<31)-1,1<<31,(1<<31)+1,(1<<32)-2,(1<<32)-1]:rows.append([key,capacity,0,17,-1,0,[],ring])
 for key in [50,51,(1<<32)-1]:rows.append([key,1<<63,0,17,-1,0,[],None])
 return [json.loads(s) for s in dict.fromkeys(json.dumps(r,separators=(',',':')) for r in rows)]
def corpus(im):
 inputs=[];expected=[];seen=set();calls=set();call_rows=0
 for row in stimuli():
  result,trace,edges=evaluate(im,row);inputs.append(json.dumps(row,separators=(',',':'))+'\n');expected.append(json.dumps(result,separators=(',',':'))+'\n');seen|=trace;calls.update(edges);call_rows+=bool(edges)
 return ''.join(inputs).encode(),''.join(expected).encode(),seen,calls,call_rows
if __name__=='__main__':
 im=Image()
 try:
  if hashlib.sha256(im.data).hexdigest()!=SHA:raise ValueError('wrong target')
  for row in [[49,0,0,17,-1,0,[],ring_storage(0,0,[],0)],[50,1<<63,0,17,0,0,leaf([50,60],0),None],[60,4,0,17,-1,0,[],ring_storage(4,3,[50,60,70,80],0)],[70,4,0,17,-1,0,[],ring_storage(4,3,[50,60,70,80],0)],[51,4,0,17,-1,0,[],ring_storage(4,3,[50,60,70,80],0)]]:print(evaluate(im,row)[0])
 finally:im.close()
