"""Actual entry-to-first-call/RET user admission, preserving unknown imports."""
from pathlib import Path
import hashlib,itertools,json,sys
ROOT=Path(__file__).resolve().parents[3];PACKET=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'tools'))
import decimal_scaled_u64 as cpu
from elfview import View
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301';TARGET=ROOT/'artifacts/node/115/hl-node';OWNER=(0x2c77640,0x2c77ba5)
OUT=cpu.INPUT+0x100;STATE=cpu.INPUT+0x1000;DESC=cpu.INPUT+0x4000;IDENT=cpu.INPUT+0x5000;NODES=cpu.INPUT+0x8000;SP=cpu.STACK;FRAME=SP-0x198;MASK=(1<<64)-1;LIMIT=0x0ccccccccccccccc;IMPORT=0x64dfb50
STOPS={0x2c7770d:'I',0x2c77831:'C',0x2c77996:'B',0x2c77a08:'O'}
class Image:
 slots={};note_target=None;panic_targets=set()
 def __init__(self):self.view=View(TARGET);self.data=self.view.b;self.cache={}
 def read_only(self,a):return None # Loader-populated memcmp slot deliberately remains unknown.
 def fetch(self,a):
  if not OWNER[0]<=a<OWNER[1]:raise ValueError('user-prefix CFG escape')
  if a not in self.cache:self.cache[a]=cpu.decode(self.data,self.view.offset(a),a)
  return self.cache[a]
 def close(self):
  if self.data is not self.view.b:self.data.close()
  self.view.b.close();self.view.file.close()
class Machine(cpu.Machine):
 def __init__(self,im,nodes):
  super().__init__(im);self.record=False;self.reads=set();self.writes=set();self.regions=[(OUT,OUT+16),(DESC,DESC+99),(IDENT,IDENT+20),(SP-0x1a0,SP+8),(IMPORT,IMPORT+8),*[(STATE+a,STATE+a+n) for a,n in [(0x10e4,1),(0xb9a,1),(0x1090,8),(0x80,1),(0x60,12),(0x1060,8),(0x1068,8)]],*[(NODES+0x200*i+a,NODES+0x200*i+a+n) for i in range(nodes) for a,n in [(8,20),(0xe6,2),(0xe8,8)]]]
 def bounds(self,a,n):
  if not any(lo<=a and a+n<=hi for lo,hi in self.regions):raise ValueError('user-prefix undeclared memory '+hex(a))
 def load(self,a,n):
  self.bounds(a,n)
  if self.record:self.reads.update(range(a,a+n))
  return super().load(a,n)
 def reload(self,r,a,n):
  self.bounds(a,n)
  if self.record:self.reads.update(range(a,a+n))
  return super().reload(r,a,n)
 def writable(self,a,n):
  self.bounds(a,n)
  if not (OUT<=a and a+n<=OUT+16 or SP-0x1a0<=a and a+n<=SP+8):raise ValueError('user-prefix input write')
  if self.record:self.writes.update(range(a,a+n))
 def store(self,a,n,v):
  if self.record:self.writable(a,n)
  return super().store(a,n,v)
 def spill(self,a,r,n):
  if self.record:self.writable(a,n)
  return super().spill(a,r,n)
 def call(self,*args):raise ValueError('opaque call was executed, not a prefix result')
def memory_hex(m,a,n):
 values=[m.mem.get(a+i) for i in range(n)]
 if None in values:raise ValueError('unknown normalized byte')
 return bytes(values).hex()
def node_origin(value,count):
 if value is None or value<NODES or (value-NODES)%0x200 or (value-NODES)//0x200>=count:raise ValueError('unknown node origin')
 return (value-NODES)//0x200

def evaluate(im,row):
 desc,active,mode,budget,aux,height,counts,identity,context,seed=row;desc=bytes.fromhex(desc);identity=bytes.fromhex(identity);context=bytes.fromhex(context)
 if len(desc)!=99 or len(identity)!=20 or len(context)!=12 or any(not 0<=v<=255 for v in [active,mode,aux,seed]) or any(not 0<=v<=MASK for v in [budget,height]) or len(counts)>4 or any(not 0<=c<=65535 for c in counts):raise ValueError('finite raw-prefix input')
 m=Machine(im,len(counts))
 for a,data in [(DESC,desc),(IDENT,identity),(STATE+0x60,context),(OUT,bytes([seed])*16)]:
  for i,value in enumerate(data):m.mem[a+i]=value
 for off,size,value in [(0x10e4,1,active),(0xb9a,1,mode),(0x1090,8,budget),(0x80,1,aux),(0x1060,8,NODES if counts else 0),(0x1068,8,height)]:m.store(STATE+off,size,value)
 for i,count in enumerate(counts):m.store(NODES+0x200*i+0xe6,2,count);m.store(NODES+0x200*i+0xe8,8,NODES+0x200*(i+1) if i+1<len(counts) else 0)
 m.store(SP,8,cpu.RETURN_MARK)
 for reg,value in [(cpu.RDI,OUT),(cpu.RSI,STATE),(cpu.RDX,IDENT),(cpu.RCX,DESC),(cpu.RSP,SP)]:m.set_reg(reg,value)
 m.record=True;m.pc=OWNER[0];kind=None
 try:
  while m.pc not in STOPS:
   m.steps+=1
   if m.steps>10000:raise ValueError('prefix failed to terminate')
   m.step()
  kind=STOPS[m.pc]
 except cpu.Done:
  if m.pc!=0x2c7768d or m.get(cpu.RSP,64)!=SP+8 or m.get(cpu.RAX,64)!=OUT:raise ValueError('not genuine user-prefix RET')
  kind='R'
 m.record=False
 if kind!='R' and m.get(cpu.RSP,64)!=FRAME:raise ValueError('wrong prefix frame')
 if kind=='R':args=[]
 elif kind=='I':
  if (m.get(cpu.RDI,64),m.get(cpu.RSI,64),m.get(cpu.RDX,64))!=(FRAME+0x50,STATE+0xd88,FRAME+0xf0):raise ValueError('identity call argument origins')
  args=[m.get(cpu.R13,64),m.get(cpu.RBP,64),m.get(cpu.RBX,64),memory_hex(m,FRAME+0x30,20),memory_hex(m,FRAME+0xf0,20)]
 elif kind=='C':
  node=node_origin(m.load(FRAME+0x18,8),len(counts))
  if (m.get(cpu.RDI,64),m.get(cpu.RSI,64),m.get(cpu.RDX,64))!=(IDENT,NODES+0x200*node+8,20) or m.get(cpu.R15,64) is not None or m.get(cpu.R12,64)!=MASK:raise ValueError('memcmp frontier or unknown import binding changed')
  args=[m.get(cpu.R13,64),node,m.load(FRAME+0x28,8),m.get(cpu.RBP,64)]
 elif kind=='B':
  if m.get(cpu.RDI,64)!=FRAME+0x50 or m.load(FRAME+0x50,2)!=0x10a:raise ValueError('budget call argument origins')
  args=[m.get(cpu.R13,64),m.get(cpu.RBP,64),m.get(cpu.RBX,64),m.get(cpu.RDX,64)]
 elif kind=='O':
  if (m.get(cpu.RDI,64),m.get(cpu.RSI,64))!=(FRAME+0xf0,DESC):raise ValueError('operation call argument origins')
  args=[m.get(cpu.R13,64),m.get(cpu.RBP,64),memory_hex(m,FRAME+0xe0,12)]
 if None in args:raise ValueError('unknown logical frontier field')
 return [kind,memory_hex(m,OUT,16),args],m.seen

def stimulus(raw=0,active=1,mode=0,op=0,identity_bit=0,guard=0,amount=0,budget=0,aux=0,height=0,counts=(),seed=0xa5,pattern=7):
 desc=bytearray([0x6d]*99);desc[:8]=raw.to_bytes(8,'little');desc[0x48]=op;desc[0x4e]=identity_bit;desc[0x4f:0x63]=bytes((pattern+17*i)%256 for i in range(20));desc[0x50]=guard;desc[0x58:0x60]=amount.to_bytes(8,'little')
 identity=bytes((pattern*3+11*i)%256 for i in range(20));context=bytes((pattern*5+19*i)%256 for i in range(12));return [desc.hex(),active,mode,budget,aux,height,list(counts),identity.hex(),context.hex(),seed]
def control_inputs():
 return [stimulus(**opts) for opts in [
  {'raw':(1<<63)+2,'active':0},
  {'raw':1<<63,'mode':0,'op':0},
  {'active':0},
  {'raw':1<<63,'mode':2,'identity_bit':1},
  {'raw':1<<63,'mode':0,'op':1},
  {'mode':1,'amount':LIMIT},
  {'mode':1,'amount':MASK},
  {'mode':1,'amount':1,'budget':MASK,'guard':1},
  {'mode':1,'amount':1,'guard':1},
  {'mode':1,'amount':1,'aux':0},
  {'active':0,'height':1,'counts':[0,1]},
  {'active':0,'height':0,'counts':[256]},
  {'raw':1<<63,'mode':2,'pattern':37},
  {'raw':1<<63,'identity_bit':1,'pattern':37},
  {'raw':(1<<63)+1},
 ]]
def stimuli():
 rows=[]
 for raw,active,mode,op,identity_bit,amount,budget,guard,aux,seed in itertools.product([0,1<<63,(1<<63)+1],[0,1],[0,1],[0,1],[0,1],[0,1,LIMIT-1,LIMIT,LIMIT+1,MASK],[0,MASK],[0,1],[0,1],[0,0xa5]):rows.append(stimulus(raw,active,mode,op,identity_bit,guard,amount,budget,aux,seed=seed))
 for value in range(256):
  rows.append(stimulus(active=value))
  rows.append(stimulus(mode=value))
  rows.append(stimulus(raw=1<<63,mode=0,op=value))
  rows.append(stimulus(raw=1<<63,identity_bit=value,mode=2,op=0xff))
  rows.append(stimulus(mode=1,amount=1,guard=value))
  rows.append(stimulus(mode=1,amount=1,aux=value))
 rawwords=[0,1,(1<<63)-1,1<<63,(1<<63)+1,(1<<63)+2,MASK-1,MASK]
 for raw,height,count,seed in itertools.product(rawwords,[0,1,2,3],[0,1,2,11,255,256,65535],[0,0xff]):
  rows.append(stimulus(raw=raw,active=0,height=height,counts=[0]*height+[count],seed=seed))
 for raw in rawwords:rows.append(stimulus(raw=raw,active=0,height=MASK,counts=[1]))
 for at in range(20):
  row=stimulus(raw=1<<63,identity_bit=1,mode=0xff,pattern=37);identity=bytearray.fromhex(row[7]);identity[at]^=0x80;row[7]=identity.hex();rows.append(row)
 for at in range(12):
  row=stimulus(raw=1<<63,mode=2,pattern=37);context=bytearray.fromhex(row[8]);context[at]^=0x80;row[8]=context.hex();rows.append(row)
 rows.extend(control_inputs())
 return list({json.dumps(x,separators=(',',':')):x for x in rows}.values())
def corpus(im):
 inputs=[];expected=[];seen=set();frontiers={}
 for row in stimuli():
  result,trace=evaluate(im,row);seen|=trace;frontiers[result[0]]=frontiers.get(result[0],0)+1;inputs.append(json.dumps(row,separators=(',',':'))+'\n');expected.append(json.dumps(result,separators=(',',':'))+'\n')
 return ''.join(inputs).encode(),''.join(expected).encode(),seen,frontiers
