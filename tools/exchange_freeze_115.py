from pathlib import Path
import sys,hashlib,json
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import decimal_scaled_u64 as cpu
TARGET=ROOT/'artifacts/node/115/hl-node';SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
CTX=cpu.INPUT;OUTER=CTX+0x10000;OUT=OUTER+0x1000
CASES=[dict(start=0x2d25620,end=0x2d275c3,entry=0x2d25642,tag=0x10e8,extra=None,cold=(0x2d26226,0x2d2623f),sentinel=0x2d2569b,prepare=0x2d25712,skip=0x2d257bc),dict(start=0x5a07ec0,end=0x5a0871c,entry=0x5a07ee2,tag=0x10e8,extra=0x39c8,cold=(0x5a08563,0x5a0857c),sentinel=0x5a07f3b,prepare=0x5a07fce,skip=0x5a08351),dict(start=0x5a08720,end=0x5a08f7c,entry=0x5a08742,tag=0x1c58,extra=0x4538,cold=(0x5a08dc3,0x5a08ddc),sentinel=0x5a0879b,prepare=0x5a0882e,skip=0x5a08bb1)]
class Machine(cpu.Machine):
 def shift(self,kind,value,count,bits):
  if kind!=1:return super().shift(kind,value,count,bits)
  # Selected ROR64 immediates only; count3 is the actual corruption control.
  # Intel SDM Vol2B RCL/RCR/ROL/ROR: CF=MSB, OF undefined for count>1,
  # other modeled flags unchanged. No shared evaluator change.
  if bits!=64 or count not in (3,4) or value is None:raise ValueError('outside selected ROR64 domain')
  result=((value>>count)|(value<<(64-count)))&cpu.U64
  self.flags=[bool(result>>63),self.flags[1],self.flags[2],None]
  return result
 def bounds(self,a,n,write=False):
  c=self.case;roles=[(cpu.STACK,0x200),(OUT,8)]
  if not write:
   roles += [(CTX+c['tag'],4),(CTX+c['tag']+8,8),(OUTER,4)]
   if c['extra'] is not None:roles.append((CTX+c['extra'],8))
  if not any(lo<=a and a+n<=lo+size for lo,size in roles):raise ValueError('outside exchange prelude fields')
 def load(self,a,n):self.bounds(a,n);return super().load(a,n)
 def reload(self,r,a,n):self.bounds(a,n);return super().reload(r,a,n)
 def store(self,a,n,v):self.bounds(a,n,True);return super().store(a,n,v)
 def spill(self,a,r,n):self.bounds(a,n,True);return super().spill(a,r,n)
 def call(self,*args):raise ValueError('exchange prelude helper execution forbidden')
def put(m,a,v,n=8):
 for j,b in enumerate(v.to_bytes(n,'little')):m.mem[a+j]=b
def evaluate(image,which,outer_tag,tag,height,freeze_target,cadence):
 c=CASES[which]
 if c['extra'] is not None and not 1<=cadence<=cpu.U64:raise ValueError('positive secondary cadence required')
 m=Machine(image);m.case=c
 m.set_reg(cpu.RSI,CTX);m.set_reg(cpu.R15,height);m.set_reg(cpu.RSP,cpu.STACK)
 if which==0:m.set_reg(cpu.R13,OUTER);m.set_reg(cpu.R14,OUT)
 else:m.set_reg(cpu.R14,OUTER);m.set_reg(cpu.RBX,OUT)
 if tag is not None:put(m,CTX+c['tag'],tag,4)
 if freeze_target is not None:put(m,CTX+c['tag']+8,freeze_target)
 put(m,OUTER,outer_tag,4);put(m,OUT,0x55)
 if c['extra'] is not None:put(m,CTX+c['extra'],cadence)
 m.pc=c['entry']
 for _ in range(96):
  if m.pc in c['cold']:return 'X',m.seen
  if m.pc==c['sentinel']:
   if m.load(OUT,8)!=1<<63:raise ValueError('sentinel word qualification')
   return 'R',m.seen
  if m.pc==c['skip']:return 'K',m.seen
  if m.pc==c['prepare']:
   request=m.get(cpu.RBX if which==0 else cpu.RBP,8)
   freeze=m.load(cpu.STACK+0xd8,1) if which==0 else m.get(cpu.R13,8)
   if request not in (0,1) or freeze not in (0,1):raise ValueError('undefined active flag byte')
   return f'P\t{request}\t{freeze}',m.seen
  if not c['entry']<=m.pc<c['prepare']:raise ValueError('escaped exchange prelude')
  m.step()
 raise ValueError('instruction bound')
def model(which,outer_tag,tag,height,target,cadence):
 fixed=height%10000==0;past=tag==1 and target<height
 if not fixed and past:return 'X'
 if outer_tag==2:return 'R'
 if past:return 'X'
 equal=tag==1 and target==height;requested=fixed or equal
 if requested or which!=0 and height%cadence==0:return f'P\t{int(requested)}\t{int(equal)}'
 return 'K'
if __name__=='__main__':
 b=TARGET.read_bytes();assert hashlib.sha256(b).hexdigest()==SHA;i=cpu.Image(b)
 for which in range(3):
  for outer,tag,height,target,cadence in [(2,1,10000,9999,7),(0,1,10000,9999,7),(2,1,10001,10000,7),(0,0,1000,cpu.U64,1000),(0,1,10001,10001,7),(0,0,1<<32,cpu.U64,1<<32)]:
   a,_=evaluate(i,which,outer,tag,height,target,0 if which==0 else cadence);assert a==model(which,outer,tag,height,target,cadence),(which,outer,tag,height,target,a)
  a,_=evaluate(i,which,2,None,10000,None,1);assert a=='R'
 print('exchange periodic-first, outer-tag handoff, repeated past-target gate and dual-width secondary cadence PASS')
