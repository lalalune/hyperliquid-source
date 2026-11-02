import hashlib,json,sys,struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import decimal_scaled_u64 as cpu
TARGET=ROOT/'artifacts/node/115/hl-node';SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
STATE=cpu.INPUT;LOW=STATE+0x1000;TARGET_WORD=LOW+8
class Machine(cpu.Machine):
 def bounds(self,a,n,write=False):
  roles=[(STATE+0x288,16),(cpu.STACK+8,8)]
  if not write:roles.append((LOW,16))
  if not any(lo<=a and a+n<=lo+size for lo,size in roles):raise ValueError('unqualified bootstrap115 memory')
 def load(self,a,n):self.bounds(a,n);return super().load(a,n)
 def reload(self,r,a,n):self.bounds(a,n);return super().reload(r,a,n)
 def store(self,a,n,v):self.bounds(a,n,True);return super().store(a,n,v)
 def spill(self,a,r,n):self.bounds(a,n,True);return super().spill(a,r,n)
 def call(self,*args):raise ValueError('no bootstrap115 helper execution')
def put(m,a,v):
 for j,b in enumerate(v.to_bytes(8,'little')):m.mem[a+j]=b
def evaluate(image,lower,target):
 m=Machine(image);m.set_reg(cpu.RBX,STATE);m.set_reg(cpu.R14,LOW);m.set_reg(cpu.R15,TARGET_WORD);m.set_reg(cpu.RSP,cpu.STACK);m.set_reg(cpu.RBP,0x115)
 put(m,LOW,lower);put(m,TARGET_WORD,target);m.pc=0x5a88391
 for _ in range(48):
  if m.pc==0x5a88d17:return 'S',m.seen
  if m.pc==0x5a883c4:
   assert m.load(STATE+0x288,8)==lower
   return 'R',m.seen
  if m.pc==0x5a83054:return f'W\t{m.load(STATE+0x288,8)}\t{m.load(STATE+0x290,8)}',m.seen
  if not (0x5a88391<=m.pc<0x5a883c4 or 0x5a83026<=m.pc<0x5a83054):raise ValueError('bootstrap115 escaped')
  m.step()
 raise ValueError('instruction bound')
def model(lower,target):
 if target>=lower and target-lower>30000:return 'S'
 if lower>target:return 'R'
 return f'W\t{lower}\t{min(target,lower+99,cpu.U64)}'
