#!/usr/bin/env python3
"""Statically validate selected #115 compare/move network; never execute target bytes."""
import csv
import hashlib
import itertools
from pathlib import Path
import re
import subprocess
import struct
import sys
sys.path.insert(0,'tools')
from elf_index import unwind_index
from fde_extents import eh_frame_records

ROOT=Path(__file__).resolve().parent
binary=Path('artifacts/node/115/hl-node')
data=binary.read_bytes()
assert hashlib.sha256(data).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
sections,header=unwind_index(data)
_,fdes=eh_frame_records(data,sections)
assert any(x['start']==0x14c6420 and x['end']==0x14c6b35 and any(y['start']==x['start'] and y['fde']==x['fde'] for y in header) for x in fdes)
text=next(x for x in sections if x['name']=='.text')
context=list(csv.DictReader((ROOT/'context.tsv').open(),delimiter='\t'))
indexed={(x['start'],x['fde']) for x in header}
bounds={(x['start'],x['end']) for x in fdes if (x['start'],x['fde']) in indexed}
ctx={}
for row in context:
 start,end,a=(int(row[k],16) for k in ('fde_start','fde_end','va'))
 raw=bytes.fromhex(row['bytes']); off=text['offset']+a-text['address']
 assert (start,end) in bounds and start<=a<a+len(raw)<=end and data[off:off+len(raw)]==raw
 assert a not in ctx
 ctx[a]=raw
def target(a):
 raw=ctx[a]; return a+len(raw)+struct.unpack_from('<i',raw,len(raw)-4)[0]
assert target(0x1550703)==0x14c6420
assert target(0x14c6494)==0x14c67d0
assert target(0x14c67bc)==0x14c699c
assert ctx[0x14c6490]==bytes.fromhex('4883fa0c')
assert ctx[0x14c6494][:2]==bytes.fromhex('0f86')
rows=list(csv.DictReader((ROOT/'instructions.tsv').open(),delimiter='\t'))
assert len(rows)==220
for r in rows:
 a=int(r['va'],16); b=bytes.fromhex(r['bytes']); off=text['offset']+a-text['address']
 assert 0x14c6420<=a<a+len(b)<=0x14c6b35 and data[off:off+len(b)]==b
# Decode independently rather than trusting the recorded mnemonic column.
out=subprocess.check_output(['objdump','-d','-M','intel','--insn-width=16','--start-address=0x14c649a','--stop-address=0x14c67bc',str(binary)],text=True)
ins=[]
for line in out.splitlines():
 m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)\s*(\S.*)$',line)
 if m: ins.append((int(m[1],16),''.join(m[2].split()),m[3].split('#')[0].strip()))
assert [(a,b) for a,b,_ in ins]==[(int(r['va'],16),r['bytes']) for r in rows]
MASK=(1<<64)-1
def simulate(values, mutant=False):
 regs={'r8':0x1000,'rsp':0x2000,'rdx':13}
 mem={0x1000+8*i:v for i,v in enumerate(values)}
 mem.update({0x2028:1,0x2030:2,0x2038:26})
 def read(x):
  x=x.strip().replace('QWORD PTR ','')
  m=re.fullmatch(r'\[(r\w+)(?:\+0x([0-9a-f]+))?\]',x)
  if m:return mem[regs[m[1]]+int(m[2] or '0',16)]
  if x.startswith('0x'):return int(x,16)
  return regs[x]
 def write(x,v):
  x=x.strip().replace('QWORD PTR ',''); v &= MASK
  m=re.fullmatch(r'\[(r\w+)(?:\+0x([0-9a-f]+))?\]',x)
  if m:mem[regs[m[1]]+int(m[2] or '0',16)]=v
  elif x=='ecx':regs['rcx']=v&0xffffffff
  else:regs[x]=v
 flags=None
 for address,raw_hex,assembly in ins:
  op,args=assembly.split(None,1); a,b=map(str.strip,args.split(','))
  if op=='cmp':flags=(read(a),read(b))
  elif op=='mov':write(a,read(b))
  elif op in ('cmova','cmovae','cmovb'):
   assert flags is not None
   x,y=flags
   condition={'cmova':x>y,'cmovae':x>=y,'cmovb':x<y}[op]
   if mutant and address==0x14c64ab: condition=not condition
   if condition:write(a,read(b))
  else:raise AssertionError(assembly)
 return tuple(mem[0x1000+8*i] for i in range(13))
for v in itertools.product((0,1),repeat=13):assert simulate(v)==tuple(sorted(v))
for v in ((2**64-1,0,4,2**63,4,2,1,3,5,7,6,8,9),tuple(range(13,0,-1))):
 assert simulate(v)==tuple(sorted(v))
assert any(simulate(v,mutant=True)!=tuple(sorted(v)) for v in itertools.product((0,1),repeat=13))
print('220 authenticated spans; 8192 binary inputs and unsigned boundary examples pass')
