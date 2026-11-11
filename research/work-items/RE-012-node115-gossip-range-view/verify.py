#!/usr/bin/env python3
"""Static evidence checks; never execute or emulate the captured target."""
import csv,hashlib
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86_const import X86_OP_IMM
from elf_index import unwind_index
from fde_extents import eh_frame_records
P=Path('research/work-items/RE-012-node115-gossip-range-view')
b=Path('artifacts/node/115/hl-node').read_bytes();assert hashlib.sha256(b).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
s,h=unwind_index(b);_,f=eh_frame_records(b,s);idx={(x['start'],x['fde']) for x in h};t=next(x for x in s if x['name']=='.text')
def read(a,n):
 assert t['address']<=a and a+n<=t['address']+t['size'];p=t['offset']+a-t['address'];return b[p:p+n]
bodies={0x4dce320:(0x4dce480,'7efde4e09efe7d39c34fbf61836b5310290659a24082d5e2928b477ae24c0855'),0x5a5dbc0:(0x5a5e281,'5d9b8d4faa0106747b55edfc16afc1e706f6f7a0aeb979b95803bab4e6523320')}
m=Cs(CS_ARCH_X86,CS_MODE_64);m.detail=True;ins={}
for a,(z,d) in bodies.items():
 assert any(x['start']==a and x['end']==z and (a,x['fde']) in idx for x in f)
 raw=read(a,z-a);assert hashlib.sha256(raw).hexdigest()==d
 seq=list(m.disasm(raw,a));assert sum(x.size for x in seq)==len(raw);ins.update({x.address:x for x in seq})
rows={}
with (P/'instructions.tsv').open() as fp:
 for x in csv.DictReader(fp,delimiter='\t'):
  a=int(x['va'],16);v=bytes.fromhex(x['bytes']);assert a not in rows and a in ins and ins[a].bytes==v and read(a,len(v))==v;rows[a]=v
pins={94757258: '4883c648', 94757262: '48896c2460', 94757267: '4889442468', 94757272: 'c644247000', 94757282: '488d542460', 94757287: 'e8740137ff', 81584945: '488b02', 81584948: '483b4208', 81584952: '7619', 81584954: '48c70300000000', 81584982: '4c8b2e', 81584988: '48f7d8', 81584991: '7135', 81585046: '0fb66a10', 81585060: 'e8074ca200', 81585074: '4084ed', 81585077: '742c', 81585123: 'e85848a200', 81585128: '4c39f8', 81585131: '0f8249ffffff', 81585137: '498b5618', 81585141: '4839d0', 81585144: '7774', 81585146: '4c29f8', 81585149: '750a', 81585151: '4531ff', 81585154: '4531ed', 81585157: '31c9', 81585161: '4d037e10', 81585167: '4d39ef', 81585170: '490f43cd', 81585174: '4929cf', 81585177: '4c89ea', 81585180: '4c29fa', 81585183: '4889c1', 81585186: '4829d1', 81585189: '7708', 81585191: '4c01f8', 81585196: '4989c5', 81585199: '498b4608', 81585203: '4b8d147f', 81585207: '488d14d0', 81585211: '4a8d346d00000000', 81585219: '4c01ee', 81585222: '488d34f0', 81585226: '488d0c49', 81585230: '488d0cc8', 81585234: '48c70301000000', 81585241: '48895308', 81585245: '48897310', 81585249: '48894318', 81585253: '48894b20'}
def check(r):
 for a,v in pins.items():assert r[a]==bytes.fromhex(v),hex(a)
check(rows)
for a,v in [(0x5a5e1a7,0x4dce320),(0x4dce338,0x4dce353),(0x4dce35f,0x4dce396),(0x4dce3a4,0x57f2fb0),(0x4dce3b5,0x4dce3e3),(0x4dce3e3,0x57f2c40),(0x4dce3eb,0x4dce33a),(0x4dce3f8,0x4dce46e),(0x4dce3fd,0x4dce409),(0x4dce425,0x4dce42f)]:assert ins[a].operands[0].type==X86_OP_IMM and ins[a].operands[0].imm==v
for cap,start,length,want in [(8,0,0,(0,0,0,0)),(8,2,3,(2,5,0,0)),(8,5,3,(5,8,0,0)),(8,6,4,(6,8,0,2))]:
 actual=(0,0,0,0) if length==0 else ((start,start+length,0,0) if start+length<=cap else (start,cap,0,length-(cap-start)));assert actual==want
for a in [0x5a5e198,0x5a5e1a7,0x4dce334,0x4dce35f,0x4dce3a4,0x4dce3b5,0x4dce3e3,0x4dce3eb,0x4dce3f8,0x4dce412,0x4dce425,0x4dce452,0x4dce465]:
 q=dict(rows);q[a]=q[a][:-1]+bytes([q[a][-1]^1])
 try:check(q)
 except AssertionError:pass
 else:raise AssertionError(hex(a))
print(f'{len(bodies)} FDEs, {len(rows)} instructions, {len(pins)} pins, 10 targets, 4 interval cases and 13 controls: OK')
