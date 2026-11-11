#!/usr/bin/env python3
"""Static evidence checks; never execute or emulate the captured target."""
import csv,hashlib
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86_const import X86_OP_IMM
from elf_index import unwind_index
from fde_extents import eh_frame_records
P=Path('research/work-items/RE-012-node115-gossip-range-bounds')
b=Path('artifacts/node/115/hl-node').read_bytes();assert hashlib.sha256(b).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
s,h=unwind_index(b);_,f=eh_frame_records(b,s);idx={(x['start'],x['fde']) for x in h};t=next(x for x in s if x['name']=='.text')
def read(a,n):
 assert t['address']<=a and a+n<=t['address']+t['size'];p=t['offset']+a-t['address'];return b[p:p+n]
bodies={0x4dce320:(0x4dce480,'7efde4e09efe7d39c34fbf61836b5310290659a24082d5e2928b477ae24c0855'),0x57f2c40:(0x57f2d24,'0a2e00e8e9db480385469dfb74928d8aef9ff2b16284f7fb5e7e0e657bd0d121'),0x57f2fb0:(0x57f3092,'60d2918dc76a3fa15e4cac599601ec527cf97e854518885355095fd4e9cbd108')}
m=Cs(CS_ARCH_X86,CS_MODE_64);m.detail=True;ins={}
for a,(z,d) in bodies.items():
 assert any(x['start']==a and x['end']==z and (a,x['fde']) in idx for x in f)
 raw=read(a,z-a);assert hashlib.sha256(raw).hexdigest()==d
 seq=list(m.disasm(raw,a));assert sum(x.size for x in seq)==len(raw);ins.update({x.address:x for x in seq})
rows={}
with (P/'instructions.tsv').open() as fp:
 for x in csv.DictReader(fp,delimiter='\t'):
  a=int(x['va'],16);v=bytes.fromhex(x['bytes']);assert a not in rows and a in ins and ins[a].bytes==v and read(a,len(v))==v;rows[a]=v
pins={81584945: '488b02', 81584948: '483b4208', 81584952: '7619', 81585046: '0fb66a10', 81585060: 'e8074ca200', 81585074: '4084ed', 81585077: '742c', 81585123: 'e85848a200', 81585128: '4c39f8', 81585131: '0f8249ffffff', 92220480: '488b5718', 92220484: '4885d2', 92220487: '743a', 92220489: '488b0f', 92220492: '4c8b4710', 92220498: '4939c8', 92220501: '480f43c1', 92220508: '4c29c1', 92220514: '4829c8', 92220517: '7623', 92220554: '4c01c2', 92220560: '4b8d1440', 92220564: '48c1e203', 92220568: '48035708', 92220572: '4c29c1', 92220578: '74dc', 92220592: '4889c7', 92220598: '49d1e8', 92220601: '4c01c0', 92220604: '4c8d0c40', 92220608: '4a3934ca', 92220612: '480f47c7', 92220616: '4c29c1', 92220623: '77df', 92220625: '488d0c40', 92220629: '483b34ca', 92220633: '4883d8ff', 92221360: '488b5718', 92221364: '4885d2', 92221367: '7434', 92221369: '488b0f', 92221372: '4c8b4710', 92221378: '4939c8', 92221381: '480f43c1', 92221388: '4c29c1', 92221394: '4829c8', 92221397: '761d', 92221428: '4c01c2', 92221434: '4b8d1440', 92221438: '48c1e203', 92221442: '48035708', 92221446: '4c29c1', 92221452: '744b', 92221472: '4889cf', 92221475: '48d1ef', 92221478: '4c8d0407', 92221482: '4f8d0c40', 92221486: '4a3934ca', 92221490: '490f42c0', 92221494: '4829f9', 92221501: '77e1', 92221503: '488d0c40', 92221507: '483934ca', 92221511: '4883d000'}
def check(r):
 for a,v in pins.items():assert r[a]==bytes.fromhex(v),hex(a)
check(rows)
for a,v in [(0x4dce338,0x4dce353),(0x4dce3a4,0x57f2fb0),(0x4dce3b5,0x4dce3e3),(0x4dce3e3,0x57f2c40),(0x4dce3eb,0x4dce33a),(0x57f2c47,0x57f2c83),(0x57f2c65,0x57f2c8a),(0x57f2ccf,0x57f2cb0),(0x57f2fb7,0x57f2fed),(0x57f2fd5,0x57f2ff4),(0x57f303d,0x57f3020)]:assert ins[a].operands[0].type==X86_OP_IMM and ins[a].operands[0].imm==v
for keys,a,b,i,j in [([],1,2,0,0),([1,2,2,3],2,2,1,3),([1,2,3],0,9,0,3),([1,1,1],2,2,3,3),([0,0xffffffffffffffff],0,0xffffffffffffffff,0,2)]:
 assert sum(k<a for k in keys)==i and sum(k<=b for k in keys)==j and keys[i:j]==[k for k in keys if a<=k<=b]
for a in [0x4dce3a4,0x4dce3e3,0x57f2c65,0x57f2c94,0x57f2cc0,0x57f2cc4,0x57f2cd5,0x57f2cd9,0x57f2fd5,0x57f2ffe,0x57f302e,0x57f3032,0x57f3043,0x57f3047]:
 q=dict(rows);q[a]=q[a][:-1]+bytes([q[a][-1]^1])
 try:check(q)
 except AssertionError:pass
 else:raise AssertionError(hex(a))
print(f'{len(bodies)} FDEs, {len(rows)} instructions, {len(pins)} pins, 11 targets, 5 sorted cases and 14 controls: OK')
