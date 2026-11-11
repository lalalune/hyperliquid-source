#!/usr/bin/env python3
"""Static evidence checks; never execute or emulate the captured target."""
import csv,hashlib
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86_const import X86_OP_IMM
from elf_index import unwind_index
from fde_extents import eh_frame_records
P=Path('research/work-items/RE-012-node115-gossip-counter-key')
b=Path('artifacts/node/115/hl-node').read_bytes();assert hashlib.sha256(b).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
s,h=unwind_index(b);_,f=eh_frame_records(b,s);idx={(x['start'],x['fde']) for x in h};t=next(x for x in s if x['name']=='.text')
def read(a,n):
 assert t['address']<=a and a+n<=t['address']+t['size'];p=t['offset']+a-t['address'];return b[p:p+n]
bodies={0x5a5dbc0:(0x5a5e281,'5d9b8d4faa0106747b55edfc16afc1e706f6f7a0aeb979b95803bab4e6523320'),0x59db3a0:(0x59db6f4,'669c5b78a31be6b0f7a03396b8ec6f72effc257f87ed4d03027a8d9759be034e'),0x4ef8bb0:(0x4ef8e13,'93869e1b32af1a162e5ee705c0fbb71f3fbc22c773b7d8df3418ea9702ca1883')}
m=Cs(CS_ARCH_X86,CS_MODE_64);m.detail=True;ins={}
for a,(z,d) in bodies.items():
 assert any(x['start']==a and x['end']==z and (a,x['fde']) in idx for x in f)
 raw=read(a,z-a);assert hashlib.sha256(raw).hexdigest()==d
 seq=list(m.disasm(raw,a));assert sum(x.size for x in seq)==len(raw);ins.update({x.address:x for x in seq})
rows={}
with (P/'instructions.tsv').open() as fp:
 for x in csv.DictReader(fp,delimiter='\t'):
  a=int(x['va'],16);v=bytes.fromhex(x['bytes']);assert a not in rows and a in ins and ins[a].bytes==v and read(a,len(v))==v;rows[a]=v
pins={94755849: '89d6', 94755851: '4189d4', 94755854: 'e8cdeb54ff', 94755859: '4489e1', 94756097: '894c2461', 94756101: 'c644246000', 94756396: '488d742460', 94756401: 'b910270000', 94756412: 'e85fd5f7ff', 94221236: '4889f3', 94221865: '4d397df0', 94221869: '7678', 94221871: '498dbea0010000', 94221878: '0fb64310', 94221882: '88442410', 94221886: '660f1003', 94221890: '660f290424', 94221895: '4889e6', 94221898: 'e861d551ff', 94221903: '89c1', 94221905: 'b001', 94221907: '84c9', 94221909: '7552', 82807739: '4889f3', 82807752: 'e8d39bf5ff', 82807757: '49837e1000', 82807762: '0f8403020000', 82807800: '440fb60b', 82807804: '41f6c101', 82807808: '0f84c0000000', 82808006: '448b5301', 82808032: '660f74d8', 82808036: '66440fd7e3', 82808046: 'f3410fbccc', 82808070: '463a4c2aef', 82808075: '750f', 82808080: 'b101', 82808082: '453b55f0', 82808086: '0f84ae000000', 82808170: '420fb60402', 82808177: '0f8985000000', 82808192: '42883402', 82808196: '4088740a10', 82808217: 'f3410f6f4e10', 82808227: 'f3410f7f4e10', 82808246: '0fb64b10', 82808250: '884c02ff', 82808254: 'f30f6f03', 82808258: 'f30f7f4402ef', 82808264: '31c9', 82808266: '89c8'}
def check(r):
 for a,v in pins.items():assert r[a]==bytes.fromhex(v),hex(a)
check(rows)
for a,v in [(0x5a5dc0e,0x4fac7e0),(0x5a5de3c,0x59db3a0),(0x59db62d,0x59db6a7),(0x59db64a,0x4ef8bb0),(0x59db655,0x59db6a9),(0x4ef8bc8,0x4e527a0),(0x4ef8bd2,0x4ef8ddb),(0x4ef8c00,0x4ef8cc6),(0x4ef8d0b,0x4ef8d1c),(0x4ef8d16,0x4ef8dca),(0x4ef8d71,0x4ef8dfc)]:assert ins[a].operands[0].type==X86_OP_IMM and ins[a].operands[0].imm==v
for a in [0x5a5dc0b,0x5a5dd01,0x5a5dd05,0x5a5de3c,0x59db62d,0x59db63e,0x59db64a,0x4ef8bfc,0x4ef8cc6,0x4ef8d06,0x4ef8d12,0x4ef8d16,0x4ef8dc2,0x4ef8dc8]:
 q=dict(rows);q[a]=q[a][:-1]+bytes([q[a][-1]^1])
 try:check(q)
 except AssertionError:pass
 else:raise AssertionError(hex(a))
print(f'{len(bodies)} FDEs, {len(rows)} instructions, {len(pins)} pins, 11 targets and 14 controls: OK')
