#!/usr/bin/env python3
"""Static evidence checks; never execute or emulate the captured target."""
import csv,hashlib
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86_const import X86_OP_IMM
from elf_index import unwind_index
from fde_extents import eh_frame_records
P=Path('research/work-items/RE-012-node115-gossip-key-hash-input')
b=Path('artifacts/node/115/hl-node').read_bytes();assert hashlib.sha256(b).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
s,h=unwind_index(b);_,f=eh_frame_records(b,s);idx={(x['start'],x['fde']) for x in h};t=next(x for x in s if x['name']=='.text')
def read(a,n):
 assert t['address']<=a and a+n<=t['address']+t['size'];p=t['offset']+a-t['address'];return b[p:p+n]
bodies={0x4e527a0:(0x4e52934,'a24d45c3929073111c464b5f866881d1420a7581994a1dc51726c5dd4223733c'),0x4ef8bb0:(0x4ef8e13,'93869e1b32af1a162e5ee705c0fbb71f3fbc22c773b7d8df3418ea9702ca1883')}
m=Cs(CS_ARCH_X86,CS_MODE_64);m.detail=True;ins={}
for a,(z,d) in bodies.items():
 assert any(x['start']==a and x['end']==z and (a,x['fde']) in idx for x in f)
 raw=read(a,z-a);assert hashlib.sha256(raw).hexdigest()==d
 seq=list(m.disasm(raw,a));assert sum(x.size for x in seq)==len(raw);ins.update({x.address:x for x in seq})
rows={}
with (P/'instructions.tsv').open() as fp:
 for x in csv.DictReader(fp,delimiter='\t'):
  a=int(x['va'],16);v=bytes.fromhex(x['bytes']);assert a not in rows and a in ins and ins[a].bytes==v and read(a,len(v))==v;rows[a]=v
pins={82126829: '440fb636', 82126833: '4c893424', 82126837: '488d7c2410', 82126842: '4889e6', 82126845: 'ba08000000', 82126850: 'e8c9c20700', 82126855: '4983fe01', 82126859: '7519', 82126861: 'f30f6f4301', 82126866: '660f7f0424', 82126879: 'ba10000000', 82126884: 'eb13', 82126886: '8b4301', 82126889: '890424', 82126900: 'ba04000000', 82126905: 'e892c20700', 82807739: '4889f3', 82807749: '4c89ff', 82807752: 'e8d39bf5ff', 82807800: '440fb60b', 82807804: '41f6c101', 82807808: '0f84c0000000', 82807814: '4c8b5309', 82807818: '4c8b5b01', 82807886: '443a4c0aef', 82807891: '751c', 82807896: '488b69f0', 82807900: '4c31dd', 82807903: '4c8b79f8', 82807907: '4d31d7', 82807912: '4909ef', 82807915: '0f8459010000', 82808006: '448b5301', 82808070: '463a4c2aef', 82808075: '750f', 82808082: '453b55f0', 82808086: '0f84ae000000'}
def check(r):
 for a,v in pins.items():assert r[a]==bytes.fromhex(v),hex(a)
check(rows)
for a,v in [(0x4e52802,0x4ecead0),(0x4e5280b,0x4e52826),(0x4e52824,0x4e52839),(0x4e52839,0x4ecead0),(0x4ef8bc8,0x4e527a0),(0x4ef8bd2,0x4ef8ddb),(0x4ef8c00,0x4ef8cc6),(0x4ef8c53,0x4ef8c71),(0x4ef8c6b,0x4ef8dca),(0x4ef8d0b,0x4ef8d1c),(0x4ef8d16,0x4ef8dca)]:assert ins[a].operands[0].type==X86_OP_IMM and ins[a].operands[0].imm==v
for tag,hashwidth,comparewidth in [(0,4,4),(1,16,16),(2,4,4),(3,4,16),(255,4,16)]:assert (16 if tag==1 else 4)==hashwidth and (16 if tag&1 else 4)==comparewidth
for a in [0x4e527ed,0x4e527fd,0x4e52802,0x4e52807,0x4e5281f,0x4e52834,0x4e52839,0x4ef8bc8,0x4ef8bfc,0x4ef8c06,0x4ef8c4e,0x4ef8cc6,0x4ef8d12]:
 q=dict(rows);q[a]=q[a][:-1]+bytes([q[a][-1]^1])
 try:check(q)
 except AssertionError:pass
 else:raise AssertionError(hex(a))
print(f'{len(bodies)} FDEs, {len(rows)} instructions, {len(pins)} pins, 11 targets, 5 tag cases and 13 controls: OK')
