#!/usr/bin/env python3
"""Static evidence checks; never execute or emulate the captured target."""
import csv,hashlib
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86_const import X86_OP_IMM
from elf_index import unwind_index
from fde_extents import eh_frame_records
P=Path('research/work-items/RE-012-node115-gossip-cache-range')
b=Path('artifacts/node/115/hl-node').read_bytes();assert hashlib.sha256(b).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
s,h=unwind_index(b);_,f=eh_frame_records(b,s);idx={(x['start'],x['fde']) for x in h};t=next(x for x in s if x['name']=='.text')
def read(a,n):
 assert t['address']<=a and a+n<=t['address']+t['size'];p=t['offset']+a-t['address'];return b[p:p+n]
a,z,d=0x5a5dbc0,0x5a5e281,'5d9b8d4faa0106747b55edfc16afc1e706f6f7a0aeb979b95803bab4e6523320'
assert any(x['start']==a and x['end']==z and (a,x['fde']) in idx for x in f)
raw=read(a,z-a);assert hashlib.sha256(raw).hexdigest()==d
m=Cs(CS_ARCH_X86,CS_MODE_64);m.detail=True;seq=list(m.disasm(raw,a));assert sum(x.size for x in seq)==len(raw);ins={x.address:x for x in seq}
rows={}
with (P/'instructions.tsv').open() as fp:
 for x in csv.DictReader(fp,delimiter='\t'):
  p=int(x['va'],16);v=bytes.fromhex(x['bytes']);assert p not in rows and p in ins and ins[p].bytes==v and read(p,len(v))==v;rows[p]=v
pins={94755890: '4929ef', 94755893: '0f839c000000', 94756055: '4983ff63', 94756059: '0f8788010000', 94756440: '4084ed', 94756443: '0f84ad000000', 94756622: '488b30', 94756633: 'f00fb04e10', 94756638: '0f85fc020000', 94756644: '48b80100000000000080', 94756654: '488b5648', 94756658: '488d48ff', 94756662: '4839ca', 94756665: '488b6c2420', 94756739: '488b4e60', 94756743: '4885c9', 94756746: '0f848f010000', 94756752: '488b7e50', 94756756: '4c8b4658', 94756763: '4939d0', 94756769: '4d0f42d1', 94756773: '4e8d1c01', 94756777: '49ffcb', 94756780: '4d29d0', 94756783: '4b8d0c40', 94756787: '4939d3', 94756790: '490f42d1', 94756794: '488d0ccf', 94756798: '4883c108', 94756802: '4929d3', 94756805: '4b8d145b', 94756809: '488d14d7', 94756813: 'e93b010000', 94757133: '488b12', 94757136: '488b09', 94757139: '48394128', 94757143: '7526', 94757145: '4c8b6960', 94757166: '41bc04000000', 94757172: '0f844cfdffff', 94757187: '4c8d81b8000000', 94757194: '483981b8000000', 94757201: '4c0f44c7', 94757205: '4d8b6830', 94757209: '4c39ed', 94757212: '761e', 94757214: '488b442408', 94757219: '4839d0', 94757222: '7622', 94757230: '41bc06000000', 94757250: '41bc05000000', 94757262: '48896c2460', 94757267: '4889442468', 94757272: 'c644247000', 94757287: 'e8740137ff', 94757348: 'e817e80600', 94757375: 'f0410fb00f', 94757383: '0f8479fcffff', 94756486: '4c897308', 94756490: '4c896310', 94756502: '48c70303000000'}
def check(r):
 for p,v in pins.items():assert r[p]==bytes.fromhex(v),hex(p)
check(rows)
for p,v in [(0x5a5dc35,0x5a5dcd7),(0x5a5dcdb,0x5a5de69),(0x5a5de5b,0x5a5df0e),(0x5a5df1e,0x5a5e220),(0x5a5df3e,0x5a5df83),(0x5a5df8a,0x5a5e11f),(0x5a5dfcd,0x5a5e10d),(0x5a5e117,0x5a5e13f),(0x5a5e134,0x5a5de86),(0x5a5e15c,0x5a5e17c),(0x5a5e166,0x5a5e18a),(0x5a5e1a7,0x4dce320),(0x5a5e1e4,0x5acca00),(0x5a5e207,0x5a5de86)]:assert ins[p].operands[0].type==X86_OP_IMM and ins[p].operands[0].imm==v
for start,end,front,last,want in [(10,20,10,20,5),(11,20,10,20,0),(11,21,10,20,6)]:assert (5 if start<=front else 6 if end>last else 0)==want
for cap,head,count,first,last in [(8,0,1,0,0),(8,7,2,7,0),(8,3,4,3,6)]:assert (head if head<cap else head-cap)==first and (head+count-1 if head+count-1<cap else head+count-1-cap)==last
for p in [0x5a5de5b,0x5a5df39,0x5a5df8a,0x5a5dfa1,0x5a5dfb6,0x5a5dfbe,0x5a5e113,0x5a5e151,0x5a5e15c,0x5a5e166,0x5a5e16e,0x5a5e182,0x5a5e1a7]:
 q=dict(rows);q[p]=q[p][:-1]+bytes([q[p][-1]^1])
 try:check(q)
 except AssertionError:pass
 else:raise AssertionError(hex(p))
print(f'1 FDE, {len(rows)} instructions, {len(pins)} pins, 14 targets, 6 arithmetic cases and 13 controls: OK')
