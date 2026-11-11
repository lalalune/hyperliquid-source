#!/usr/bin/env python3
"""Static evidence checks; no execution or emulation of captured instructions."""
import csv,hashlib,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86_const import X86_OP_IMM
from elf_index import unwind_index
from fde_extents import eh_frame_records
P=Path('research/work-items/RE-005-node115-gossip-request-handler')
b=Path('artifacts/node/115/hl-node').read_bytes();assert hashlib.sha256(b).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
s,h=unwind_index(b);_,f=eh_frame_records(b,s);idx={(x['start'],x['fde']) for x in h};t=next(x for x in s if x['name']=='.text')
def read(a,n):
 assert t['address']<=a and a+n<=t['address']+t['size'];p=t['offset']+a-t['address'];return b[p:p+n]
bodies={0x5a5dbc0:(0x5a5e281,'5d9b8d4faa0106747b55edfc16afc1e706f6f7a0aeb979b95803bab4e6523320'),0x5a60a50:(0x5a61e38,'540390760e4360efd444c06270a6d20e97432861e5230991093cb886e5530f3f')}
m=Cs(CS_ARCH_X86,CS_MODE_64);m.detail=True;ins={}
for a,(z,d) in bodies.items():
 assert any(x['start']==a and x['end']==z and (a,x['fde']) in idx for x in f)
 raw=read(a,z-a);assert hashlib.sha256(raw).hexdigest()==d
 seq=list(m.disasm(raw,a));assert sum(x.size for x in seq)==len(raw);ins.update({x.address:x for x in seq})
rows={}
with (P/'instructions.tsv').open() as fp:
 for x in csv.DictReader(fp,delimiter='\t'):
  a=int(x['va'],16);v=bytes.fromhex(x['bytes']);assert a not in rows and a in ins and ins[a].bytes==v and read(a,len(v))==v;rows[a]=v
pins={94755796: '488b01', 94755799: '4885c0', 94755802: '741e', 94755804: '83f801', 94755807: '756a', 94755817: 'e822e754ff', 94755822: '48c70304000000', 94755834: '488b6908', 94755838: '4c8b7910', 94755854: 'e8cdeb54ff', 94755862: '4181fc7f000001', 94755869: '0f94c2', 94755872: '08c2', 94755874: '80fa01', 94755877: '7575', 94755884: '41be01000000', 94755890: '4929ef', 94755893: '0f839c000000', 94755899: '41bc01000000', 94755910: 'e93b020000', 94755922: 'f0410fb04e10', 94755928: '0f8571020000', 94755934: '410f104618', 94755939: '410f104e28', 94755944: '410f105638', 94755949: '0f115320', 94755953: '0f114b10', 94755957: '0f1103', 94755996: '80f90a', 94755999: '7486', 94756010: '3dc0000000', 94756015: '0f84bc010000', 94756021: '3dac000000', 94756026: '0f85c3010000', 94756034: '2500f00000', 94756039: '3d00100000', 94756044: '0f8455ffffff', 94756055: '4983ff63', 94756059: '0f8788010000', 94756457: '41bc02000000', 94756467: '2500ff0000', 94756472: '3d00a80000', 94756477: '0f84a4fdffff', 94756486: '4c897308', 94756490: '4c896310', 94756502: '48c70303000000', 94770478: '488d8c24f0000000', 94770486: '4c89f7', 94770489: 'ff1571aaa800'}
def check(r):
 for a,v in pins.items():assert r[a]==bytes.fromhex(v),hex(a)
check(rows)
for a,v in [(0x5a5dbda,0x5a5dbfa),(0x5a5dbdf,0x5a5dc4b),(0x5a5dbe9,0x4fac310),(0x5a5dc0e,0x4fac7e0),(0x5a5dc25,0x5a5dc9c),(0x5a5dc35,0x5a5dcd7),(0x5a5dc46,0x5a5de86),(0x5a5dc9f,0x5a5dc27),(0x5a5dcaf,0x5a5de71),(0x5a5dcba,0x5a5de83),(0x5a5dccc,0x5a5dc27),(0x5a5dcdb,0x5a5de69),(0x5a5de7d,0x5a5dc27)]:assert ins[a].operands[0].type==X86_OP_IMM and ins[a].operands[0].imm==v
a=0x5a61539;slot=a+len(rows[a])+int.from_bytes(rows[a][-4:],'little',signed=True);assert slot==0x64ebfb0
r=next(x for x in s if x['name']=='.rela.dyn');rel={a:(i,d) for a,i,d in struct.iter_unpack('<QQq',b[r['offset']:r['offset']+r['size']])};assert rel[slot]==(8,0x5a5dbc0)
for a,b_,want in [(0,0,'continue'),(1,0,'borrow'),(4,103,'continue'),(4,104,'large')]:
 got='borrow' if b_<a else ('large' if b_-a>99 else 'continue');assert got==want
for a in [0x5a5dbda,0x5a5dbdc,0x5a5dc16,0x5a5dc20,0x5a5dc32,0x5a5dc35,0x5a5dccc,0x5a5dcd7,0x5a5dcdb,0x5a5de8a,0x5a61539]:
 q=dict(rows);q[a]=q[a][:-1]+bytes([q[a][-1]^1])
 try:check(q)
 except AssertionError:pass
 else:raise AssertionError(hex(a))
print(f'{len(bodies)} FDEs, {len(rows)} instructions, {len(pins)} pins, 13 targets, relocation, 4 boundaries, 11 controls: OK')
