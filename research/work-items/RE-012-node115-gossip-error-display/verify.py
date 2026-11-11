#!/usr/bin/env python3
"""Static evidence checks; never execute or emulate the captured target."""
import csv,hashlib,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86_const import X86_OP_IMM
from elf_index import unwind_index
from fde_extents import eh_frame_records
P=Path('research/work-items/RE-012-node115-gossip-error-display')
b=Path('artifacts/node/115/hl-node').read_bytes();assert hashlib.sha256(b).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
s,h=unwind_index(b);_,f=eh_frame_records(b,s);idx={(x['start'],x['fde']) for x in h}
def read(a,n):
 x=next(x for x in s if x['address']<=a and a+n<=x['address']+x['size'] and x['name'] in ('.text','.rodata'));p=x['offset']+a-x['address'];return b[p:p+n]
bodies={0x5aaa0c0:(0x5aaa24a,'351c11c2052e69d82e5ba0e5fa35b4776afa903e6af843fa2ceef1b42fabbfcd'),0x5a5dbc0:(0x5a5e281,'5d9b8d4faa0106747b55edfc16afc1e706f6f7a0aeb979b95803bab4e6523320'),0x5a60a50:(0x5a61e38,'540390760e4360efd444c06270a6d20e97432861e5230991093cb886e5530f3f')}
m=Cs(CS_ARCH_X86,CS_MODE_64);m.detail=True;ins={}
for a,(z,d) in bodies.items():
 assert any(x['start']==a and x['end']==z and (a,x['fde']) in idx for x in f)
 raw=read(a,z-a);assert hashlib.sha256(raw).hexdigest()==d
 seq=list(m.disasm(raw,a));assert sum(x.size for x in seq)==len(raw);ins.update({x.address:x for x in seq})
rows={}
with (P/'instructions.tsv').open() as fp:
 for x in csv.DictReader(fp,delimiter='\t'):
  a=int(x['va'],16);v=bytes.fromhex(x['bytes']);assert a not in rows and a in ins and ins[a].bytes==v and read(a,len(v))==v;rows[a]=v
pins={95068356: '488b07', 95068359: '488d0d06fee8fa', 95068366: '48630481', 95068370: '4801c8', 95068373: 'ffe0', 95068382: '488b4018', 95068386: '488d359121e9fa', 95068393: 'ba11000000', 95068402: 'ffe0', 95068411: '488b4018', 95068415: '488d359121e9fa', 95068422: 'ba19000000', 95068431: 'ffe0', 95068440: '488b4018', 95068444: '488d355dd59afa', 95068451: 'ba20000000', 95068460: 'ffe0', 95068469: '488b4018', 95068473: '488d354b21e9fa', 95068480: 'ba0c000000', 95068489: 'ffe0', 95068491: '488d4708', 95068495: '4883c710', 95068519: '488d0542b692ff', 95068553: '488d15856b98fa', 95068565: 'ff155555a300', 95068576: '488d4708', 95068580: '4883c710', 95068604: '488d05edb592ff', 95068638: '488d1578cb98fa', 95068650: 'ff150055a300', 95068661: '488d4708', 95068665: '4883c710', 95068689: '488d0598b592ff', 95068723: '488d15743099fa', 95068735: 'ff15ab54a300', 94755884: '41be01000000', 94755890: '4929ef', 94755893: '0f839c000000', 94755899: '41bc01000000', 94756449: '41bc03000000', 94756457: '41bc02000000', 94756483: '4531e4', 94756486: '4c897308', 94756490: '4c896310', 94756502: '48c70303000000', 94757166: '41bc04000000', 94757172: '0f844cfdffff', 94757209: '4c39ed', 94757212: '761e', 94757219: '4839d0', 94757222: '7622', 94757230: '41bc06000000', 94757250: '41bc05000000', 94770495: '41833e03', 94770499: '0f853f030000', 94770505: '80bbb011000000', 94770512: '0f845a030000', 94770518: '488dbbb8110000', 94770612: 'ff15fea9a800', 94770618: '84c0', 94770620: '0f8520040000'}
def check(r):
 for a,v in pins.items():assert r[a]==bytes.fromhex(v),hex(a)
check(rows)
for a,v in [(0x5a5dc35,0x5a5dcd7),(0x5a5e134,0x5a5de86),(0x5a5e15c,0x5a5e17c),(0x5a5e166,0x5a5e18a),(0x5a61543,0x5a61888),(0x5a61550,0x5a618b0),(0x5a615bc,0x5a619e2)]:assert ins[a].operands[0].type==X86_OP_IMM and ins[a].operands[0].imm==v
def rip(a):return a+len(rows[a])+int.from_bytes(rows[a][-4:],'little',signed=True)
for a,v in [(0x5aaa0c7,0x939ed4),(0x5aaa0e2,0x93c27a),(0x5aaa0ff,0x93c297),(0x5aaa11c,0x457680),(0x5aaa139,0x93c28b),(0x5aaa189,0x430d15),(0x5aaa1de,0x436d5d),(0x5aaa233,0x43d2ae),(0x5aaa195,0x64df6f0),(0x5aaa1ea,0x64df6f0),(0x5aaa23f,0x64df6f0),(0x5a615b4,0x64ebfb8)]:assert rip(a)==v
base=0x939ed4
for i,want in enumerate([0x5aaa0d7,0x5aaa14b,0x5aaa111,0x5aaa12e,0x5aaa0f4,0x5aaa1a0,0x5aaa1f5]):assert base+int.from_bytes(read(base+4*i,4),'little',signed=True)==want and want in ins
for a,v in [(0x93c27a,b'Peer-only request'),(0x93c297,b'no client blocks to serve'),(0x457680,b'too many client blocks requested'),(0x93c28b,b'rate limited'),(0x430d15,b'\x1cinvalid client block range: '),(0x436d5d,b'\x1eclient block round too small: '),(0x43d2ae,b'\x1eclient block round too large: ')]:assert read(a,len(v))==v
r=next(x for x in s if x['name']=='.rela.dyn');rel={a:(i,d) for a,i,d in struct.iter_unpack('<QQq',b[r['offset']:r['offset']+r['size']])};assert rel[0x64ebfb8]==(8,0x5aaa0c0) and rel[0x64df6f0]==(8,0x1680500)
for a in [0x5aaa0c7,0x5aaa0ce,0x5aaa0e2,0x5aaa0ff,0x5aaa11c,0x5aaa139,0x5aaa189,0x5aaa1de,0x5aaa233,0x5a5dc3b,0x5a5de61,0x5a5de69,0x5a5e12e,0x5a5e16e,0x5a5e182,0x5a615b4]:
 q=dict(rows);q[a]=q[a][:-1]+bytes([q[a][-1]^1])
 try:check(q)
 except AssertionError:pass
 else:raise AssertionError(hex(a))
print(f'{len(bodies)} FDEs, {len(rows)} instructions, {len(pins)} pins, 7 table entries, 7 literals, 2 relocations and 16 controls: OK')
