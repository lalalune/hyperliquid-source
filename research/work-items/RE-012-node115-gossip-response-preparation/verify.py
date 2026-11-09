#!/usr/bin/env python3
"""Static evidence checks; never execute or emulate the captured target."""
import csv,hashlib,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86_const import X86_OP_IMM
from elf_index import unwind_index
from fde_extents import eh_frame_records
P=Path('research/work-items/RE-012-node115-gossip-response-preparation')
b=Path('artifacts/node/115/hl-node').read_bytes();assert hashlib.sha256(b).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
s,h=unwind_index(b);_,f=eh_frame_records(b,s);idx={(x['start'],x['fde']) for x in h}
def read(a,n):
 x=next(x for x in s if x['address']<=a and a+n<=x['address']+x['size'] and x['name'] in ('.text','.rodata'));p=x['offset']+a-x['address'];return b[p:p+n]
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
pins={94757348: 'e817e80600', 94757353: '4c8b642428', 94757358: '488b6c2430', 94757363: '4c8b6c2438', 94757368: '4531f6', 94757375: 'f0410fb00f', 94757380: '4c89e8', 94757383: '0f8479fcffff', 94756486: '4c897308', 94756490: '4c896310', 94756494: '48896b18', 94756498: '48894320', 94756502: '48c70303000000', 94770471: '4c8db3a8110000', 94770486: '4c89f7', 94770489: 'ff1571aaa800', 94770495: '41833e03', 94770499: '0f853f030000', 94770505: '80bbb011000000', 94770512: '0f845a030000', 94770518: '488dbbb8110000', 94770525: '48c78424d006000000000000', 94770537: '48c78424d806000001000000', 94770549: '48c78424e006000000000000', 94770561: '48c784240001000020000060', 94770612: 'ff15fea9a800', 94770618: '84c0', 94770620: '0f8520040000', 94770626: '4c8bbc24d0060000', 94770634: '488b8424d8060000', 94770642: '488b8c24e0060000', 94770650: '31d2', 94770652: 'e934030000', 94771336: '41bf02000000', 94771342: 'bf02000000', 94771347: 'ff15e7dba700', 94771353: '4885c0', 94771356: '0f842d020000', 94771362: '66c7006f6b', 94771367: '31d2', 94771369: 'b902000000', 94771374: 'eb65', 94771376: '488b83c8110000', 94771407: '488b05f2dda700', 94771422: '488d35c7c39efa', 94771445: 'ff15eddda700', 94771451: '4c8bbc24f0000000', 94771459: '488b8424f8000000', 94771467: '488b8c2400010000', 94771475: 'b201', 94771477: 'c683190e000001', 94771484: '4c89bb380e0000', 94771491: '488983400e0000', 94771498: '48898b480e0000', 94771512: '488d0dab91edfa', 94771519: '48898b500e0000', 94771526: '48c783580e000014000000', 94771558: 'c683a011000000', 94771565: '8893a1110000', 94771571: '41b814000000', 94771577: 'e9f7f6ffff', 94769269: '488dbb600e0000', 94769279: '4c89f6', 94769282: 'e82906e0ff'}
def check(r):
 for a,v in pins.items():assert r[a]==bytes.fromhex(v),hex(a)
check(rows)
for a,v in [(0x5a5e1e4,0x5acca00),(0x5a5e207,0x5a5de86),(0x5a61543,0x5a61888),(0x5a61550,0x5a618b0),(0x5a615bc,0x5a619e2),(0x5a615dc,0x5a61915),(0x5a6189c,0x5a61acf),(0x5a618ae,0x5a61915),(0x5a61979,0x5a61075),(0x5a61082,0x58616b0)]:assert ins[a].operands[0].type==X86_OP_IMM and ins[a].operands[0].imm==v
def rip(a):return a+len(rows[a])+int.from_bytes(rows[a][-4:],'little',signed=True)
for a,v in [(0x5a61539,0x64ebfb0),(0x5a615b4,0x64ebfb8),(0x5a61893,0x64df480),(0x5a618cf,0x64df6c8),(0x5a618de,0x44dcac),(0x5a618f5,0x64df6e8),(0x5a61938,0x93aaea)]:assert rip(a)==v
r=next(x for x in s if x['name']=='.rela.dyn');rel={a:(i,d) for a,i,d in struct.iter_unpack('<QQq',b[r['offset']:r['offset']+r['size']])}
for a,v in [(0x64ebfb0,0x5a5dbc0),(0x64ebfb8,0x5aaa0c0),(0x64df480,0x6355830),(0x64df6c8,0x1689420),(0x64df6e8,0x141e3a0)]:assert rel[a]==(8,v)
assert read(0x44dcac,22)==b'\x05sent \xc0\x0e client blocks' and read(0x93aaea,20)==b'send gossip rpc resp'
for a in [0x5a5e1f8,0x5a5de96,0x5a61539,0x5a6153f,0x5a61550,0x5a615b4,0x5a615bc,0x5a61893,0x5a618a2,0x5a618b0,0x5a618de,0x5a61913,0x5a61938,0x5a6196d,0x5a61082]:
 q=dict(rows);q[a]=q[a][:-1]+bytes([q[a][-1]^1])
 try:check(q)
 except AssertionError:pass
 else:raise AssertionError(hex(a))
print(f'{len(bodies)} FDEs, {len(rows)} instructions, {len(pins)} pins, 10 direct targets, 5 relocations, literals and 15 controls: OK')
