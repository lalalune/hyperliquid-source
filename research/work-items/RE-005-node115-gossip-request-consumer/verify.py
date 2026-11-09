#!/usr/bin/env python3
"""Digest-bound static evidence checks; no target execution or emulation."""
import csv, hashlib, struct
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86_const import X86_OP_IMM
from elf_index import unwind_index
from fde_extents import eh_frame_records
P=Path('research/work-items/RE-005-node115-gossip-request-consumer')
b=Path('artifacts/node/115/hl-node').read_bytes()
assert hashlib.sha256(b).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
s,h=unwind_index(b);_,f=eh_frame_records(b,s);idx={(x['start'],x['fde']) for x in h};t=next(x for x in s if x['name']=='.text')
def read(a,n):
 assert t['address']<=a and a+n<=t['address']+t['size'];p=t['offset']+a-t['address'];return b[p:p+n]
bodies={0x5a60a50:(0x5a61e38,'540390760e4360efd444c06270a6d20e97432861e5230991093cb886e5530f3f'),0x5860970:(0x5860a8a,'f3093f366b92b7da85c0478b3ac11d3544d4082ef9914234d0b29f551ed4520f')}
m=Cs(CS_ARCH_X86,CS_MODE_64);m.detail=True;ins={}
for a,(z,d) in bodies.items():
 assert any(x['start']==a and x['end']==z and (a,x['fde']) in idx for x in f)
 raw=read(a,z-a);assert hashlib.sha256(raw).hexdigest()==d
 seq=list(m.disasm(raw,a));assert sum(x.size for x in seq)==len(raw);ins.update({x.address:x for x in seq})
rows={}
with (P/'instructions.tsv').open() as fp:
 for x in csv.DictReader(fp,delimiter='\t'):
  a=int(x['va'],16);v=bytes.fromhex(x['bytes']);assert a not in rows and a in ins and ins[a].bytes==v and read(a,len(v))==v;rows[a]=v
pins={94769749: 'e836310500', 94769754: '48bd0000000000000080', 94769764: '4c8bb424f0000000', 94769772: '488d4501', 94769776: '4939c6', 94769779: '7556', 94769877: '4c8bbc24f8000000', 94769885: '4c8ba42400010000', 94769926: '4939ee', 94769929: '0f8530010000', 94770230: '4939ee', 94770233: '0f84d0feffff', 94770239: '488b8b480e0000', 94770246: '440fb68398100000', 94770280: '4c89fe', 94770283: '4c89e2', 94770286: 'e8fdf4dfff', 94770291: '80bc24d006000012', 94770299: '0f8560010000', 94770305: '488bac24d8060000', 94770313: '4c8ba424e0060000', 94770321: '488b8424e8060000', 94770347: 'ff15efdfa700', 94770358: 'c60001', 94770363: '4883fd04', 94770367: '0f84b7fdffff', 94770373: '4889abe00d0000', 94770380: '4c89a3e80d0000', 94770392: '488983f00d0000', 94770399: '4883fd03', 94770403: '0f8442feffff', 94770425: '48894f10', 94770432: '0f1107', 94770463: '0f298424f0000000', 94770489: 'ff1571aaa800', 94770657: '0f108424d0060000', 94770665: '0f108c24e0060000', 94770697: 'e842450500', 94770702: '4989c4', 94770705: 'bd03000000', 94770713: '0f8584feffff', 94770719: 'e98dfeffff', 92670334: '4489c5', 92670337: '4989d4', 92670340: '4989f5', 92670346: '48894c2420', 92670396: 'e81f985eff'}
def check(r):
 for a,v in pins.items():assert r[a]==bytes.fromhex(v),hex(a)
check(rows)
for a,v in [(0x5a61255,0x5ab4390),(0x5a61273,0x5a612cb),(0x5a61309,0x5a6143f),(0x5a61439,0x5a6130f),(0x5a6146e,0x5860970),(0x5a6147b,0x5a615e1),(0x5a614bf,0x5a6127c),(0x5a614e3,0x5a6132b),(0x5a61609,0x5ab5b50),(0x5a61619,0x5a614a3),(0x5a6161f,0x5a614b1),(0x58609bc,0x4e4a1e0)]:assert ins[a].operands[0].type==X86_OP_IMM and ins[a].operands[0].imm==v
def rip(a):return a+len(rows[a])+int.from_bytes(rows[a][-4:],'little',signed=True)
assert rip(0x5a614ab)==0x64df4a0 and rip(0x5a61539)==0x64ebfb0
r=next(x for x in s if x['name']=='.rela.dyn');rel={a:(i,d) for a,i,d in struct.iter_unpack('<QQq',b[r['offset']:r['offset']+r['size']])}
assert rel[0x64df4a0]==(8,0x635de30) and rel[0x64ebfb0]==(8,0x5a5dbc0)
assert (1<<63)+1 != 1<<63
for a in [0x5a61255,0x5a61273,0x5a612dd,0x5a61309,0x5a61446,0x5a6146e,0x5a6147b,0x5a614bf,0x5a614e3,0x5a61539,0x5a61609]:
 q=dict(rows);q[a]=q[a][:-1]+bytes([q[a][-1]^1])
 try:check(q)
 except AssertionError:pass
 else:raise AssertionError(hex(a))
print(f'{len(bodies)} FDEs, {len(rows)} instructions, {len(pins)} pins, 12 direct targets, 2 relocations and 11 controls: OK')
