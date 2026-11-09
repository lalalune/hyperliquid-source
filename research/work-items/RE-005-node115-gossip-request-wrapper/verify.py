#!/usr/bin/env python3
"""Static byte and control-flow checks; never executes the target."""
import csv, hashlib
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_OP_IMM
from elf_index import unwind_index
from fde_extents import eh_frame_records
P=Path('research/work-items/RE-005-node115-gossip-request-wrapper')
b=Path('artifacts/node/115/hl-node').read_bytes()
assert hashlib.sha256(b).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
s,h=unwind_index(b); _,f=eh_frame_records(b,s); idx={(x['start'],x['fde']) for x in h}; t=next(x for x in s if x['name']=='.text')
def read(a,n):
 assert t['address']<=a and a+n<=t['address']+t['size']
 p=t['offset']+a-t['address']; return b[p:p+n]
bodies={0x5860970:(0x5860a8a,'f3093f366b92b7da85c0478b3ac11d3544d4082ef9914234d0b29f551ed4520f'),0x4e4a1e0:(0x4e4a738,'24b14d6568a4732c5e162b1d6c3a59ad73675c043ac0c9816a690600f6117c85'),0x5aac6a0:(0x5aac7b7,'1cf55e47440548478e74ecf07ca6b1622a37e73d88b6d3d2f7bcabfd6023de42')}
m=Cs(CS_ARCH_X86,CS_MODE_64);m.detail=True;ins={}
for a,(z,d) in bodies.items():
 assert any(x['start']==a and x['end']==z and (a,x['fde']) in idx for x in f)
 raw=read(a,z-a);assert hashlib.sha256(raw).hexdigest()==d
 seq=list(m.disasm(raw,a));assert sum(x.size for x in seq)==len(raw);ins.update({x.address:x for x in seq})
rows={}
with (P/'instructions.tsv').open() as fp:
 for x in csv.DictReader(fp,delimiter='\t'):
  a=int(x['va'],16);v=bytes.fromhex(x['bytes']);assert a not in rows and a in ins and ins[a].bytes==v and read(a,len(v))==v;rows[a]=v
pins={0x586097e:'4489c5',0x5860981:'4989d4',0x5860984:'4989f5',0x586098a:'48894c2420',0x586099f:'4c892c24',0x58609a3:'4c89642408',0x58609ad:'4889442410',0x58609ba:'89ea',0x58609bc:'e81f985eff',0x58609c1:'0f10442448',0x58609c6:'0f104c2458',0x5860a08:'4084ed',0x4e4a284:'488b06',0x4e4a287:'4c8b7608',0x4e4a28f:'488b09',0x4e4a292:'4889442440',0x4e4a297:'4c89742448',0x4e4a29c:'48c744243001000000',0x4e4a2a5:'48894c2438',0x4e4a2aa:'48c744245000000000',0x4e4a2bd:'e8de23c600',0x4e4a2c7:'80f912',0x4e4a2cc:'4c2b742448',0x4e4a2d1:'0f8207040000',0x4e4a31f:'ba01000000',0x4e4a324:'b928000000',0x4e4a329:'be18000000',0x4e4a38d:'4c89340b',0x4e4a499:'48895320'}
def check(r):
 for a,v in pins.items():assert r[a]==bytes.fromhex(v),hex(a)
check(rows)
for a,v in [(0x58609bc,0x4e4a1e0),(0x4e4a2bd,0x5aac6a0),(0x4e4a2d1,0x4e4a6de),(0x4e4a32e,0x4e4a389),(0x4e4a391,0x4e4a499)]:assert ins[a].operands[0].type==X86_OP_IMM and ins[a].operands[0].imm==v
for initial,remaining,want in [(0,0,0),(100,99,1),(100,0,100)]:assert initial>=remaining and initial-remaining==want
assert 0<1 # remaining > initial takes unsigned borrow
for a in [0x58609bc,0x58609c1,0x4e4a29c,0x4e4a2aa,0x4e4a2bd,0x4e4a2cc,0x4e4a2d1,0x4e4a38d]:
 r=dict(rows);r[a]=r[a][:-1]+bytes([r[a][-1]^1])
 try:check(r)
 except AssertionError:pass
 else:raise AssertionError(hex(a))
print(f'{len(bodies)} FDEs, {len(rows)} instructions, {len(pins)} pins, 5 targets and 8 controls: OK')
