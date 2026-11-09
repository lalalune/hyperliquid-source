#!/usr/bin/env python3
"""Static evidence checks; never execute or emulate the captured target."""
import csv,hashlib
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86_const import X86_OP_IMM
from elf_index import unwind_index
from fde_extents import eh_frame_records
P=Path('research/work-items/RE-012-node115-gossip-request-counter')
b=Path('artifacts/node/115/hl-node').read_bytes();assert hashlib.sha256(b).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
s,h=unwind_index(b);_,f=eh_frame_records(b,s);idx={(x['start'],x['fde']) for x in h};t=next(x for x in s if x['name']=='.text')
def read(a,n):
 assert t['address']<=a and a+n<=t['address']+t['size'];p=t['offset']+a-t['address'];return b[p:p+n]
bodies={0x5a5dbc0:(0x5a5e281,'5d9b8d4faa0106747b55edfc16afc1e706f6f7a0aeb979b95803bab4e6523320'),0x59db3a0:(0x59db6f4,'669c5b78a31be6b0f7a03396b8ec6f72effc257f87ed4d03027a8d9759be034e')}
m=Cs(CS_ARCH_X86,CS_MODE_64);m.detail=True;ins={}
for a,(z,d) in bodies.items():
 assert any(x['start']==a and x['end']==z and (a,x['fde']) in idx for x in f)
 raw=read(a,z-a);assert hashlib.sha256(raw).hexdigest()==d
 seq=list(m.disasm(raw,a));assert sum(x.size for x in seq)==len(raw);ins.update({x.address:x for x in seq})
rows={}
with (P/'instructions.tsv').open() as fp:
 for x in csv.DictReader(fp,delimiter='\t'):
  a=int(x['va'],16);v=bytes.fromhex(x['bytes']);assert a not in rows and a in ins and ins[a].bytes==v and read(a,len(v))==v;rows[a]=v
pins={94755890: '4929ef', 94755893: '0f839c000000', 94756055: '4983ff63', 94756059: '0f8788010000', 94756393: '49ffc7', 94756401: 'b910270000', 94756406: '4c89e7', 94756409: '4c89fa', 94756412: 'e85fd5f7ff', 94756417: '89c5', 94756427: 'f00fb00f', 94756434: '0f85a2000000', 94756440: '4084ed', 94756443: '0f84ad000000', 94221230: '4989cf', 94221233: '4989d4', 94221242: '488b8768010000', 94221269: 'ffd0', 94221271: '84c0', 94221273: '0f85c8020000', 94221507: '4d0365f0', 94221511: '48c7c5ffffffff', 94221521: '480f42c5', 94221525: '490f43c4', 94221529: '498945f0', 94221533: '41833e01', 94221537: '7571', 94221652: '498b45f8', 94221656: '48ffc0', 94221659: '480f44c5', 94221663: '498945f8', 94221669: '493b4628', 94221673: '0f80ba000000', 94221819: '49f76640', 94221823: '7028', 94221825: '4939c4', 94221828: '7623', 94221860: 'e887c951ff', 94221865: '4d397df0', 94221869: '7678', 94221991: '31c0'}
def check(r):
 for a,v in pins.items():assert r[a]==bytes.fromhex(v),hex(a)
check(rows)
for a,v in [(0x5a5dc35,0x5a5dcd7),(0x5a5dcdb,0x5a5de69),(0x5a5de3c,0x59db3a0),(0x5a5de52,0x5a5defa),(0x5a5de5b,0x5a5df0e),(0x59db3d9,0x59db6a7),(0x59db4e1,0x59db554),(0x59db569,0x59db629),(0x59db5ff,0x59db629),(0x59db604,0x59db629),(0x59db624,0x4ef7fb0),(0x59db62d,0x59db6a7)]:assert ins[a].operands[0].type==X86_OP_IMM and ins[a].operands[0].imm==v
mx=(1<<64)-1
for old,delta,want in [(0,1,1),(9900,100,10000),(9999,2,10001),(mx,1,mx),(mx-1,100,mx)]:assert min(mx,old+delta)==want
for count,want in [(0,1),(mx-1,mx),(mx,mx)]:assert min(mx,count+1)==want
assert all(1<=n+1<=100 for n in range(100))
for a in [0x5a5dc32,0x5a5dcdb,0x5a5de31,0x5a5de3c,0x59db3d9,0x59db4c3,0x59db4d1,0x59db4d9,0x59db55b,0x59db629,0x59db62d]:
 q=dict(rows);q[a]=q[a][:-1]+bytes([q[a][-1]^1])
 try:check(q)
 except AssertionError:pass
 else:raise AssertionError(hex(a))
print(f'{len(bodies)} FDEs, {len(rows)} instructions, {len(pins)} pins, 12 targets, 8 numeric cases and 11 controls: OK')
