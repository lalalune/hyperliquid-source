#!/usr/bin/env python3
"""Static evidence checks; never execute or emulate the captured target."""
import csv,hashlib
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86_const import X86_OP_IMM
from elf_index import unwind_index
from fde_extents import eh_frame_records
P=Path('research/work-items/RE-012-node115-gossip-range-iterator')
b=Path('artifacts/node/115/hl-node').read_bytes();assert hashlib.sha256(b).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
s,h=unwind_index(b);_,f=eh_frame_records(b,s);idx={(x['start'],x['fde']) for x in h};t=next(x for x in s if x['name']=='.text')
def read(a,n):
 assert t['address']<=a and a+n<=t['address']+t['size'];p=t['offset']+a-t['address'];return b[p:p+n]
bodies={0x4e18c50:(0x4e18dfe,'8708a3941b37625fe634ed3496cbaa27045177a66e2bd65122efdfcf8d398a15'),0x5acca00:(0x5accc71,'8fbc9e12bde4d8eb49f62cf1ab939a35392b1ca843ad3593537008290b7aa57c'),0x4dce320:(0x4dce480,'7efde4e09efe7d39c34fbf61836b5310290659a24082d5e2928b477ae24c0855')}
m=Cs(CS_ARCH_X86,CS_MODE_64);m.detail=True;ins={}
for a,(z,d) in bodies.items():
 assert any(x['start']==a and x['end']==z and (a,x['fde']) in idx for x in f)
 raw=read(a,z-a);assert hashlib.sha256(raw).hexdigest()==d
 seq=list(m.disasm(raw,a));assert sum(x.size for x in seq)==len(raw);ins.update({x.address:x for x in seq})
rows={}
with (P/'instructions.tsv').open() as fp:
 for x in csv.DictReader(fp,delimiter='\t'):
  a=int(x['va'],16);v=bytes.fromhex(x['bytes']);assert a not in rows and a in ins and ins[a].bytes==v and read(a,len(v))==v;rows[a]=v
pins={81890385: '488b07', 81890388: '4885c0', 81890391: '0f84fe000000', 81890397: '83f801', 81890400: '753b', 81890402: '488d4f08', 81890406: '488b4708', 81890410: '488b5710', 81890414: '4839d0', 81890417: '751d', 81890419: '0f104718', 81890423: '0f1101', 81890426: '48894718', 81890430: '48895720', 81890434: '488b4708', 81890438: '483b4710', 81890442: '0f84cf000000', 81890448: '488d5018', 81890452: '488911', 81890455: '488d5008', 81890655: '31c0', 81890657: '488d5008', 95210007: 'e834c234ff', 95210012: '4885c0', 95210015: '0f84a0000000', 95210021: '488b1a', 95210024: '4c8b6208', 95210064: '41833e01', 95210078: '492b4608', 95210086: '48baabaaaaaaaaaaaaaa', 95210096: '480fafc2', 95210100: '492b4e18', 95210108: '480fafca', 95210112: '4801c1', 95210115: '4883f904', 95210124: '480f43e9', 95210128: '48ffc5', 95210347: '49895c2df8', 95210352: '4d89642d00', 95210357: '49ffc6', 95210372: 'e8c7c034ff', 95210380: '7473', 81585234: '48c70301000000', 81585241: '48895308', 81585245: '48897310', 81585249: '48894318', 81585253: '48894b20'}
def check(r):
 for a,v in pins.items():assert r[a]==bytes.fromhex(v),hex(a)
check(rows)
for a,v in [(0x4e18c57,0x4e18d5b),(0x4e18c60,0x4e18c9d),(0x4e18c71,0x4e18c90),(0x4e18c8a,0x4e18d5f),(0x5acca17,0x4e18c50),(0x5acca1f,0x5accac5),(0x5accb84,0x4e18c50),(0x5accb8c,0x5accc01)]:assert ins[a].operands[0].type==X86_OP_IMM and ins[a].operands[0].imm==v
for n1,n2 in [(0,0),(0,1),(1,0),(2,3),(4,4)]:
 n=n1+n2
 if n:assert max(3,(n-1))+1==max(4,n)
 assert (24*n1+24*n2)//24==n
for a in [0x4e18c57,0x4e18c60,0x4e18c71,0x4e18c73,0x4e18c77,0x4e18c8a,0x4e18c90,0x4e18c94,0x4e18c97,0x5acca17,0x5acca25,0x5acca28,0x5acca8c,0x4dce465]:
 q=dict(rows);q[a]=q[a][:-1]+bytes([q[a][-1]^1])
 try:check(q)
 except AssertionError:pass
 else:raise AssertionError(hex(a))
print(f'{len(bodies)} FDEs, {len(rows)} instructions, {len(pins)} pins, 8 targets, 5 count cases and 14 controls: OK')
