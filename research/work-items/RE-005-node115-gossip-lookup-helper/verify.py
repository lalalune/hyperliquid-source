#!/usr/bin/env python3
"""Static evidence checks; never execute or emulate the captured target."""
import csv,hashlib
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86_const import X86_OP_IMM
from elf_index import unwind_index
from fde_extents import eh_frame_records
P=Path('research/work-items/RE-005-node115-gossip-lookup-helper')
b=Path('artifacts/node/115/hl-node').read_bytes();assert hashlib.sha256(b).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
s,h=unwind_index(b);_,f=eh_frame_records(b,s);idx={(x['start'],x['fde']) for x in h};t=next(x for x in s if x['name']=='.text')
def read(a,n):
 assert t['address']<=a and a+n<=t['address']+t['size'];p=t['offset']+a-t['address'];return b[p:p+n]
bodies={0x4fac7e0:(0x4fac94a,'e56359a2f2faa2b075119fdb2d2ae25c47f9cd4bdd9a952012cf5be5850b8ae5'),0x5a5dbc0:(0x5a5e281,'5d9b8d4faa0106747b55edfc16afc1e706f6f7a0aeb979b95803bab4e6523320')}
m=Cs(CS_ARCH_X86,CS_MODE_64);m.detail=True;ins={}
for a,(z,d) in bodies.items():
 assert any(x['start']==a and x['end']==z and (a,x['fde']) in idx for x in f)
 raw=read(a,z-a);assert hashlib.sha256(raw).hexdigest()==d
 seq=list(m.disasm(raw,a));assert sum(x.size for x in seq)==len(raw);ins.update({x.address:x for x in seq})
rows={}
with (P/'instructions.tsv').open() as fp:
 for x in csv.DictReader(fp,delimiter='\t'):
  a=int(x['va'],16);v=bytes.fromhex(x['bytes']);assert a not in rows and a in ins and ins[a].bytes==v and read(a,len(v))==v;rows[a]=v
pins={94755845: '488d7e08', 94755849: '89d6', 94755854: 'e8cdeb54ff', 94755872: '08c2', 83544036: '89742404', 83544040: '4c8b37', 83544099: '31c0', 83544101: '493b4618', 83544105: '0f8197000000', 83544111: '498b4620', 83544115: '4885c0', 83544118: '0f84a7000000', 83544124: '498b4e28', 83544128: '488db8b8000000', 83544135: '0fb7b0e6000000', 83544145: '41c1e002', 83544160: '4d85c0', 83544163: '744b', 83544165: '448b4c2404', 83544170: '448b17', 83544173: '4883c704', 83544177: '410fc9', 83544180: '410fca', 83544183: '4539d1', 83544186: '410f97c1', 83544190: '4180d900', 83544194: '4d0fbec9', 83544215: '4983c0fc', 83544219: '4180f901', 83544223: '74bf', 83544229: '85f6', 83544231: '750a', 83544233: 'eb34', 83544240: '4889f2', 83544243: '4883e901', 83544247: '722a', 83544249: '488b84d0e8000000', 83544257: 'e97affffff', 83544262: '4983c618', 83544274: 'e8f9e68400', 83544279: '4885c0', 83544282: '0f94c0', 83544287: 'b001', 83544291: '31c0', 83544300: 'f0480fc10b', 83544309: '4883f912', 83544326: '89c3', 83544328: 'ff15da465301', 83544334: '89d8'}
def check(r):
 for a,v in pins.items():assert r[a]==bytes.fromhex(v),hex(a)
check(rows)
for a,v in [(0x5a5dc0e,0x4fac7e0),(0x4fac829,0x4fac8c6),(0x4fac836,0x4fac8e3),(0x4fac863,0x4fac8b0),(0x4fac89f,0x4fac860),(0x4fac8a7,0x4fac8b3),(0x4fac8a9,0x4fac8df),(0x4fac8b7,0x4fac8e3),(0x4fac8c1,0x4fac840),(0x4fac8d2,0x57fafd0)]:assert ins[a].operands[0].type==X86_OP_IMM and ins[a].operands[0].imm==v
for x,overflow in [(0,False),((1<<63)-1,False),(1<<63,True),((1<<64)-1,False)]:
 result=(-x)&((1<<64)-1);of=bool(((0^x)&(0^result))>>63);assert of==overflow
for k,v,expected in [(0,1,-1),(1,1,0),(2,1,1),(0xffffffff,0,1)]:
 assert int(k>v)-int(k<v)==expected
for a in [0x5a5dc0e,0x4fac825,0x4fac829,0x4fac847,0x4fac871,0x4fac877,0x4fac89f,0x4fac8b7,0x4fac8b9,0x4fac8da,0x4fac8ec]:
 q=dict(rows);q[a]=q[a][:-1]+bytes([q[a][-1]^1])
 try:check(q)
 except AssertionError:pass
 else:raise AssertionError(hex(a))
print(f'{len(bodies)} FDEs, {len(rows)} instructions, {len(pins)} pins, 10 targets, 8 numeric cases and 11 controls: OK')
