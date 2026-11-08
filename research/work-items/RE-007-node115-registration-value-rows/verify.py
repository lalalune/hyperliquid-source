#!/usr/bin/env python3
"""Check static evidence only: never execute or emulate target instructions."""
import csv,hashlib,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from elf_index import unwind_index
from fde_extents import eh_frame_records
P=Path('research/work-items/RE-007-node115-registration-value-rows')
b=Path('artifacts/node/115/hl-node').read_bytes();assert hashlib.sha256(b).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
s,h=unwind_index(b);_,f=eh_frame_records(b,s);idx={(x['start'],x['fde']) for x in h};t=next(x for x in s if x['name']=='.text')
def read(a,n):
 assert t['address']<=a and a+n<=t['address']+t['size'];p=t['offset']+a-t['address'];return b[p:p+n]
bodies={0x3bcb6c0:(0x3bcb806,'89ef9dd25e2433e2a317c8cf56b5767adc5de0622f08a0d67fb007b1ee3746ab'),0x3d9b0c0:(0x3d9b27a,'63d88052d1e4df3ee217a3f6c6ceea996417f551b08c9adf7acf1ac0403d5a26'),0x3db4e40:(0x3db50ed,'c343da26e99796dbac808468e9fa77d9658c56209ea0b9a20571106817ba43b8'),0x38b3f90:(0x38b4546,'b2bf46b8cf29ca1af27b6070fcd5455c108fb3c40b23c2c1a4a3f62a5c6808fd')}
ins={}
for a,(z,d) in bodies.items():
 assert any(x['start']==a and x['end']==z and (a,x['fde']) in idx for x in f);raw=read(a,z-a);assert hashlib.sha256(raw).hexdigest()==d
 seq=list(Cs(CS_ARCH_X86,CS_MODE_64).disasm(raw,a));assert sum(x.size for x in seq)==len(raw);ins.update({x.address:x for x in seq})
rows={}
with (P/'instructions.tsv').open() as fp:
 for x in csv.DictReader(fp,delimiter='\t'):
  a=int(x['va'],16);v=bytes.fromhex(x['bytes']);assert a not in rows and a in ins and ins[a].bytes==v and read(a,len(v))==v;rows[a]=v
pins={0x38b4225:'4889b424a8000000',0x38b4235:'807c241c00',0x38b423a:'746b',0x38b425d:'0f118424f8000000',0x38b4265:'488d8424a8000000',0x38b426d:'48898424f0000000',0x38b4275:'488dbc24b0000000',0x38b427d:'488db424f0000000',0x38b4285:'e836743100',0x38b4296:'488d9424b0000000',0x38b42a1:'ff152129c302',0x3bcb6c8:'488b4610',0x3bcb6d1:'0f1006',0x3bcb6e3:'e858971e00',0x3bcb6fc:'4883fe02',0x3bcb706:'488d7c2438',0x3bcb70b:'e8b0f91c00',0x3bcb71a:'488b542448',0x3bcb71f:'4883fa40',0x3bcb723:'763f',0x3bcb725:'486bd238',0x3bcb749:'e84208ccff',0x3bcb783:'e8e88f9900',0x3bcb7a2:'4883fe15',0x3bcb7b2:'e8491b7a00',0x3d9b0c0:'488b4710',0x3d9b0c4:'4883f802',0x3d9b0c8:'0f82cc000000',0x3d9b0ce:'488b4f08',0x3d9b0fb:'4883c238',0x3d9b113:'440fb64ac8',0x3d9b118:'443a4a90',0x3d9b123:'4c8b4ad0',0x3d9b127:'4c3b4a98',0x3d9b135:'443a5a91',0x3d9b18d:'498d70ff',0x3d9b196:'48897710',0x3d9b1cd:'4c6bd638',0x3d9b1d5:'440fb60a',0x3d9b1d9:'463a4c11c8',0x3d9b1e5:'4c8b4a08',0x3d9b1e9:'4d3b48d0',0x3d9b1ef:'440fb64a01',0x3d9b1f4:'453a48c9',0x3d9b268:'4883c238',0x3db4e4e:'488b4608',0x3db4e5e:'4c8b6610',0x3db4e6e:'4883fa04',0x3db4e75:'bb03000000',0x3db4ea1:'48c7471000000000',0x3db4f18:'c6403202'}
def check(r):
 for a,v in pins.items():assert r[a]==bytes.fromhex(v),hex(a)
check(rows)
def target(a):return a+len(rows[a])+int.from_bytes(rows[a][-4:],'little',signed=True)
for a,v in [(0x38b4285,0x3bcb6c0),(0x38b42a1,0x64e6bc8),(0x3bcb6e3,0x3db4e40),(0x3bcb70b,0x3d9b0c0),(0x3bcb749,0x388bf90),(0x3bcb783,0x4564770),(0x3bcb7b2,0x436d300)]:assert target(a)==v
r=next(x for x in s if x['name']=='.rela.dyn');rel={a:(i,d) for a,i,d in struct.iter_unpack('<QQq',b[r['offset']:r['offset']+r['size']])};assert rel[0x64e6bc8]==(8,0x42096d0)
for a in (0x38b423a,0x38b4285,0x3bcb71f,0x3d9b113,0x3d9b127,0x3d9b196,0x3db4e6e):
 m=dict(rows);m[a]=m[a][:-1]+bytes([m[a][-1]^1])
 try:check(m)
 except AssertionError:pass
 else:raise AssertionError(hex(a))
print(f'{len(bodies)} FDEs, {len(rows)} instruction spans, {len(pins)} pins, 7 targets, 1 relocation and 7 controls: OK')
