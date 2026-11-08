#!/usr/bin/env python3
"""Static #115 evidence verification, with no target execution or emulation."""
import csv,hashlib,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from elf_index import unwind_index
from fde_extents import eh_frame_records
P=Path('research/work-items/RE-007-node115-asset-conversion-scale')
b=Path('artifacts/node/115/hl-node').read_bytes();assert hashlib.sha256(b).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
s,h=unwind_index(b);_,f=eh_frame_records(b,s);idx={(x['start'],x['fde']) for x in h};t=next(x for x in s if x['name']=='.text')
def read(a,n):
 assert t['address']<=a and a+n<=t['address']+t['size'];p=t['offset']+a-t['address'];return b[p:p+n]
bodies={0x421e9d0:(0x421ecb4,'3982b2915d6184f86433f359c537f1347c617488580be1e6c9997b3b859e8377'),0x3c42660:(0x3c4287e,'6897c78dff74312b8533a483928cc05590eff629c584b5036db4af231f6492f1')}
ins={}
for a,(z,d) in bodies.items():
 assert any(x['start']==a and x['end']==z and (a,x['fde']) in idx for x in f);raw=read(a,z-a);assert hashlib.sha256(raw).hexdigest()==d
 seq=list(Cs(CS_ARCH_X86,CS_MODE_64).disasm(raw,a));assert sum(x.size for x in seq)==len(raw);ins.update({x.address:x for x in seq})
rows={}
with (P/'instructions.tsv').open() as fp:
 for x in csv.DictReader(fp,delimiter='\t'):
  a=int(x['va'],16);v=bytes.fromhex(x['bytes']);assert a not in rows and a in ins and ins[a].bytes==v and read(a,len(v))==v;rows[a]=v
pins={0x3c426bb:'0fb644011d',0x3c426c0:'3c07',0x3c426c2:'0f83a9010000',0x3c426cb:'b106',0x3c426cd:'28c1',0x3c426cf:'0fb6c9',0x3c426df:'ba02000000',0x3c426e4:'ff157e3d8a02',0x3c426ea:'66817c2410a201',0x3c426f3:'4c8b7c2418',0x3c426f8:'4d85ff',0x3c426fb:'0f84f3000000',0x3c42718:'4c897b10',0x421e9dc:'89d5',0x421e9e1:'b801000000',0x421e9e6:'84c9',0x421e9ea:'f6c101',0x421e9ef:'b80a000000',0x421e9fd:'f6c102',0x421ea02:'486bc064',0x421ea11:'f6c104',0x421ea16:'4869c010270000',0x421ea28:'f6c108',0x421ea2d:'4869c000e1f505',0x421ea3f:'66bfac00',0x421ea43:'f6c110',0x421ea48:'48b90000c16ff2862300',0x421ea52:'48f7e1',0x421ea66:'f30f6f06',0x421ea79:'4889442438',0x421ea8d:'ff150dbc2c02',0x421ea93:'837c240c00',0x421ea9a:'66bfac00',0x421ea9e:'66893b',0x421eabd:'4084ed',0x421eac6:'400fb6c5',0x421eaca:'83f801',0x421eb7a:'488d7c240c',0x421eb88:'ff1522bb2c02',0x421eba4:'ff15feba2c02',0x421ebcf:'448b4c2420',0x421ebd4:'4585c9',0x421ebd7:'0f88c1feffff',0x421ec84:'0f8514feffff',0x421ec94:'48b9feffffffffffff7f',0x421ec9e:'4839c8',0x421eca1:'0f87f7fdffff',0x421eca7:'48894308',0x421ecab:'66bfa201'}
def check(r):
 for a,v in pins.items():assert r[a]==bytes.fromhex(v),hex(a)
check(rows)
def target(a):return a+len(rows[a])+int.from_bytes(rows[a][-4:],'little',signed=True)
for a,v in [(0x3c426c2,0x3c42871),(0x3c426e4,0x64e6468),(0x3c426fb,0x3c427f4),(0x421ea8d,0x64ea6a0),(0x421eb88,0x64ea6b0),(0x421eba4,0x64ea6a8),(0x421eca1,0x421ea9e)]:assert target(a)==v
r=next(x for x in s if x['name']=='.rela.dyn');rel={a:(i,d) for a,i,d in struct.iter_unpack('<QQq',b[r['offset']:r['offset']+r['size']])}
for a,v in [(0x64e6468,0x421e9d0),(0x64ea6a0,0x5c457a0),(0x64ea6b0,0x5c442f0),(0x64ea6a8,0x5c448a0)]:assert rel[a]==(8,v)
for A,want in enumerate((1000000,100000,10000,1000,100,10,1)):
 n=6-A;factor=(10 if n&1 else 1)*(100 if n&2 else 1)*(10000 if n&4 else 1);assert factor==want==10**n
for a in (0x3c426c0,0x3c426cd,0x3c426df,0x421e9ef,0x421ea02,0x421ea16,0x421ec94,0x421ecab):
 m=dict(rows);m[a]=m[a][:-1]+bytes([m[a][-1]^1])
 try:check(m)
 except AssertionError:pass
 else:raise AssertionError(hex(a))
print(f'{len(bodies)} FDEs, {len(rows)} instruction spans, {len(pins)} pins, 7 targets, 4 relocations, 7 scale cases and 8 controls: OK')
