#!/usr/bin/env python3
"""Verify static ELF evidence; never execute or emulate target instructions."""
import csv,hashlib,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from elf_index import unwind_index
from fde_extents import eh_frame_records
b=Path('artifacts/node/115/hl-node').read_bytes();assert hashlib.sha256(b).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
s,h=unwind_index(b);_,f=eh_frame_records(b,s);idx={(x['start'],x['fde']) for x in h}
def read(name,a,n):
 t=next(x for x in s if x['name']==name);assert t['address']<=a and a+n<=t['address']+t['size'];p=t['offset']+a-t['address'];return b[p:p+n]
bodies={0x5a81ed0:(0x5a820c3,'29d5e00e750f07cc884ce108fb3ad224770ac9fbc0b415800e386a8060dd5f39'),0x15d6ef0:(0x15d6fc4,'e2216cdf32fe765abbb91798b77e4c2a7395777b567114eca2190a3aae06b373')}
starts=set()
for a,(z,d) in bodies.items():
 assert any(x['start']==a and x['end']==z and (a,x['fde']) in idx for x in f)
 raw=read('.text',a,z-a);assert hashlib.sha256(raw).hexdigest()==d
 ins=list(Cs(CS_ARCH_X86,CS_MODE_64).disasm(raw,a));assert sum(x.size for x in ins)==len(raw);starts.update(i.address for i in ins)
for a,z in ((0x5a82670,0x5a89535),(0x5a5c610,0x5a5ca8f)):
 assert any(x['start']==a and x['end']==z and (a,x['fde']) in idx for x in f)
rows={}
with Path('research/work-items/RE-005-node115-block-pipeline-descriptor/instructions.tsv').open() as fp:
 for x in csv.DictReader(fp,delimiter='\t'):
  a=int(x['va'],16);lo=int(x['fde_start'],16);hi=int(x['fde_end'],16);raw=bytes.fromhex(x['bytes'])
  assert a not in rows and a in starts and lo in bodies and bodies[lo][0]==hi and lo<=a<a+len(raw)<=hi and read('.text',a,len(raw))==raw
  rows[a]=raw
pins={0x5a81f17:'4d89c7',0x5a81f1a:'4989d6',0x5a81f1d:'89f5',0x5a81f1f:'4889fb',0x5a81fab:'4c89b42428010000',0x5a81fb3:'488d7c2410',0x5a81fb8:'ba18010000',0x5a81fbd:'4889de',0x5a81fc0:'ff1542d5a500',0x5a81fc6:'4c89bc2430010000',0x5a81fce:'4088ac24b4010000',0x5a81fd6:'c68424b501000000',0x5a81fde:'bf802d0000',0x5a81fe3:'ff1597d4a500',0x5a81fe9:'4885c0',0x5a81fec:'7460',0x5a81fee:'4889c3',0x5a81ff1:'488d058a99ebfa',0x5a81ff8:'4531f6',0x5a81ffb:'4084ed',0x5a81ffe:'4c0f45f0',0x5a82002:'488d742410',0x5a82007:'ba802d0000',0x5a8200c:'4889df',0x5a8200f:'ff15f3d4a500',0x5a82015:'488d0d8c71a300',0x5a8201c:'be1f000000',0x5a82021:'4c89f7',0x5a82024:'4889da',0x5a82036:'ff251cf7a500',0x15d6efb:'4889cb',0x15d6efe:'4989d6',0x15d6f01:'4885ff',0x15d6f04:'741c',0x15d6f0e:'7556',0x15d6f15:'4c89f1',0x15d6f18:'4989d8',0x15d6f1b:'e810f8ffff',0x15d6f29:'4c89f7',0x15d6f2c:'4889de',0x15d6f2f:'e8ac3affff'}
def check(r):
 for a,v in pins.items():assert r[a]==bytes.fromhex(v),hex(a)
check(rows)
def target(a):
 raw=rows[a];return a+len(raw)+int.from_bytes(raw[-4:],'little',signed=True)
for a,t in [(0x5a81fc0,0x64df508),(0x5a81fe3,0x64df480),(0x5a81ff1,0x93b982),(0x5a8200f,0x64df508),(0x5a82015,0x64b91a8),(0x5a82036,0x64e1758),(0x15d6f1b,0x15d6730),(0x15d6f2f,0x15ca9e0)]:assert target(a)==t
r=next(x for x in s if x['name']=='.rela.dyn');rel={a:(i,d) for a,i,d in struct.iter_unpack('<QQq',b[r['offset']:r['offset']+r['size']])}
for a,t in [(0x64b91a8,0x5a5c610),(0x64b91c0,0x5a82670),(0x64e1758,0x15d6ef0),(0x64df480,0x6355830)]:assert rel[a]==(8,t)
assert rel[0x64df508]==((7<<32)|6,0)
dyn=next(x for x in s if x['name']=='.dynsym');st=next(x for x in s if x['name']=='.dynstr');n=struct.unpack_from('<I',b,dyn['offset']+7*24)[0];p=st['offset']+n;assert b[p:b.index(b'\0',p)]==b'memcpy'
assert struct.unpack('<QQ',read('.data.rel.ro',0x64b91b0,16))==(0x2d80,8)
assert read('.rodata',0x93b982,31)==b'nv_stream_forward_client_blocks'
for a in (0x5a81fb8,0x5a81fce,0x5a82007,0x5a82015,0x15d6f18):
 changed=dict(rows);changed[a]=changed[a][:-1]+bytes([changed[a][-1]^1])
 try:check(changed)
 except AssertionError:pass
 else:raise AssertionError('mutation accepted '+hex(a))
print(f'{len(bodies)} decoded FDEs, 2 target FDEs, {len(rows)} spans, {len(pins)} pins, 8 targets, 5 relocations, 1 import, 1 literal and 5 mutations: OK')
