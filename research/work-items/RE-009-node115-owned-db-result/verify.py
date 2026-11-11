#!/usr/bin/env python3
"""Verify pinned static evidence; never execute or emulate target instructions."""
import csv,hashlib,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from elf_index import unwind_index
from fde_extents import eh_frame_records
b=Path('artifacts/node/115/hl-node').read_bytes()
assert hashlib.sha256(b).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
s,h=unwind_index(b);_,f=eh_frame_records(b,s);idx={(x['start'],x['fde']) for x in h}
def read(a,n):
 t=next(x for x in s if x['name']=='.text');p=t['offset']+a-t['address'];assert t['address']<=a and a+n<=t['address']+t['size'];return b[p:p+n]
bodies={0x37bee70:(0x37befc6,'3eedd3d8dbccd26bd1b4f51c70e649c5a51374777f9414ec0a5d0a36168e403b'),0x3d5ed10:(0x3d6032d,'2c68ab9058f7bda8bca6d59c1c419afe879d10754ee3ccb8ca7a58ab2c5873dd'),0x4524660:(0x4524adb,'dc1e605f41e2852c1abf20beae609aadff947c84de7f227e46481758a04760bf')}
starts=set()
for a,(z,d) in bodies.items():
 assert any(x['start']==a and x['end']==z and (a,x['fde']) in idx for x in f)
 raw=read(a,z-a);assert hashlib.sha256(raw).hexdigest()==d
 ins=list(Cs(CS_ARCH_X86,CS_MODE_64).disasm(raw,a));assert sum(x.size for x in ins)==len(raw);starts.update(x.address for x in ins)
rows={}
with Path('research/work-items/RE-009-node115-owned-db-result/instructions.tsv').open() as fp:
 for x in csv.DictReader(fp,delimiter='\t'):
  a=int(x['va'],16);lo=int(x['fde_start'],16);hi=int(x['fde_end'],16);raw=bytes.fromhex(x['bytes'])
  assert a not in rows and a in starts and lo in bodies and bodies[lo][0]==hi and lo<=a<a+len(raw)<=hi and read(a,len(raw))==raw
  rows[a]=raw
pins={
0x452486b:'498b542418',0x4524870:'498b4c2420',0x452487f:'4531c0',0x4524882:'e889a483ff',0x4524889:'483b442468',0x452488e:'0f80ea000000',0x45248c9:'4c896350',
0x37bee85:'4885ff',0x37bee88:'0f84c5000000',0x37bef53:'49892c24',
0x3d5ed27:'4989cf',0x3d5ed30:'4889942438010000',0x3d5ed48:'4d85c0',0x3d5ed4b:'741b',0x3d5ed87:'48c784245801000000000000',0x3d5edb7:'e8b400a6ff',0x3d5edcc:'488b842458010000',0x3d5ee28:'488bac2410010000',0x3d5eebe:'0f81f3000000',0x3d5eef6:'ff15441a7802',0x3d5eeff:'0f8492010000',0x3d5f0af:'4885ed',0x3d5f0b2:'0f84f0010000',0x3d5f2c3:'ff15c77c7802',0x3d5f2ce:'4885db',0x3d5f2d1:'745e',0x3d5f334:'e9cd050000',0x3d5f906:'4885c0',0x3d5f909:'743a',0x3d5f90b:'4989c4',0x3d5f911:'0f8412010000',0x3d5f92f:'488bb42438010000',0x3d5f937:'4c89fa',0x3d5f93a:'ff15c8fb7702',0x3d5f940:'e9e9000000',0x3d5f987:'48b80000000000000080',0x3d5f991:'488901',0x3d5fa29:'bb01000000',0x3d5fabf:'48894128',0x3d5facb:'0f114118',0x3d5fad4:'0f114138',0x3d5fadd:'48894148',0x3d5fae1:'4c8939',0x3d5fae4:'48895908',0x3d5fae8:'4c897910',0x3d5faec:'4c896130'}
pins.update({0x37bee7e:'4c8b22',0x37bee81:'488b6a08',0x3d5ed2d:'4989fd',0x3d5ed68:'b808000000',0x3d5ed6d:'31c9',0x3d5ed9b:'48894c2478',0x3d5eda0:'48c784248000000000000000',0x3d5edac:'488d542478',0x3d5edb1:'4c89f7',0x3d5edd4:'4889842410010000',0x3d5f2ad:'48c744246000000000',0x3d5f2b6:'488d542460',0x3d5f2c9:'488b5c2460',0x3d5f331:'41b501',0x3d5f90e:'4d85ff',0x3d5f917:'4c89ff',0x3d5f91a:'ff1560fb7702',0x3d5f929:'4889c3',0x3d5f92c:'4889c7',0x3d5f973:'48c741081e000000',0x3d5f97b:'48894110',0x3d5f97f:'48c741181e000000',0x3d5faad:'e81e0fee01',0x3d5faba:'488b4c2458',0x4524875:'488d7c2468',0x4524894:'0f108424a8000000',0x45248a0:'0f10442468',0x45248be:'0f115320',0x45248c2:'0f114b10',0x45248c6:'0f1103'})
def check(r):
 for a,v in pins.items():assert r[a]==bytes.fromhex(v),hex(a)
check(rows)
def target(a):
 raw=rows[a];return a+len(raw)+int.from_bytes(raw[-4:],'little',signed=True)
for a,t in [(0x4524882,0x3d5ed10),(0x3d5edb7,0x37bee70),(0x3d5eef6,0x64e0940),(0x3d5eeff,0x3d5f097),(0x3d5f0b2,0x3d5f2a8),(0x3d5f2c3,0x64e6f90),(0x3d5f334,0x3d5f906),(0x3d5f911,0x3d5fa29),(0x3d5f93a,0x64df508),(0x3d5f940,0x3d5fa2e),(0x452488e,0x452497e)]:assert target(a)==t
r=next(x for x in s if x['name']=='.rela.dyn');rel={a:(i,d) for a,i,d in struct.iter_unpack('<QQq',b[r['offset']:r['offset']+r['size']])}
assert rel[0x64e0940]==(8,0x5c8f4c0) and rel[0x64e6f90]==(8,0x5d33cb0)
assert rel[0x64df480]==(8,0x6355830) and rel[0x64df508]==((7<<32)|6,0)
dyn=next(x for x in s if x['name']=='.dynsym');strings=next(x for x in s if x['name']=='.dynstr')
name=struct.unpack_from('<I',b,dyn['offset']+7*24)[0];start=strings['offset']+name;assert b[start:b.index(b'\0',start)]==b'memcpy'
ro=next(x for x in s if x['name']=='.rodata');start=ro['offset']+0x7bd805-ro['address'];assert b[start:start+30]==b'Could not initialize database.'
for a in (0x452487f,0x3d5f0b2,0x3d5f2d1,0x3d5f991,0x3d5faec):
 altered=dict(rows);altered[a]=altered[a][:-1]+bytes([altered[a][-1]^1])
 try:check(altered)
 except AssertionError:pass
 else:raise AssertionError('mutation accepted '+hex(a))
print(f'{len(bodies)} FDEs, {len(rows)} instructions, {len(pins)} semantic pins, 11 target edges, 4 relocations, 1 import, 1 literal, 5 mutation controls: OK')
