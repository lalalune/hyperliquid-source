#!/usr/bin/env python3
"""Verify static evidence without running or emulating target code."""
import csv,hashlib,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from elf_index import unwind_index
from fde_extents import eh_frame_records
b=Path('artifacts/node/115/hl-node').read_bytes();assert hashlib.sha256(b).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
s,h=unwind_index(b);_,f=eh_frame_records(b,s);idx={(x['start'],x['fde']) for x in h};t=next(x for x in s if x['name']=='.text')
def read(a,n):
 assert t['address']<=a and a+n<=t['address']+t['size'];p=t['offset']+a-t['address'];return b[p:p+n]
bodies={0x421a8b0:(0x421a9cc,'6f1a63aad6cfbcc1635d94d4cb57cd28153f4714301d3b23da4711bf1e8cc967'),0x447d760:(0x447db37,'cf4de2dcb1267fa4aaf714a66e8b7e1b0b8f0e8c5bbbb3f814fb4de50a7ee774')}
ins={}
for a,(z,d) in bodies.items():
 assert any(x['start']==a and x['end']==z and (a,x['fde']) in idx for x in f);raw=read(a,z-a);assert hashlib.sha256(raw).hexdigest()==d
 seq=list(Cs(CS_ARCH_X86,CS_MODE_64).disasm(raw,a));assert sum(x.size for x in seq)==len(raw);ins.update({x.address:x for x in seq})
rows={}
with Path('research/work-items/RE-007-node115-asset-name-lookup/instructions.tsv').open() as fp:
 for x in csv.DictReader(fp,delimiter='\t'):
  a=int(x['va'],16);v=bytes.fromhex(x['bytes']);assert a not in rows and a in ins and ins[a].bytes==v and read(a,len(v))==v;rows[a]=v
pins={0x421a8be:'4889d3',0x421a8cb:'4c8b6910',0x421a8cf:'4d85ed',0x421a8d4:'b810270000',0x421a8d9:'48f76150',0x421a8dd:'0f80ce000000',0x421a8e6:'488b6908',0x421a8ea:'49c1e505',0x421a900:'4983c620',0x421a904:'49ffc4',0x421a915:'4a3b5c3510',0x421a91c:'4a8b743508',0x421a929:'ff15c9502c02',0x421a92f:'85c0',0x421a931:'75cd',0x421a938:'4c896008',0x421a93c:'66c700a201',0x421a943:'4885db',0x421a958:'ff15224b2c02',0x421a971:'ff15914b2c02',0x421a979:'41bc01000000',0x421a984:'66c7006800',0x421a989:'48895808',0x421a98d:'4c896010',0x421a991:'48895818',0x447da2f:'488d7c2470',0x447da34:'4c89e6',0x447da37:'4c89fa',0x447da3a:'488b4c2448',0x447da3f:'ff15738f0602',0x447da4a:'3da2010000',0x447da57:'4c8b7c2478'}
def check(r):
 for a,v in pins.items():assert r[a]==bytes.fromhex(v),hex(a)
check(rows)
def target(a):return a+len(rows[a])+int.from_bytes(rows[a][-4:],'little',signed=True)
for a,v in [(0x421a8dd,0x421a9b1),(0x421a929,0x64df9f8),(0x421a958,0x64df480),(0x421a971,0x64df508),(0x447da3f,0x64e69b8)]:assert target(a)==v
r=next(x for x in s if x['name']=='.rela.dyn');rel={a:(i,d) for a,i,d in struct.iter_unpack('<QQq',b[r['offset']:r['offset']+r['size']])}
assert rel[0x64e69b8]==(8,0x421a8b0) and rel[0x64df9f8]==((11<<32)|6,0) and rel[0x64df508]==((7<<32)|6,0)
dyn=next(x for x in s if x['name']=='.dynsym');st=next(x for x in s if x['name']=='.dynstr')
for n,name in [(11,b'bcmp'),(7,b'memcpy')]:
 p=st['offset']+struct.unpack_from('<I',b,dyn['offset']+n*24)[0];assert b[p:b.index(b'\0',p)]==name
for a in (0x421a8d4,0x421a8dd,0x421a915,0x421a931,0x421a93c,0x421a984,0x447da3f):
 m=dict(rows);m[a]=m[a][:-1]+bytes([m[a][-1]^1])
 try:check(m)
 except AssertionError:pass
 else:raise AssertionError(hex(a))
print(f'{len(bodies)} FDEs, {len(rows)} instruction spans, {len(pins)} pins, 5 targets, 3 relocations, 2 imports, 7 controls: OK')
