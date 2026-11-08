#!/usr/bin/env python3
"""Static byte and ordering evidence only; never run the target."""
import csv,hashlib,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86_const import X86_OP_IMM,X86_OP_REG
from elf_index import unwind_index
from fde_extents import eh_frame_records
P=Path('research/work-items/RE-005-node115-clientblocks-blob-budget')
b=Path('artifacts/node/115/hl-node').read_bytes();assert hashlib.sha256(b).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
s,h=unwind_index(b);_,f=eh_frame_records(b,s);idx={(x['start'],x['fde']) for x in h};t=next(x for x in s if x['name']=='.text')
def read(a,n):
 assert t['address']<=a and a+n<=t['address']+t['size'];p=t['offset']+a-t['address'];return b[p:p+n]
bodies={0x5824b60:(0x5824c59,'c633c938aeeb979c077c0cdc1f71ff53f842115044503ac870eb030b2d7e43fe'),0x4e04e90:(0x4e04fb8,'db38152d3e3aa6d9f9336364fd59c52beca5396809a91f1cf5b8a6857172cb95'),0x5821250:(0x5821335,'12341e48e3f53f92ed9caa50ddc8c09b3716795758360fd10e6a869eccd150a2')}
ins={};md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
for a,(z,d) in bodies.items():
 assert any(x['start']==a and x['end']==z and (a,x['fde']) in idx for x in f);raw=read(a,z-a);assert hashlib.sha256(raw).hexdigest()==d
 seq=list(md.disasm(raw,a));assert sum(x.size for x in seq)==len(raw);ins.update({x.address:x for x in seq})
rows={}
with (P/'instructions.tsv').open() as fp:
 for x in csv.DictReader(fp,delimiter='\t'):
  a=int(x['va'],16);v=bytes.fromhex(x['bytes']);assert a not in rows and a in ins and ins[a].bytes==v and read(a,len(v))==v;rows[a]=v
pins={0x4e04ea7:'e884c5a100',0x4e04eac:'803c2401',0x4e04eb0:'7520',0x4e04ee5:'488d15641ad500',0x4e04ef1:'4c89f6',0x4e04ef4:'e867fca100',0x4e04efe:'3c12',0x4e04f00:'754c',0x5824b6e:'4989f6',0x5824b79:'e8d2c6ffff',0x5824b7e:'0fb6442408',0x5824b83:'3c12',0x5824b85:'7529',0x5824b87:'4c8b7c2410',0x5824b8c:'49833e00',0x5824b90:'7442',0x5824b92:'498b4620',0x5824b96:'4c01f8',0x5824b99:'720d',0x5824b9b:'498b4e08',0x5824b9f:'49894620',0x5824ba3:'4839c8',0x5824ba6:'762c',0x5824ba8:'c60302',0x5824bd4:'498b6e18',0x5824bd8:'4c29fd',0x5824bdb:'7305',0x5824bdd:'c60301',0x5824be2:'4d85ff',0x5824be5:'790f',0x5824bf6:'741e',0x5824bfe:'bf01000000',0x5824c03:'4c89fe',0x5824c06:'ff158ca9cb00',0x5824c16:'41bc01000000',0x5824c1c:'498b7610',0x5824c20:'4e8d2c3e',0x5824c24:'4c89e7',0x5824c27:'4c89fa',0x5824c2a:'ff15d8a8cb00',0x5824c30:'4d896e10',0x5824c34:'49896e18',0x5824c38:'4c897b08',0x5824c3c:'4c896310',0x5824c40:'4c897b18',0x5824c44:'c60312'}
def check(r):
 for a,v in pins.items():assert r[a]==bytes.fromhex(v),hex(a)
check(rows)
def rip(a):return a+len(rows[a])+int.from_bytes(rows[a][-4:],'little',signed=True)
for a,v in [(0x4e04ee5,0x5b56950),(0x5824c06,0x64df598),(0x5824c2a,0x64df508)]:assert rip(a)==v
for a,v in [(0x4e04ea7,0x5821430),(0x4e04ef4,0x5824b60),(0x5824b79,0x5821250)]:assert ins[a].operands[0].type==X86_OP_IMM and ins[a].operands[0].imm==v
r=next(x for x in s if x['name']=='.rela.dyn');rel={a:(i,d) for a,i,d in struct.iter_unpack('<QQq',b[r['offset']:r['offset']+r['size']])};assert rel[0x64df598]==(8,0x6355900) and rel[0x64df508]==((7<<32)|6,0)
dyn=next(x for x in s if x['name']=='.dynsym');st=next(x for x in s if x['name']=='.dynstr');p=st['offset']+struct.unpack_from('<I',b,dyn['offset']+7*24)[0];assert b[p:b.index(b'\0',p)]==b'memcpy'
assert not any(x.mnemonic=='call' and x.operands[0].type==X86_OP_REG for a,x in ins.items() if 0x5824b60<=a<0x5824c59)
for mode,c,n,limit,remaining,want in [(1,5,4,8,10,('limit',9)),(1,5,4,9,3,('short',9)),(1,5,4,9,4,('copy',9)),(0,5,4,0,3,('short',5)),(1,(1<<64)-1,1,(1<<64)-1,10,('overflow',None))]:
 total=c+n
 actual=('overflow',None) if mode and total>=1<<64 else (('limit',total) if mode and total>limit else (('short' if remaining<n else 'copy'),total if mode else c))
 assert actual==want
for a in (0x4e04ef4,0x5824b99,0x5824b9f,0x5824ba6,0x5824bdb,0x5824c2a,0x5824c30,0x5824c34,0x5824c44):
 m=dict(rows);m[a]=m[a][:-1]+bytes([m[a][-1]^1])
 try:check(m)
 except AssertionError:pass
 else:raise AssertionError(hex(a))
print(f'{len(bodies)} FDEs, {len(rows)} spans, {len(pins)} pins, 6 targets, 2 relocations, memcpy binding, 5 ordering cases and 9 controls: OK')
