#!/usr/bin/env python3
"""Static evidence checks only; do not execute or emulate target code."""
import csv,hashlib,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86_const import X86_OP_IMM
from elf_index import unwind_index
from fde_extents import eh_frame_records
P=Path('research/work-items/RE-010-node115-variant-generic-errors')
b=Path('artifacts/node/115/hl-node').read_bytes();assert hashlib.sha256(b).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
s,h=unwind_index(b);_,f=eh_frame_records(b,s);idx={(x['start'],x['fde']) for x in h}
def read(sec,a,n):
 t=next(x for x in s if x['name']==sec);assert t['address']<=a and a+n<=t['address']+t['size'];p=t['offset']+a-t['address'];return b[p:p+n]
bodies={0x18bf680:(0x18bf6f6,'9da3454c4d7a9b1973b0b8de193d7693e3b2b8ad6d824e48ecb4b970fb6a36bb'),0x18bfe80:(0x18bfefc,'0ff7d914b9325f09e47cad983085fee6a336fd27dc178fbbe4091e04b8413ccb'),0x18bf480:(0x18bf4fc,'6f4080495af9879385fe22700893f8e7ac2e57399c3d4d104b269226204477df'),0x18be120:(0x18be1ba,'1843d78f492ce208e9a206c7f17e56e5a81e9d88fe9a463346655d81943e8a00'),0x2870370:(0x2871708,'2524f6e53246e22da215b8ebe7ab53d41de13ecaf8d1f4ab5f4c90c5e1636ffb')}
ins={};md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
for a,(z,d) in bodies.items():
 assert any(x['start']==a and x['end']==z and (a,x['fde']) in idx for x in f);raw=read('.text',a,z-a);assert hashlib.sha256(raw).hexdigest()==d
 seq=list(md.disasm(raw,a));assert sum(x.size for x in seq)==len(raw);ins.update({x.address:x for x in seq})
rows={}
with (P/'instructions.tsv').open() as fp:
 for x in csv.DictReader(fp,delimiter='\t'):
  a=int(x['va'],16);v=bytes.fromhex(x['bytes']);assert a not in rows and a in ins and ins[a].bytes==v and read('.text',a,len(v))==v;rows[a]=v
pins={0x18bf688:'c64424380d',0x18bf68d:'488d050c03b604',0x18bf699:'488d05f0d7b504',0x18bf6af:'488b051a08c204',0x18bf6c5:'488d05e4a84801',0x18bf6d1:'4883c708',0x18bf6d5:'488d359ef9b8fe',0x18bf6dc:'488d542418',0x18bf6e1:'e83aeaffff',0x18bf6e6:'48c70301000000',0x18bfe88:'c64424380d',0x18bfe8d:'488d050cfbb504',0x18bfe99:'488d05f0cfb504',0x18bfeaf:'488b051a00c204',0x18bfec5:'488d05e4a04801',0x18bfed1:'4883c708',0x18bfed5:'488d359ef1b8fe',0x18bfedc:'488d542418',0x18bfee1:'e83ae2ffff',0x18bfee6:'48b80000000000000080',0x18bfef0:'488903',0x18bf488:'c64424380d',0x18bf48d:'488d050c05b604',0x18bf499:'488d05f0d9b504',0x18bf4af:'488b051a0ac204',0x18bf4c5:'488d05e4aa4801',0x18bf4d1:'4883c708',0x18bf4d5:'488d359efbb8fe',0x18bf4dc:'488d542418',0x18bf4e1:'e83aecffff',0x18bf4e6:'48b80000000000000080',0x18bf4f0:'488903',0x18be131:'41f6c601',0x18be135:'750e',0x18be13d:'ff15a515c204',0x18be183:'488b442410',0x18be188:'48894318',0x18be18c:'488b0424',0x18be190:'48894308',0x18be194:'488b442408',0x18be199:'48894310',0x18be19d:'c60306',0x2870d20:'e85be904ff',0x2870d2a:'807c240800',0x2870d3c:'b886000000',0x2870d41:'b916000000',0x2870d46:'e963080000',0x28715ae:'480f45c8',0x28715b2:'48890b',0x2870fd9:'e8a2ee04ff',0x2870fe2:'31c9',0x2870fe4:'483b4c2408',0x2870fe9:'0f80d5010000',0x28711ae:'e8cde204ff',0x28711b7:'31c9',0x28711b9:'483b4c2408',0x28711be:'0f81df040000',0x28711c4:'0f10442410',0x28711c9:'0f104c2420',0x28711ce:'0f114810',0x28711d2:'0f1100',0x28711d5:'e9bc040000',0x2871696:'b886000000',0x287169b:'488903'}
def check(r):
 for a,v in pins.items():assert r[a]==bytes.fromhex(v),hex(a)
check(rows)
def rip(a):return a+len(rows[a])+int.from_bytes(rows[a][-4:],'little',signed=True)
for a,v in [(0x18bf68d,0x641f9a0),(0x18bf699,0x641ce90),(0x18bf6af,0x64dfed0),(0x18bf6c5,0x2d49fb0),(0x18bf6d5,0x44f07a),(0x18bfe8d,0x641f9a0),(0x18bfed5,0x44f07a),(0x18bf48d,0x641f9a0),(0x18bf4d5,0x44f07a),(0x18be13d,0x64df6e8)]:assert rip(a)==v
for a,v in [(0x18bf6e1,0x18be120),(0x18bfee1,0x18be120),(0x18bf4e1,0x18be120),(0x2870d20,0x18bf680),(0x2870fd9,0x18bfe80),(0x28711ae,0x18bf480),(0x2870d46,0x28715ae),(0x2870fe9,0x28711c4),(0x28711be,0x28716a3),(0x28711d5,0x2871696)]:
 assert ins[a].operands[0].type==X86_OP_IMM and ins[a].operands[0].imm==v
r=next(x for x in s if x['name']=='.rela.dyn');rel={a:(i,d) for a,i,d in struct.iter_unpack('<QQq',b[r['offset']:r['offset']+r['size']])}
for a,v in [(0x641f9a0,0x5cd121),(0x64dfed0,0x5c4f380),(0x64df6e8,0x141e3a0)]:assert rel[a]==(8,v)
assert read('.data.rel.ro',0x641f9a8,8)==(15).to_bytes(8,'little')
assert read('.rodata',0x5cd121,15)==b'newtype variant'
assert read('.rodata',0x44f07a,30)==b'\x0einvalid type: \xc0\x0b, expected \xc0\x00'
for a in (0x18bf688,0x18bf6e6,0x18bfee6,0x18bf4e6,0x18be19d,0x2870d2a,0x2870fe9,0x28711be,0x2871696):
 m=dict(rows);m[a]=m[a][:-1]+bytes([m[a][-1]^1])
 try:check(m)
 except AssertionError:pass
 else:raise AssertionError(hex(a))
print(f'{len(bodies)} FDEs, {len(rows)} spans, {len(pins)} pins, 20 targets, 3 relocations, 2 literals and 9 controls: OK')
