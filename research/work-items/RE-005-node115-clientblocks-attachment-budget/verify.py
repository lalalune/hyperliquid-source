#!/usr/bin/env python3
"""Digest-bound static evidence checks; no target execution or emulation."""
import csv,hashlib,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86_const import X86_OP_IMM
from elf_index import unwind_index
from fde_extents import eh_frame_records
P=Path('research/work-items/RE-005-node115-clientblocks-attachment-budget')
b=Path('artifacts/node/115/hl-node').read_bytes();assert hashlib.sha256(b).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
s,h=unwind_index(b);_,f=eh_frame_records(b,s);idx={(x['start'],x['fde']) for x in h};t=next(x for x in s if x['name']=='.text')
def read(a,n):
 assert t['address']<=a and a+n<=t['address']+t['size'];p=t['offset']+a-t['address'];return b[p:p+n]
bodies={0x5824840:(0x5824b5b,'b6e022d43edcdff560d395a9eff26aae32df752863550d674cfdb449abfb4f4f'),0x4fbad90:(0x4fbb008,'4a5b944abd869caae825297d31713122eb729fb397707c4f5b447178f3a3a2b9'),0x4e04e90:(0x4e04fb8,'db38152d3e3aa6d9f9336364fd59c52beca5396809a91f1cf5b8a6857172cb95'),0x5824b60:(0x5824c59,'c633c938aeeb979c077c0cdc1f71ff53f842115044503ac870eb030b2d7e43fe'),0x5ab7f10:(0x5ab7f5a,'43ac297470e8c9994d5f10a8798a2a168dd9dc0ca3c31ac274001979515c5f0a')}
ins={};md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
for a,(z,d) in bodies.items():
 assert any(x['start']==a and x['end']==z and (a,x['fde']) in idx for x in f);raw=read(a,z-a);assert hashlib.sha256(raw).hexdigest()==d
 seq=list(md.disasm(raw,a));assert sum(x.size for x in seq)==len(raw);ins.update({x.address:x for x in seq})
rows={}
with (P/'instructions.tsv').open() as fp:
 for x in csv.DictReader(fp,delimiter='\t'):
  a=int(x['va'],16);v=bytes.fromhex(x['bytes']);assert a not in rows and a in ins and ins[a].bytes==v and read(a,len(v))==v;rows[a]=v
pins={0x5ab7f18:'4889e7',0x5ab7f1b:'e8702e50ff',0x4fbad9f:'4989f7',0x4fbaec1:'488d15c89fe4ff',0x4fbaecd:'4c89fe',0x4fbaed0:'e86b998600',0x4fbaeda:'3c12',0x5824851:'4989d6',0x5824854:'4989f7',0x582485f:'e8ecc9ffff',0x5824869:'3c12',0x582486d:'4c8b642420',0x5824872:'49833f00',0x5824876:'744f',0x5824878:'b928000000',0x582487d:'4c89e0',0x5824880:'48f7e1',0x5824883:'7013',0x5824885:'49034720',0x5824889:'720d',0x582488b:'498b4f08',0x582488f:'49894720',0x5824893:'4839c8',0x5824896:'762f',0x5824898:'c60302',0x58248c7:'4981fc66660000',0x58248ce:'bd66660000',0x58248d3:'490f42ec',0x58248d7:'4d85e4',0x58248e0:'8d04ed00000000',0x58248e7:'4c8d2c80',0x58248ee:'ff158cabcb00',0x5824950:'48ffc5',0x5824958:'49ffcc',0x5824961:'49833f00',0x5824967:'498b4720',0x582496b:'4883f828',0x582496f:'0f822e010000',0x5824975:'4883c0d8',0x5824979:'49894720',0x5824982:'4c89fe',0x5824985:'41ffd6',0x5824988:'4c8b6c2438',0x58249a1:'4d85ed',0x58249a4:'7472',0x58249d4:'ff154e06cc00',0x58249df:'48c7042400000000',0x58249e7:'48c744240808000000',0x58249f0:'48c744241000000000',0x5824a13:'c60312',0x5824a18:'0f28442440',0x5824a22:'0f114b10',0x5824a26:'0f1103',0x5824a88:'ff1512aacb00',0x4e04ee5:'488d15641ad500',0x4e04ef1:'4c89f6',0x4e04ef4:'e867fca100',0x4e04efe:'3c12',0x4e04f00:'754c',0x4e04f16:'ff1564a56d01',0x4e04f70:'31c0',0x4e04f72:'48894320',0x5824b96:'4c01f8',0x5824b9f:'49894620',0x5824bd8:'4c29fd',0x5824c30:'4d896e10'}
def check(r):
 for a,v in pins.items():assert r[a]==bytes.fromhex(v),hex(a)
check(rows)
def rip(a):return a+len(rows[a])+int.from_bytes(rows[a][-4:],'little',signed=True)
for a,v in [(0x4fbaec1,0x4e04e90),(0x4e04ee5,0x5b56950),(0x58248ee,0x64df480),(0x58249d4,0x64e5028),(0x5824a88,0x64df4a0),(0x4e04f16,0x64df480)]:assert rip(a)==v
for a,v in [(0x5ab7f1b,0x4fbad90),(0x4fbaed0,0x5824840),(0x582485f,0x5821250),(0x582496f,0x5824aa3),(0x58249a4,0x5824a18),(0x4e04ef4,0x5824b60)]:assert ins[a].operands[0].type==X86_OP_IMM and ins[a].operands[0].imm==v
r=next(x for x in s if x['name']=='.rela.dyn');rel={a:(i,d) for a,i,d in struct.iter_unpack('<QQq',b[r['offset']:r['offset']+r['size']])}
for a,v in [(0x64df480,0x6355830),(0x64e5028,0x5962770),(0x64df4a0,0x635de30)]:assert rel[a]==(8,v)
for n,c,limit,want in [(0,5,5,('ok',5)),(1,5,44,('limit',45)),(1,5,45,('ok',45)),((1<<64)//40+1,0,(1<<64)-1,('overflow',None))]:
 total=c+n*40;actual=('overflow',None) if n*40>=1<<64 or total>=1<<64 else (('limit' if total>limit else 'ok'),total);assert actual==want
assert 0x6666==26214 and min(26215,0x6666)*40==1048560
assert (5+40)-40==5
for a in (0x4fbaec1,0x5824878,0x5824883,0x582488f,0x58248ce,0x5824975,0x5824985,0x58249a4,0x4e04f72,0x5824b9f):
 m=dict(rows);m[a]=m[a][:-1]+bytes([m[a][-1]^1])
 try:check(m)
 except AssertionError:pass
 else:raise AssertionError(hex(a))
print(f'{len(bodies)} FDEs, {len(rows)} spans, {len(pins)} pins, 12 targets, 3 relocations, 6 arithmetic cases and 10 controls: OK')
