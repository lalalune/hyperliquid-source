#!/usr/bin/env python3
"""Authenticate static vector-budget evidence; do not run target code."""
import csv,hashlib,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86_const import X86_OP_IMM
from elf_index import unwind_index
from fde_extents import eh_frame_records
P=Path('research/work-items/RE-005-node115-clientblocks-vector-budget')
b=Path('artifacts/node/115/hl-node').read_bytes();assert hashlib.sha256(b).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
s,h=unwind_index(b);_,f=eh_frame_records(b,s);idx={(x['start'],x['fde']) for x in h};t=next(x for x in s if x['name']=='.text')
def read(a,n):
 assert t['address']<=a and a+n<=t['address']+t['size'];p=t['offset']+a-t['address'];return b[p:p+n]
bodies={0x5aac7c0:(0x5aacc22,'3e0159ca16b60928de905e585f823776c42d39b592da8d78895ba5644a335668'),0x5824f20:(0x5825192,'b5062c7e55d91bdee8d2b908894ac96e19d88748a7ad01db3fbe908fd2c7187f'),0x5ab7f10:(0x5ab7f5a,'43ac297470e8c9994d5f10a8798a2a168dd9dc0ca3c31ac274001979515c5f0a'),0x5821250:(0x5821335,'12341e48e3f53f92ed9caa50ddc8c09b3716795758360fd10e6a869eccd150a2')}
ins={};md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
for a,(z,d) in bodies.items():
 assert any(x['start']==a and x['end']==z and (a,x['fde']) in idx for x in f);raw=read(a,z-a);assert hashlib.sha256(raw).hexdigest()==d
 seq=list(md.disasm(raw,a));assert sum(x.size for x in seq)==len(raw);ins.update({x.address:x for x in seq})
rows={}
with (P/'instructions.tsv').open() as fp:
 for x in csv.DictReader(fp,delimiter='\t'):
  a=int(x['va'],16);v=bytes.fromhex(x['bytes']);assert a not in rows and a in ins and ins[a].bytes==v and read(a,len(v))==v;rows[a]=v
pins={0x5aac96c:'488d159db50000',0x5aac973:'4889e7',0x5aac976:'4c89f6',0x5aac979:'e8a285d7ff',0x5aac97e:'0fb62c24',0x5aac982:'4080fd12',0x5aac986:'0f8543020000',0x5aac99e:'48c70303000000',0x5824f2e:'4989d6',0x5824f31:'4989f7',0x5824f3c:'e80fc3ffff',0x5824f41:'0fb6442420',0x5824f46:'3c12',0x5824f48:'7540',0x5824f4f:'488b6c2428',0x5824f54:'49833f00',0x5824f58:'7457',0x5824f5d:'48c1e83c',0x5824f61:'751a',0x5824f66:'48c1e004',0x5824f6a:'49034720',0x5824f6e:'720d',0x5824f70:'498b4f08',0x5824f74:'49894720',0x5824f78:'4839c8',0x5824f7b:'7634',0x5824f82:'c60302',0x5824fb1:'4881fd00000100',0x5824fb8:'41bd00000100',0x5824fbe:'4c0f42ed',0x5824fc2:'4885ed',0x5824fc5:'0f84b4000000',0x5824fce:'41c1e404',0x5824fd5:'ff15a5a4cb00',0x5825015:'48ffc3',0x582501d:'48ffcd',0x5825022:'49833f00',0x5825028:'498b4720',0x582502c:'4883f810',0x5825030:'0f82e7000000',0x5825036:'4883c0f0',0x582503a:'49894720',0x5825043:'4c89fe',0x5825046:'41ffd6',0x5825049:'0fb6442420',0x582504e:'3c12',0x5825050:'756d',0x582506b:'483b5c2408',0x5825077:'ff15a3ffcb00',0x582507f:'48c744240800000000',0x5825088:'48c744241008000000',0x5825091:'48c744241800000000',0x58250a4:'48894318',0x58250ad:'48894308',0x58250b6:'48894310',0x58250ba:'c60312',0x58250e6:'488d7c2408',0x58250eb:'e860743200',0x5825105:'ff1595a3cb00',0x5ab7f1b:'e8702e50ff',0x5ab7f24:'3c12',0x5ab7f4f:'8803'}
def check(r):
 for a,v in pins.items():assert r[a]==bytes.fromhex(v),hex(a)
check(rows)
def rip(a):return a+len(rows[a])+int.from_bytes(rows[a][-4:],'little',signed=True)
for a,v in [(0x5aac96c,0x5ab7f10),(0x5824fd5,0x64df480),(0x5825077,0x64e5020),(0x5825105,0x64df4a0)]:assert rip(a)==v
for a,v in [(0x5aac979,0x5824f20),(0x5aac986,0x5aacbcf),(0x5824f3c,0x5821250),(0x5824fc5,0x582507f),(0x5825030,0x582511d),(0x5825050,0x58250bf),(0x58250eb,0x5b4c550),(0x5ab7f1b,0x4fbad90)]:assert ins[a].operands[0].type==X86_OP_IMM and ins[a].operands[0].imm==v
r=next(x for x in s if x['name']=='.rela.dyn');rel={a:(i,d) for a,i,d in struct.iter_unpack('<QQq',b[r['offset']:r['offset']+r['size']])}
for a,v in [(0x64df480,0x6355830),(0x64e5020,0x5962620),(0x64df4a0,0x635de30)]:assert rel[a]==(8,v)
for n,old,limit,want in [(0,10,10,('ok',10)),(2,20,51,('limit',52)),(2,20,52,('ok',52)),(1,(1<<64)-15,(1<<64)-1,('overflow',None)),(1<<60,0,(1<<64)-1,('overflow',None))]:
 total=n*16+old;actual=('overflow',None) if n>>60 or total>=1<<64 else (('limit' if total>limit else 'ok'),total);assert actual==want
assert min(65537,65536)*16==1048576
for a in (0x5aac96c,0x5824f5d,0x5824f6e,0x5824f74,0x5824fb8,0x5825036,0x5825046,0x58250ba,0x58250eb):
 m=dict(rows);m[a]=m[a][:-1]+bytes([m[a][-1]^1])
 try:check(m)
 except AssertionError:pass
 else:raise AssertionError(hex(a))
print(f'{len(bodies)} FDEs, {len(rows)} spans, {len(pins)} pins, 12 targets, 3 relocations, 6 arithmetic cases and 9 controls: OK')
