#!/usr/bin/env python3
"""Verify selected static evidence without executing or emulating target code."""
import csv,hashlib,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from elf_index import unwind_index
from fde_extents import eh_frame_records
b=Path('artifacts/node/115/hl-node').read_bytes();assert hashlib.sha256(b).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
s,h=unwind_index(b);_,f=eh_frame_records(b,s);idx={(x['start'],x['fde']) for x in h}
def read(name,a,n):
 t=next(x for x in s if x['name']==name);assert t['address']<=a and a+n<=t['address']+t['size'];p=t['offset']+a-t['address'];return b[p:p+n]
bodies={0x22d7030:(0x22d7a68,'3cb0461454809aa6d4d10d8ace9a95d7ae1a4569bef311060e4b658eba7e6f7f'),0x2d087e0:(0x2d09986,'113f1730ee43d4ecaf1778f3565eb2c70d88e9ce5d39649683f23f459652c596')}
starts=set()
for a,(z,d) in bodies.items():
 assert any(x['start']==a and x['end']==z and (a,x['fde']) in idx for x in f)
 raw=read('.text',a,z-a);assert hashlib.sha256(raw).hexdigest()==d
 ins=list(Cs(CS_ARCH_X86,CS_MODE_64).disasm(raw,a));assert sum(x.size for x in ins)==len(raw);starts.update(i.address for i in ins)
rows={}
with Path('research/work-items/RE-011-node115-eth-call-error-codes/instructions.tsv').open() as fp:
 for x in csv.DictReader(fp,delimiter='\t'):
  a=int(x['va'],16);lo=int(x['fde_start'],16);hi=int(x['fde_end'],16);raw=bytes.fromhex(x['bytes'])
  assert a not in rows and a in starts and lo in bodies and bodies[lo][0]==hi and lo<=a<a+len(raw)<=hi and read('.text',a,len(raw))==raw
  rows[a]=raw
pins={0x22d7044:'4889d3',0x22d704c:'4989ff',0x22d709c:'837b1003',0x22d70a0:'757f',0x22d7121:'8b4b40',0x22d7124:'41be01000000',0x22d712a:'488d15532431fe',0x22d7131:'48630c8a',0x22d7135:'4801d1',0x22d7138:'ffe1',0x22d713a:'c74424144480ffff',0x22d7142:'e95effffff',0x22d71e6:'e8f5323300',0x22d71eb:'4885c0',0x22d71ee:'0f842b010000',0x22d734e:'ff15c4ae2004',0x22d7354:'488b442450',0x22d7359:'4885c0',0x22d735c:'0f8414040000',0x22d736f:'4c8bbc24b0000000',0x22d737f:'45897710',0x22d7383:'8b442414',0x22d7387:'41894714',0x22d7708:'c7442414f782ffff',0x22d7710:'e990f9ffff',0x22d7715:'c7442414a880ffff',0x22d771d:'e983f9ffff',0x22d7722:'c7442414a780ffff',0x22d772a:'e976f9ffff',0x22d772f:'488b4c2418',0x22d7734:'8b4944',0x22d7737:'894c2414',0x22d773b:'e965f9ffff',0x22d7740:'c7442414f982ffff',0x22d7748:'e958f9ffff',0x22d774d:'c7442414a680ffff',0x22d7755:'e94bf9ffff',0x22d775a:'c7442414a580ffff',0x22d7762:'e93ef9ffff',0x2d0928d:'488dbc2400050000',0x2d0929d:'488d942460020000',0x2d092ad:'e87edd5cff',0x2d092d2:'f30f7e842410050000',0x2d092db:'660f7f442460',0x2d0932d:'660f6f442460',0x2d09333:'660fd64010'}
def check(r):
 for a,v in pins.items():assert r[a]==bytes.fromhex(v),hex(a)
check(rows)
def target(a):
 x=rows[a];return a+len(x)+int.from_bytes(x[-4:],'little',signed=True)
for a,t in [(0x22d712a,0x5e9584),(0x22d7142,0x22d70a5),(0x22d71e6,0x260a4e0),(0x22d71ee,0x22d731f),(0x22d734e,0x64e2218),(0x22d735c,0x22d7776),(0x22d7710,0x22d70a5),(0x22d771d,0x22d70a5),(0x22d772a,0x22d70a5),(0x22d773b,0x22d70a5),(0x22d7748,0x22d70a5),(0x22d7755,0x22d70a5),(0x22d7762,0x22d70a5),(0x2d092ad,0x22d7030)]:assert target(a)==t
base=0x5e9584;dst=[base+x for x in struct.unpack('<8i',read('.rodata',base,32))]
assert dst==[0x22d713a,0x22d7740,0x22d7715,0x22d7722,0x22d7708,0x22d774d,0x22d775a,0x22d772f]
r=next(x for x in s if x['name']=='.rela.dyn');rel={a:(i,d) for a,i,d in struct.iter_unpack('<QQq',b[r['offset']:r['offset']+r['size']])};assert rel[0x64e2218]==(8,0x5c55c30)
for a in (0x22d709c,0x22d7121,0x22d713a,0x22d7734,0x22d7387,0x2d09333):
 changed=dict(rows);changed[a]=changed[a][:-1]+bytes([changed[a][-1]^1])
 try:check(changed)
 except AssertionError:pass
 else:raise AssertionError('mutation accepted '+hex(a))
print(f'{len(bodies)} decoded FDEs, {len(rows)} spans, {len(pins)} pins, 14 edges, 8 table entries, 1 relocation and 6 corruption controls: OK')
