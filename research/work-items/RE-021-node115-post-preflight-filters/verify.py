#!/usr/bin/env python3
"""Pinned static checks; no target instruction execution or interpretation."""
import csv,hashlib,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from elf_index import unwind_index
from fde_extents import eh_frame_records
b=Path('artifacts/node/115/hl-node').read_bytes();assert hashlib.sha256(b).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
s,h=unwind_index(b);_,f=eh_frame_records(b,s);idx={(x['start'],x['fde']) for x in h}
def read(a,n):
 t=next(x for x in s if x['name']=='.text');assert t['address']<=a and a+n<=t['address']+t['size'];p=t['offset']+a-t['address'];return b[p:p+n]
bodies={0x29a1290:(0x29a5fca,'aff83c384b12d1d6aab814d03a5c80cdef82b626dacd49830bb223f416c83bde'),0x2962aa0:(0x296754d,'880fe617eb64670749f2bbc2eec999ff26e0649d7ef58289af0af7af366ca9ec')}
starts=set()
for a,(z,d) in bodies.items():
 assert any(x['start']==a and x['end']==z and (a,x['fde']) in idx for x in f)
 raw=read(a,z-a);assert hashlib.sha256(raw).hexdigest()==d
 ins=list(Cs(CS_ARCH_X86,CS_MODE_64).disasm(raw,a));assert sum(i.size for i in ins)==len(raw);starts.update(i.address for i in ins)
rows={}
with Path('research/work-items/RE-021-node115-post-preflight-filters/instructions.tsv').open() as fp:
 for x in csv.DictReader(fp,delimiter='\t'):
  a=int(x['va'],16);lo=int(x['fde_start'],16);hi=int(x['fde_end'],16);raw=bytes.fromhex(x['bytes'])
  assert a not in rows and a in starts and lo in bodies and bodies[lo][0]==hi and lo<=a<a+len(raw)<=hi and read(a,len(raw))==raw
  rows[a]=raw
pins={0x29a1fb4:'e8a765ccff',0x29a1fb9:'488b842430020000',0x29a1fc1:'4883f825',0x29a1fc5:'0f8546070000',0x29a1fcb:'80bc24010d000004',0x29a1fd3:'0f8573070000',0x29a1fe5:'488b8424c00c0000',0x29a1ff0:'0f84f00c0000',0x29a2006:'4c8d24c0',0x29a200a:'49c1e404',0x29a203f:'e90c010000',0x29a2140:'4981c790000000',0x29a2147:'4d39e7',0x29a214a:'0f84a80b0000',0x29a2150:'410f104708',0x29a2155:'f3410f6f4f18',0x29a2175:'660feb842420010000',0x29a218c:'744e',0x29a2191:'410f1106',0x29a2195:'49c7461000000000',0x29a219d:'4c89ac2430020000',0x29a21c9:'660fdbc1',0x29a21cd:'660fd7c0',0x29a21d1:'3dffff0000',0x29a21d6:'0f8564ffffff',0x29a21dc:'49837f28ff',0x29a21e1:'0f8459ffffff',0x29a21e7:'41833f01',0x29a21eb:'751f',0x29a21ed:'41807f4800',0x29a21f2:'0f8548ffffff',0x29a21f8:'418b4759',0x29a2200:'410f104749',0x29a2213:'ff15df4ab403',0x29a2219:'80bc243002000001',0x29a2221:'0f8519ffffff',0x29a2252:'e879d2ffff',0x29637a6:'e87552d0ff',0x29637ab:'488b9c2410020000',0x29637b3:'4883fb25',0x29637b7:'756f',0x29637b9:'80bc24e111000004',0x29637c1:'0f85f8060000',0x29637d3:'488b8424a0110000',0x29637de:'0f846f080000',0x29637f9:'488d2cc0',0x29637fd:'48c1e504',0x2963823:'e9c8000000',0x29638e0:'4981c790000000',0x29638e7:'4939ef',0x29638ea:'0f846e070000',0x29638f0:'410f104708',0x29638f5:'f3410f6f4f18',0x2963915:'660feb8424500b0000',0x296392c:'7453',0x2963931:'410f1106',0x2963935:'49c7461000000000',0x2963942:'4889842410020000',0x296396e:'660fdbc1',0x2963972:'660fd7c0',0x2963976:'3dffff0000',0x296397b:'0f855fffffff',0x2963981:'49837f28ff',0x2963986:'0f8454ffffff',0x296398c:'41833f01',0x2963990:'751f',0x2963992:'41807f4800',0x2963997:'0f8543ffffff',0x296399d:'418b4759',0x29639a5:'410f104749',0x29639bd:'ff153533b803',0x29639c3:'80bc241002000001',0x29639cb:'0f850fffffff',0x2963a0c:'ff15d632b803'}
pins.update({0x29a1ff6:'4c8bac24680d0000',0x29a2011:'4c8db42438020000',0x29a218e:'0f57c0',0x29a21a5:'f30f6f842430020000',0x29a21ae:'f30f6f8c2440020000',0x29a21b7:'660f748c2420010000',0x29a21c0:'660f74842410010000',0x29a21fc:'41894609',0x29a2205:'410f1146f9',0x29637e4:'488b8c2448120000',0x29637ec:'48894c2428',0x2963804:'4c8db42418020000',0x296392e:'0f57c0',0x296393d:'488b442428',0x296394a:'f30f6f842410020000',0x2963953:'f30f6f8c2420020000',0x296395c:'660f748c24500b0000',0x2963965:'660f748424400b0000',0x29639a1:'41894609',0x29639aa:'410f1146f9'})
def check(r):
 for a,v in pins.items():assert r[a]==bytes.fromhex(v),hex(a)
check(rows)
def target(a):
 x=rows[a];return a+len(x)+int.from_bytes(x[-4:],'little',signed=True)
for a,t in [(0x29a1fb4,0x2668560),(0x29a1fc5,0x29a2711),(0x29a1fd3,0x29a274c),(0x29a1ff0,0x29a2ce6),(0x29a203f,0x29a2150),(0x29a214a,0x29a2cf8),(0x29a21d6,0x29a2140),(0x29a21e1,0x29a2140),(0x29a21f2,0x29a2140),(0x29a2213,0x64e6cf8),(0x29a2252,0x299f4d0),(0x29637a6,0x2668a20),(0x29637c1,0x2963ebf),(0x29637de,0x2964053),(0x2963823,0x29638f0),(0x29638ea,0x296405e),(0x296397b,0x29638e0),(0x2963986,0x29638e0),(0x2963997,0x29638e0),(0x29639bd,0x64e6cf8),(0x2963a0c,0x64e6ce8)]:assert target(a)==t
r=next(x for x in s if x['name']=='.rela.dyn');rel={a:(i,d) for a,i,d in struct.iter_unpack('<QQq',b[r['offset']:r['offset']+r['size']])};assert rel[0x64e6cf8]==(8,0x5be3b50) and rel[0x64e6ce8]==(8,0x5463980)
for a in (0x29a1fc1,0x29a1fcb,0x29a2140,0x29a21dc,0x29637b3,0x296398c,0x29639c3):
 changed=dict(rows);changed[a]=changed[a][:-1]+bytes([changed[a][-1]^1])
 try:check(changed)
 except AssertionError:pass
 else:raise AssertionError('mutation accepted '+hex(a))
print(f'{len(bodies)} decoded FDEs, {len(rows)} spans, {len(pins)} pins, 21 edges, 2 relocations and 7 corruption controls: OK')
