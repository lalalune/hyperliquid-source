#!/usr/bin/env python3
"""Static target-byte and layout checks; no target execution or emulation."""
import csv,hashlib,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from elf_index import unwind_index
from fde_extents import eh_frame_records
b=Path('artifacts/node/115/hl-node').read_bytes();assert hashlib.sha256(b).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
s,h=unwind_index(b);_,f=eh_frame_records(b,s);idx={(x['start'],x['fde']) for x in h}
def read(a,n):
 t=next(x for x in s if x['name']=='.text');assert t['address']<=a and a+n<=t['address']+t['size'];p=t['offset']+a-t['address'];return b[p:p+n]
bodies={0x2972390:(0x2972c20,'f47ba29ca1c91c4bb21e63de7cfa7f860f5ad05a2cd8ab9fb4d58a16165b8bcf'),0x2994e90:(0x2994f1e,'819cc3ce7dafff758f3d35c5d2428e591645c16906b8d9f494b1a5efed9d5abe')}
starts=set()
for a,(z,d) in bodies.items():
 assert any(x['start']==a and x['end']==z and (a,x['fde']) in idx for x in f)
 raw=read(a,z-a);assert hashlib.sha256(raw).hexdigest()==d
 ins=list(Cs(CS_ARCH_X86,CS_MODE_64).disasm(raw,a));assert sum(x.size for x in ins)==len(raw);starts.update(i.address for i in ins)
rows={}
with Path('research/work-items/RE-011-node115-transient-journal/instructions.tsv').open() as fp:
 for x in csv.DictReader(fp,delimiter='\t'):
  a=int(x['va'],16);lo=int(x['fde_start'],16);hi=int(x['fde_end'],16);raw=bytes.fromhex(x['bytes'])
  assert a not in rows and a in starts and lo in bodies and bodies[lo][0]==hi and lo<=a<a+len(raw)<=hi and read(a,len(raw))==raw
  rows[a]=raw
pins={0x29723a1:'4889d3',0x29723a4:'f30f6f01',0x29723a8:'f30f6f4910',0x29723ad:'660febc8',0x29723b5:'660f76c1',0x29723b9:'0f50c0',0x29723bc:'83f00f',0x29723bf:'0f840b010000',0x29724d0:'4883bf0801000000',0x29724d8:'0f84d6040000',0x2972812:'410f1045e0',0x2972817:'410f104df0',0x2972826:'0f1001',0x2972829:'0f104910',0x297282d:'410f1145e0',0x2972832:'410f114df0',0x2972837:'e9a8000000',0x29728d7:'0f57c0',0x29728da:'0f29442460',0x29728df:'0f29442470',0x29728e4:'f30f6f01',0x29728e8:'f30f6f4910',0x29728ed:'660f744c2470',0x29728f3:'660f74442460',0x29728fd:'660fd7c0',0x2972901:'3dffff0000',0x2972906:'0f84a8000000',0x2972916:'660f7f8c24a0000000',0x2972939:'488b5f28',0x297293d:'483b5f18',0x2972941:'7519',0x2972950:'ff159a43b703',0x2972960:'486bcb58',0x2972964:'c604080a',0x2972968:'8b5610',0x297296b:'89540811',0x297296f:'0f1006',0x2972972:'0f11440801',0x2972977:'0f10442420',0x297297c:'0f104c2430',0x2972981:'0f11440815',0x2972986:'0f114c0825',0x297298b:'8b54243f',0x297298f:'89540834',0x2972993:'0f28842490000000',0x297299b:'0f288c24a0000000',0x29729a3:'0f11440838',0x29729a8:'0f114c0848',0x29729ad:'48ffc3',0x29729b0:'48895f28',0x2972a89:'0f8525ffffff',0x2972af3:'46880410',0x2972af7:'4488441010',0x2972afc:'48ff49f0',0x2972b00:'f3410f6f43e0',0x2972b06:'f3410f6f4bf0',0x2972b0c:'e905feffff',0x2994ef0:'4883c778',0x2994ef4:'4881c670020000',0x2994efb:'4889e2',0x2994efe:'488d4c2420',0x2994f0c:'e87fd4fdff'}
pins.update({0x297281c:'0f294c2470',0x2972821:'0f29442460',0x29728f9:'660fdbc1',0x2972911:'0f284c2470',0x297291f:'660f7f842490000000',0x2972928:'0f1003',0x297292b:'0f104b10',0x297292f:'0f114c2433',0x2972934:'0f11442423',0x297295c:'488b4720'})
def check(r):
 for a,v in pins.items():assert r[a]==bytes.fromhex(v),hex(a)
check(rows)
def target(a):
 x=rows[a];return a+len(x)+int.from_bytes(x[-4:],'little',signed=True)
for a,t in [(0x2994f0c,0x2972390),(0x29723bf,0x29724d0),(0x29724d8,0x29729b4),(0x2972837,0x29728e4),(0x2972906,0x29729b4),(0x2972950,0x64e6cf0),(0x2972a89,0x29729b4),(0x2972b0c,0x2972916)]:assert target(a)==t
r=next(x for x in s if x['name']=='.rela.dyn');rel={a:(i,d) for a,i,d in struct.iter_unpack('<QQq',b[r['offset']:r['offset']+r['size']])};assert rel[0x64e6cf0]==(8,0x43bc980)
for a in (0x29723bf,0x2972906,0x2972960,0x2972964,0x29729a3,0x2972b0c):
 altered=dict(rows);altered[a]=altered[a][:-1]+bytes([altered[a][-1]^1])
 try:check(altered)
 except AssertionError:pass
 else:raise AssertionError('mutation accepted '+hex(a))
print(f'{len(bodies)} decoded FDEs, {len(rows)} spans, {len(pins)} pins, 8 edges, 1 relocation and 6 mutation controls: OK')
