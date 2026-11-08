#!/usr/bin/env python3
"""Re-check static projection evidence; no target execution or emulation."""
import csv,hashlib,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from elf_index import unwind_index
from fde_extents import eh_frame_records
P=Path('research/work-items/RE-010-node115-delayer-state-projection')
b=Path('artifacts/node/115/hl-node').read_bytes();assert hashlib.sha256(b).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
s,h=unwind_index(b);_,f=eh_frame_records(b,s);idx={(x['start'],x['fde']) for x in h};t=next(x for x in s if x['name']=='.text')
def read(a,n):
 assert t['address']<=a and a+n<=t['address']+t['size'];p=t['offset']+a-t['address'];return b[p:p+n]
bodies={0x1850600:(0x185f325,'a11b3f7dd96482ec20d96352417594c8900739889f58c939ad51e6134dd14903'),0x3c2e860:(0x3c2f45b,'c6af69902c83a3168bce2aec40093de78fd9932ccacc44e7eeac00ca44e0f2f3'),0x2d23610:(0x2d2561c,'fe32b7bdcd444d83c31778a02e84a04f2724ad20512c3471fbc2a9dccc831cc5'),0x3c12800:(0x3c12af5,'52e2718331566ec5c5cf72a65e69764441372b67802a9f3e8a04445e7d10949a'),0x3bec320:(0x3becd9a,'4d2d247246e6bc942ff12681bc4ab13ff3f5ac8580b5863a512a7e0a32463a91')}
ins={}
for a,(z,d) in bodies.items():
 assert any(x['start']==a and x['end']==z and (a,x['fde']) in idx for x in f);raw=read(a,z-a);assert hashlib.sha256(raw).hexdigest()==d
 seq=list(Cs(CS_ARCH_X86,CS_MODE_64).disasm(raw,a));assert sum(x.size for x in seq)==len(raw);ins.update({x.address:x for x in seq})
rows={}
with (P/'instructions.tsv').open() as fp:
 for x in csv.DictReader(fp,delimiter='\t'):
  a=int(x['va'],16);v=bytes.fromhex(x['bytes']);assert a not in rows and a in ins and ins[a].bytes==v and read(a,len(v))==v;rows[a]=v
pins={0x185d881:'0f10842448080000',0x185d889:'0f108c2458080000',0x185d891:'0f10942468080000',0x185d899:'0f109c2478080000',0x185d8a1:'0f1183a0250000',0x185d8a8:'0f118bb0250000',0x185d8af:'0f1193c0250000',0x185d8b6:'0f119bd0250000',0x185d8bd:'0f10842488080000',0x185d8c5:'0f1183e0250000',0x185d8cc:'0f10842498080000',0x185d8d4:'0f1183f0250000',0x185d8db:'0f108424a8080000',0x185d8e3:'0f118300260000',0x185d8ea:'488b8424b8080000',0x185d8f2:'48898310260000',0x3c2e8a7:'4989f6',0x3c2e8aa:'4889fb',0x3c2ea91:'4d8da6a0250000',0x3c2eebb:'410f100424',0x3c2eec0:'410f104c2410',0x3c2eec6:'410f10542420',0x3c2eecc:'410f105c2430',0x3c2eed2:'0f1183c0400000',0x3c2eed9:'0f118bd0400000',0x3c2eee0:'0f1193e0400000',0x3c2eee7:'0f119bf0400000',0x3c2eeee:'410f10442440',0x3c2eef4:'0f118300410000',0x3c2eefb:'410f10442450',0x3c2ef01:'0f118310410000',0x3c2ef08:'410f10442460',0x3c2ef0e:'0f118320410000',0x3c2ef15:'498b442470',0x3c2ef1a:'48898330410000',0x3c1294b:'498dbc24c0400000',0x3c12953:'ff15b7258d02',0x2d237ad:'488db3c0400000',0x2d237b4:'8b4368',0x2d237be:'488b4360',0x2d237d7:'ff1523177c03'}
def check(r):
 for a,v in pins.items():assert r[a]==bytes.fromhex(v),hex(a)
check(rows)
# The chosen materializer path keeps its input/output registers and the
# projected-input alias unchanged between assignment and the copy window.
# Normal called functions are assumed to obey the x86-64 callee-saved ABI.
md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
for start,end,protected in [(0x3c2e8ad,0x3c2eebb,{'rbx','ebx','r14','r14d'}),(0x3c2ea98,0x3c2eebb,{'r12','r12d'})]:
 seq=list(md.disasm(read(start,end-start),start));assert sum(x.size for x in seq)==end-start
 for x in seq:
  _,writes=x.regs_access();assert not protected.intersection(x.reg_name(y) for y in writes),hex(x.address)
def target(a):return a+len(rows[a])+int.from_bytes(rows[a][-4:],'little',signed=True)
for a,v in [(0x3c12953,0x64e4f10),(0x2d237d7,0x64e4f00)]:assert target(a)==v
r=next(x for x in s if x['name']=='.rela.dyn');rel={a:(i,d) for a,i,d in struct.iter_unpack('<QQq',b[r['offset']:r['offset']+r['size']])};assert rel[0x64e4f10]==(8,0x3bec320) and rel[0x64e4f00]==(8,0x3bed8a0)
# Seven 16-byte pairs and one 8-byte pair preserve exactly 0x78 bytes.
chunks=[(i*16,16) for i in range(7)]+[(0x70,8)]
assert sum(n for _,n in chunks)==0x78
assert all(0x25a0+off+0x1b20==0x40c0+off for off,_ in chunks)
for a in (0x185d8a1,0x185d8f2,0x3c2ea91,0x3c2eed2,0x3c2ef1a,0x3c12953,0x2d237ad,0x2d237d7):
 m=dict(rows);m[a]=m[a][:-1]+bytes([m[a][-1]^1])
 try:check(m)
 except AssertionError:pass
 else:raise AssertionError(hex(a))
print(f'{len(bodies)} FDEs, {len(rows)} instruction spans, {len(pins)} pins, 2 slots, 2 relocations, 8 range joins and 8 controls: OK')
