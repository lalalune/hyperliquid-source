#!/usr/bin/env python3
"""Static evidence checks; never execute or emulate the captured target."""
import csv,hashlib
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86_const import X86_OP_IMM
from elf_index import unwind_index
from fde_extents import eh_frame_records
P=Path('research/work-items/RE-005-node115-gossip-error-wire-prefix')
b=Path('artifacts/node/115/hl-node').read_bytes();assert hashlib.sha256(b).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
s,h=unwind_index(b);_,f=eh_frame_records(b,s);idx={(x['start'],x['fde']) for x in h}
def read(a,n):
 x=next(x for x in s if x['address']<=a and a+n<=x['address']+x['size'] and x['name'] in ('.text','.rodata'));p=x['offset']+a-x['address'];return b[p:p+n]
bodies={0x5aaa810:(0x5aaab63,'633be2bbbf1d5becc33995371c57122cbd53bf145f85a68060ce96a1125a1c55'),0x5aaac40:(0x5aaaf54,'191fe271fe2bcd6b1ef64d28f14ade5b45047f3a2245a042315b90671fe44cb1'),0x5821f30:(0x58220d6,'3e3cf35ed57b1ecfb2ee1c2dd8919cf4104c1f871d896d9788e3186cffe74df3'),0x58220e0:(0x5822157,'d0b011312bb5eed943bba34c34ae2cf1278dd86e78a7e10d62f7234eaa961ff5'),0x5822f70:(0x58230b7,'ffa7aeeb0210976913a11f652573b640f1d5238e57d56ad1a376f7dff9634ba5')}
m=Cs(CS_ARCH_X86,CS_MODE_64);m.detail=True;ins={}
for a,(z,d) in bodies.items():
 assert any(x['start']==a and x['end']==z and (a,x['fde']) in idx for x in f)
 raw=read(a,z-a);assert hashlib.sha256(raw).hexdigest()==d
 seq=list(m.disasm(raw,a));assert sum(x.size for x in seq)==len(raw);ins.update({x.address:x for x in seq})
rows={}
with (P/'instructions.tsv').open() as fp:
 for x in csv.DictReader(fp,delimiter='\t'):
  a=int(x['va'],16);v=bytes.fromhex(x['bytes']);assert a not in rows and a in ins and ins[a].bytes==v and read(a,len(v))==v;rows[a]=v
pins={95070243: '4c8b3e', 95070246: '498b0f', 95070249: '4883e903', 95070253: 'b802000000', 95070258: '480f43c1', 95070262: '4885c0', 95070265: '7457', 95070354: '488d35d3f59afa', 95070367: 'e88c76d7ff', 95070372: '833c2408', 95070376: '0f858f000000', 95070382: '41837f0801', 95070387: '0f85be000000', 95070393: '488d359cf79afa', 95070406: 'e86576d7ff', 95070425: '498b4710', 95070429: '488d0d0cf6e8fa', 95070436: '48630481', 95070443: 'ffe0', 95070445: '488d3578f59afa', 95070452: 'e967010000', 95070791: '488d3522f49afa', 95070800: '488d3565f59afa', 95070809: '488d3564f59afa', 95070816: '4889e7', 95070822: 'e8c574d7ff', 95070835: '7570', 95070837: '48c70308000000', 95070849: '488d35d4f59afa', 95070858: '488d35cbf39afa', 95070867: '488d356ef59afa', 95070880: 'e88b74d7ff', 95070899: '498b5718', 95070909: 'e84e7ed7ff', 95070924: '498b5720', 95070934: 'e8357ed7ff', 95071315: '4c8b3e', 95071318: '498b0f', 95071321: '4883e903', 95071325: 'b802000000', 95071330: '480f43c1', 95071334: '4885c0', 95071337: '7457', 95071426: '488d35a3f19afa', 95071439: 'e80c74d7ff', 95071444: '833c2408', 95071448: '0f8587000000', 95071454: '41837f0801', 95071459: '0f85b6000000', 95071465: '488d356cf39afa', 95071478: 'e8e573d7ff', 95071497: '498b4710', 95071501: '488d0df8f1e8fa', 95071508: '48630481', 95071515: 'ffe0', 95071517: '488d3548f19afa', 95071524: 'e95f010000', 95071855: '488d35faef9afa', 95071864: '488d353df19afa', 95071873: '488d353cf19afa', 95071880: '4889e7', 95071886: 'e84d72d7ff', 95071899: '7570', 95071901: '48c70308000000', 95071913: '488d35acf19afa', 95071922: '488d35a3ef9afa', 95071931: '488d3546f19afa', 95071944: 'e81372d7ff', 95071963: '498b5718', 95071973: 'e8a67cd7ff', 95071988: '498b5720', 95071998: 'e88d7cd7ff', 92413752: '8b1e', 92413754: '81fbfb000000', 92413760: '731a', 92413762: '488b7220', 92413766: '48397210', 92413770: '0f8490000000', 92413776: '488b4a18', 92413780: '881c31', 92413783: '48ffc6', 92413903: '48897220', 92413907: '48c70008000000', 92414177: '8b06', 92414179: '3dfb000000', 92414184: '730f', 92414186: '488b4210', 92414190: '4883f8ff', 92414194: '7456', 92414196: '48ffc0', 92414266: '48894210', 92414270: '48c70708000000', 92417929: '48c744244800000000', 92417963: 'e8907c2800', 92417968: '837c241008', 92418090: 'e8e1772800', 92418095: '837c243808'}
def check(r):
 for a,v in pins.items():assert r[a]==bytes.fromhex(v),hex(a)
check(rows)
for a,v in [(0x5aaa839,0x5aaa892),(0x5aaa89f,0x5821f30),(0x5aaa8b3,0x5aaa977),(0x5aaa8c6,0x5821f30),(0x5aaaa66,0x5821f30),(0x5aaaaa0,0x5821f30),(0x5aaaabd,0x5822910),(0x5aaaad6,0x5822910),(0x5aaac69,0x5aaacc2),(0x5aaaccf,0x58220e0),(0x5aaace3,0x5aaad9f),(0x5aaacf6,0x58220e0),(0x5aaae8e,0x58220e0),(0x5aaaec8,0x58220e0),(0x5aaaee5,0x5822b90),(0x5aaaefe,0x5822b90),(0x5822fab,0x5aaac40),(0x582302a,0x5aaa810)]:assert ins[a].operands[0].type==X86_OP_IMM and ins[a].operands[0].imm==v
def rip(a):return a+len(rows[a])+int.from_bytes(rows[a][-4:],'little',signed=True)
for a,v in [(0x5aaa892,0x459e6c),(0x5aaa8b9,0x45a05c),(0x5aaa8dd,0x939ef0),(0x5aaacc2,0x459e6c),(0x5aaace9,0x45a05c),(0x5aaad0d,0x939f0c)]:assert rip(a)==v
for base,wants in [(0x939ef0,[0x5aaa8ed,0x5aaaa81,0x5aaaa50,0x5aaaa59,0x5aaaa47,0x5aaaa8a,0x5aaaa93]),(0x939f0c,[0x5aaad1d,0x5aaaea9,0x5aaae78,0x5aaae81,0x5aaae6f,0x5aaaeb2,0x5aaaebb])]:
 for i,want in enumerate(wants):assert base+int.from_bytes(read(base+4*i,4),'little',signed=True)==want and want in ins
for a,n in [(0x459e6c,0),(0x45a05c,1),(0x459fbc,2),(0x459fc4,3),(0x459e70,4),(0x459e5c,5),(0x45a008,6)]:assert int.from_bytes(read(a,4),'little')==n
for a in [0x5aaa829,0x5aaa892,0x5aaa8ae,0x5aaa8dd,0x5aaaa66,0x5aaaaa0,0x5aaac59,0x5aaacc2,0x5aaacde,0x5aaad0d,0x5aaae8e,0x5aaaec8,0x5821f40,0x5821f54,0x58220e8,0x58220f4,0x5822fab,0x582302a]:
 q=dict(rows);q[a]=q[a][:-1]+bytes([q[a][-1]^1])
 try:check(q)
 except AssertionError:pass
 else:raise AssertionError(hex(a))
print(f'{len(bodies)} FDEs, {len(rows)} instructions, {len(pins)} pins, 14 table entries, 7 constants, 18 targets and 18 controls: OK')
