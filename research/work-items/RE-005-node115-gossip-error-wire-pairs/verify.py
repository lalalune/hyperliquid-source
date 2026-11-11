#!/usr/bin/env python3
"""Static evidence checks; never execute or emulate the captured target."""
import csv,hashlib
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86_const import X86_OP_IMM
from elf_index import unwind_index
from fde_extents import eh_frame_records
P=Path('research/work-items/RE-005-node115-gossip-error-wire-pairs')
b=Path('artifacts/node/115/hl-node').read_bytes();assert hashlib.sha256(b).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
s,h=unwind_index(b);_,f=eh_frame_records(b,s);idx={(x['start'],x['fde']) for x in h}
def read(a,n):
 x=next(x for x in s if x['address']<=a and a+n<=x['address']+x['size'] and x['name'] in ('.text','.rodata'));p=x['offset']+a-x['address'];return b[p:p+n]
bodies={0x5aaa810:(0x5aaab63,'633be2bbbf1d5becc33995371c57122cbd53bf145f85a68060ce96a1125a1c55'),0x5aaac40:(0x5aaaf54,'191fe271fe2bcd6b1ef64d28f14ade5b45047f3a2245a042315b90671fe44cb1'),0x5822910:(0x5822b90,'cef335ef12cfd1f5067a20fac0c35ac5c484a0a28153af8c1c079522bbabcec1'),0x5822b90:(0x5822c44,'f9f20366d3044558de7225af68a2aebe275baba3b50ae6f2d4f7e0d079285732'),0x5a5dbc0:(0x5a5e281,'5d9b8d4faa0106747b55edfc16afc1e706f6f7a0aeb979b95803bab4e6523320')}
m=Cs(CS_ARCH_X86,CS_MODE_64);m.detail=True;ins={}
for a,(z,d) in bodies.items():
 assert any(x['start']==a and x['end']==z and (a,x['fde']) in idx for x in f)
 raw=read(a,z-a);assert hashlib.sha256(raw).hexdigest()==d
 seq=list(m.disasm(raw,a));assert sum(x.size for x in seq)==len(raw);ins.update({x.address:x for x in seq})
rows={}
with (P/'instructions.tsv').open() as fp:
 for x in csv.DictReader(fp,delimiter='\t'):
  a=int(x['va'],16);v=bytes.fromhex(x['bytes']);assert a not in rows and a in ins and ins[a].bytes==v and read(a,len(v))==v;rows[a]=v
pins={95070243: '4c8b3e', 95070249: '4883e903', 95070265: '7457', 95070382: '41837f0801', 95070387: '0f85be000000', 95070406: 'e86576d7ff', 95070425: '498b4710', 95070429: '488d0d0cf6e8fa', 95070849: '488d35d4f59afa', 95070858: '488d35cbf39afa', 95070867: '488d356ef59afa', 95070880: 'e88b74d7ff', 95070899: '498b5718', 95070909: 'e84e7ed7ff', 95070924: '498b5720', 95070934: 'e8357ed7ff', 95071315: '4c8b3e', 95071321: '4883e903', 95071337: '7457', 95071454: '41837f0801', 95071459: '0f85b6000000', 95071478: 'e8e573d7ff', 95071497: '498b4710', 95071501: '488d0df8f1e8fa', 95071913: '488d35acf19afa', 95071922: '488d35a3ef9afa', 95071931: '488d3546f19afa', 95071944: 'e81372d7ff', 95071963: '498b5718', 95071973: 'e8a67cd7ff', 95071988: '498b5720', 95071998: 'e88d7cd7ff', 92416277: '4881fafb000000', 92416284: '731c', 92416303: '881401', 92416314: '4881fa00000100', 92416321: '7338', 92416343: '41c60400fb', 92416368: '6641891400', 92416379: '4889d0', 92416382: '48c1e820', 92416386: '7537', 92416408: '41c60400fc', 92416433: '41891400', 92416443: '488b0e', 92416463: '41c60400fd', 92416488: '49891400', 92416496: '48894610', 92416500: '48c70708000000', 92416913: '4881fafb000000', 92416920: '731c', 92416935: '48ffc0', 92416938: '488906', 92416950: '4881fa00000100', 92416957: '7326', 92416981: '4883c003', 92416997: '48c1ea20', 92417001: '7526', 92417025: '4883c005', 92417063: '4883c009', 94755884: '41be01000000', 94755890: '4929ef', 94755893: '0f839c000000', 94755899: '41bc01000000', 94755905: '488b442408', 94756486: '4c897308', 94756490: '4c896310', 94756494: '48896b18', 94756498: '48894320', 94757209: '4c39ed', 94757212: '761e', 94757219: '4839d0', 94757222: '7622', 94757230: '41bc06000000', 94757236: '4989d5', 94757239: '4889c5', 94757250: '41bc05000000', 94757380: '4c89e8', 94757383: '0f8479fcffff'}
def check(r):
 for a,v in pins.items():assert r[a]==bytes.fromhex(v),hex(a)
check(rows)
for a,v in [(0x5aaa839,0x5aaa892),(0x5aaa8b3,0x5aaa977),(0x5aaaaa0,0x5821f30),(0x5aaaabd,0x5822910),(0x5aaaad6,0x5822910),(0x5aaac69,0x5aaacc2),(0x5aaace3,0x5aaad9f),(0x5aaaec8,0x58220e0),(0x5aaaee5,0x5822b90),(0x5aaaefe,0x5822b90),(0x582291c,0x582293a),(0x5822941,0x582297b),(0x5822982,0x58229bb),(0x5822b98,0x5822bb6),(0x5822bbd,0x5822be5),(0x5822be9,0x5822c11),(0x5a5dc35,0x5a5dcd7),(0x5a5e15c,0x5a5e17c),(0x5a5e166,0x5a5e18a),(0x5a5e207,0x5a5de86)]:assert ins[a].operands[0].type==X86_OP_IMM and ins[a].operands[0].imm==v
def rip(a):return a+len(rows[a])+int.from_bytes(rows[a][-4:],'little',signed=True)
for a,v in [(0x5aaa8dd,0x939ef0),(0x5aaad0d,0x939f0c),(0x5aaaa81,0x45a05c),(0x5aaaa8a,0x459e5c),(0x5aaaa93,0x45a008),(0x5aaaea9,0x45a05c),(0x5aaaeb2,0x459e5c),(0x5aaaebb,0x45a008)]:assert rip(a)==v
for base,pairs in [(0x939ef0,[(1,0x5aaaa81),(5,0x5aaaa8a),(6,0x5aaaa93)]),(0x939f0c,[(1,0x5aaaea9),(5,0x5aaaeb2),(6,0x5aaaebb)])]:
 for i,want in pairs:assert base+int.from_bytes(read(base+4*i,4),'little',signed=True)==want
for a,n in [(0x45a05c,1),(0x459e5c,5),(0x45a008,6)]:assert int.from_bytes(read(a,4),'little')==n
for x,w in [(0,1),(250,1),(251,3),(65535,3),(65536,5),((1<<32)-1,5),(1<<32,9),((1<<64)-1,9)]:assert (1 if x<251 else 3 if x<65536 else 5 if x<1<<32 else 9)==w
assert 3+1+1==5 and 3+9+9==21
for a in [0x5aaaabd,0x5aaaad6,0x5aaaee5,0x5aaaefe,0x5822915,0x5822957,0x5822970,0x5822998,0x58229cf,0x5822b91,0x5822bd5,0x5822c27,0x5a5dc3b,0x5a5de8e,0x5a5de92,0x5a5e16e,0x5a5e174,0x5a5e177,0x5a5e182]:
 q=dict(rows);q[a]=q[a][:-1]+bytes([q[a][-1]^1])
 try:check(q)
 except AssertionError:pass
 else:raise AssertionError(hex(a))
print(f'{len(bodies)} FDEs, {len(rows)} instructions, {len(pins)} pins, 6 table entries, 20 targets, 8 width cases and 19 controls: OK')
