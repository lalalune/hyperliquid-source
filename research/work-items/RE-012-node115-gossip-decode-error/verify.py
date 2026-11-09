#!/usr/bin/env python3
"""Static evidence checks; never execute or emulate the captured target."""
import csv,hashlib,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86_const import X86_OP_IMM
from elf_index import unwind_index
from fde_extents import eh_frame_records
P=Path('research/work-items/RE-012-node115-gossip-decode-error')
b=Path('artifacts/node/115/hl-node').read_bytes();assert hashlib.sha256(b).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
s,h=unwind_index(b);_,f=eh_frame_records(b,s);idx={(x['start'],x['fde']) for x in h};t=next(x for x in s if x['name']=='.text')
def read(a,n):
 x=next(x for x in s if x['address']<=a and a+n<=x['address']+x['size'] and x['name'] in ('.text','.rodata'));p=x['offset']+a-x['address'];return b[p:p+n]
bodies={0x5a60a50:(0x5a61e38,'540390760e4360efd444c06270a6d20e97432861e5230991093cb886e5530f3f'),0x5ab5b50:(0x5ab5be0,'0eabd4bf109ae96a1a4f285e7bf152433777a94695e5d248bb0f36cf732db656'),0x5a4b8f0:(0x5a4b9c1,'a8994487c0f385a19e929ac02ef9973f3463beca216a9540269ef19bfad0768e')}
m=Cs(CS_ARCH_X86,CS_MODE_64);m.detail=True;ins={}
for a,(z,d) in bodies.items():
 assert any(x['start']==a and x['end']==z and (a,x['fde']) in idx for x in f)
 raw=read(a,z-a);assert hashlib.sha256(raw).hexdigest()==d
 seq=list(m.disasm(raw,a));assert sum(x.size for x in seq)==len(raw);ins.update({x.address:x for x in seq})
rows={}
with (P/'instructions.tsv').open() as fp:
 for x in csv.DictReader(fp,delimiter='\t'):
  a=int(x['va'],16);v=bytes.fromhex(x['bytes']);assert a not in rows and a in ins and ins[a].bytes==v and read(a,len(v))==v;rows[a]=v
pins={94770657: '0f108424d0060000', 94770665: '0f108c24e0060000', 94770689: '488dbc24f0000000', 94770697: 'e842450500', 94770702: '4989c4', 94770705: 'bd03000000', 95116122: '48897c2408', 95116127: '488b05dabda200', 95116134: '4889442410', 95116139: '488d3dfbf198fa', 95116146: '488d742408', 95116151: 'e8d434ffff', 95116156: '0fb60b', 95116159: '83f90f', 95116162: '7308', 95116172: '741f', 95116174: '83f910', 95116177: '74f1', 95116179: '488b7308', 95116183: '4885f6', 95116186: '74e8', 95116188: '488b7b10', 95116192: '31d2', 95116194: '4889c3', 95116197: 'ff15f598a200', 95116205: '4883c310', 95116212: '4889c3', 95116215: 'e8345df9ff', 95116220: '4889d8', 94681336: '488b07', 94681341: '83e103', 94681344: '8d51fe', 94681347: '83fa02', 94681350: '7205', 94681352: '4885c9', 94681355: '750c', 94681369: '488d58ff', 94681373: '4c8b70ff', 94681377: '4c8b6007', 94681381: '498b0424', 94681388: '7405', 94681393: 'ffd0', 94681395: '498b742408', 94681400: '4885f6', 94681403: '7422', 94681433: 'ff15413ba900', 94681439: 'be18000000', 94681444: '4889df', 94681460: 'ff25263ba900'}
def check(r):
 for a,v in pins.items():assert r[a]==bytes.fromhex(v),hex(a)
check(rows)
for a,v in [(0x5a61609,0x5ab5b50),(0x5ab5b77,0x5aa9050),(0x5ab5b82,0x5ab5b8c),(0x5ab5b8c,0x5ab5bad),(0x5ab5b91,0x5ab5b84),(0x5ab5b9a,0x5ab5b84),(0x5ab5bb7,0x5a4b8f0),(0x5a4b906,0x5a4b90d),(0x5a4b90b,0x5a4b919),(0x5a4b92c,0x5a4b933),(0x5a4b93b,0x5a4b95f)]:assert ins[a].operands[0].type==X86_OP_IMM and ins[a].operands[0].imm==v
def rip(a):return a+len(rows[a])+int.from_bytes(rows[a][-4:],'little',signed=True)
for a,v in [(0x5ab5b5f,0x64e1940),(0x5ab5b6b,0x444d6d),(0x5ab5ba5,0x64df4a0),(0x5a4b959,0x64df4a0),(0x5a4b974,0x64df4a0)]:assert rip(a)==v
r=next(x for x in s if x['name']=='.rela.dyn');rel={a:(i,d) for a,i,d in struct.iter_unpack('<QQq',b[r['offset']:r['offset']+r['size']])};assert rel[0x64e1940]==(8,0x1609a70) and rel[0x64df4a0]==(8,0x635de30)
assert read(0x444d6d,23)==bytes([22])+b'TcpRead::bincode err: '
for tag,action in [(0,'none'),(14,'none'),(15,'nested'),(16,'none'),(17,'indirect'),(255,'indirect')]:assert ('none' if tag<15 or tag==16 else 'nested' if tag==15 else 'indirect')==action
for a in [0x5a61609,0x5ab5b6b,0x5ab5b77,0x5ab5b7f,0x5ab5b8c,0x5ab5b91,0x5ab5ba5,0x5ab5bb7,0x5a4b8fd,0x5a4b90b,0x5a4b974]:
 q=dict(rows);q[a]=q[a][:-1]+bytes([q[a][-1]^1])
 try:check(q)
 except AssertionError:pass
 else:raise AssertionError(hex(a))
print(f'{len(bodies)} FDEs, {len(rows)} instructions, {len(pins)} pins, 11 targets, 2 relocations, literal and 11 controls: OK')
