#!/usr/bin/env python3
"""Static evidence checks; never execute or emulate the captured target."""
import csv,hashlib,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86_const import X86_OP_IMM
from elf_index import unwind_index
from fde_extents import eh_frame_records
P=Path('research/work-items/RE-012-node115-gossip-output-buffer')
b=Path('artifacts/node/115/hl-node').read_bytes();assert hashlib.sha256(b).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
s,h=unwind_index(b);_,f=eh_frame_records(b,s);idx={(x['start'],x['fde']) for x in h};t=next(x for x in s if x['name']=='.text')
def read(a,n):
 assert t['address']<=a and a+n<=t['address']+t['size'];p=t['offset']+a-t['address'];return b[p:p+n]
bodies={0x58616b0:(0x586182f,'d65b823d376f7f31d9bb50edeecd13d5a30a9793cb40a19512cca86f0aa32abc'),0x4e47f90:(0x4e481a6,'a1266cf4e4781b049a695f51f5805c304f4822230140e04b1acb8fedea9e30ef'),0x5822f70:(0x58230b7,'ffa7aeeb0210976913a11f652573b640f1d5238e57d56ad1a376f7dff9634ba5'),0x5a60a50:(0x5a61e38,'540390760e4360efd444c06270a6d20e97432861e5230991093cb886e5530f3f')}
m=Cs(CS_ARCH_X86,CS_MODE_64);m.detail=True;ins={}
for a,(z,d) in bodies.items():
 assert any(x['start']==a and x['end']==z and (a,x['fde']) in idx for x in f)
 raw=read(a,z-a);assert hashlib.sha256(raw).hexdigest()==d
 seq=list(m.disasm(raw,a));assert sum(x.size for x in seq)==len(raw);ins.update({x.address:x for x in seq})
rows={}
with (P/'instructions.tsv').open() as fp:
 for x in csv.DictReader(fp,delimiter='\t'):
  a=int(x['va'],16);v=bytes.fromhex(x['bytes']);assert a not in rows and a in ins and ins[a].bytes==v and read(a,len(v))==v;rows[a]=v
pins={94769269: '488dbb600e0000', 94769276: '0fb6d2', 94769279: '4c89f6', 94769282: 'e82906e0ff', 92673724: '89d5', 92673726: '4889fb', 92673729: '4889742420', 92673750: '4889e7', 92673753: '488d742420', 92673758: '89ea', 92673760: 'e8ab685eff', 92673820: '4084ed', 92673823: '740e', 92673839: '488b0c24', 92673843: '4883f908', 92673847: '7513', 92673849: '488b442418', 92673854: '48894310', 92673858: '0f10442408', 92673863: '0f1103', 82083740: '4889fb', 82083743: '4c8b3e', 82083746: '85d2', 82083748: '7475', 82083867: '4889df', 82083870: '4c89fe', 82083873: '31d2', 82083875: 'e848af9d00', 92417921: '4889fb', 92417924: '4889742408', 92417929: '48c744244800000000', 92417938: '4889542438', 92417943: '48894c2440', 92417963: 'e8907c2800', 92417968: '837c241008', 92417973: '752c', 92417975: '4c8b642448', 92417980: '4d85e4', 92417983: '0f88c5000000', 92417989: '7432', 92417991: '4c89e7', 92417994: 'ff15b0c4cb00', 92418000: '4885c0', 92418003: '7529', 92418019: '0f10442410', 92418029: '0f114b10', 92418033: '0f1103', 92418041: 'b801000000', 92418046: '4c89642420', 92418051: '4889442428', 92418056: '48c744243000000000', 92418090: 'e8e1772800', 92418095: '837c243808', 92418100: '751d', 92418111: '48894b18', 92418118: '0f114308', 92418122: '48c70308000000', 92418131: '0f10442438', 92418141: '0f114b10', 92418148: '488b742420', 92418153: '4885f6', 92418156: '740d', 92418165: 'ff1525c4cb00'}
def check(r):
 for a,v in pins.items():assert r[a]==bytes.fromhex(v),hex(a)
check(rows)
for a,v in [(0x5a61082,0x58616b0),(0x58616e0,0x4e47f90),(0x586171f,0x586172f),(0x5861737,0x586174c),(0x4e47fa4,0x4e4801b),(0x4e48023,0x5822f70),(0x5822fab,0x5aaac40),(0x5822fb5,0x5822fe3),(0x5822fbf,0x582308a),(0x5822fc5,0x5822ff9),(0x5822fd3,0x5822ffe),(0x582302a,0x5aaa810),(0x5823034,0x5823053),(0x582306c,0x582307b)]:assert ins[a].operands[0].type==X86_OP_IMM and ins[a].operands[0].imm==v
def rip(a):return a+len(rows[a])+int.from_bytes(rows[a][-4:],'little',signed=True)
assert rip(0x5822fca)==0x64df480 and rip(0x5823075)==0x64df4a0
r=next(x for x in s if x['name']=='.rela.dyn');rel={a:(i,d) for a,i,d in struct.iter_unpack('<QQq',b[r['offset']:r['offset']+r['size']])};assert rel[0x64df480]==(8,0x6355830) and rel[0x64df4a0]==(8,0x635de30)
for n,negative in [(0,False),(1,False),((1<<63)-1,False),(1<<63,True),((1<<64)-1,True)]:assert bool(n>>63)==negative
for a in [0x5a61082,0x58616e0,0x5861733,0x4e47fa4,0x4e48023,0x5822fab,0x5822fb0,0x5822fbf,0x5822fc5,0x5822fca,0x5822ff9,0x582302a,0x582302f,0x582304a,0x5823075]:
 q=dict(rows);q[a]=q[a][:-1]+bytes([q[a][-1]^1])
 try:check(q)
 except AssertionError:pass
 else:raise AssertionError(hex(a))
print(f'{len(bodies)} FDEs, {len(rows)} instructions, {len(pins)} pins, 14 targets, 2 relocations, 5 boundaries and 15 controls: OK')
