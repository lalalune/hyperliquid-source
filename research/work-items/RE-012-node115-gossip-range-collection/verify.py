#!/usr/bin/env python3
"""Static evidence checks; never execute or emulate the captured target."""
import csv,hashlib,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86_const import X86_OP_IMM
from elf_index import unwind_index
from fde_extents import eh_frame_records
P=Path('research/work-items/RE-012-node115-gossip-range-collection')
b=Path('artifacts/node/115/hl-node').read_bytes();assert hashlib.sha256(b).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
s,h=unwind_index(b);_,f=eh_frame_records(b,s);idx={(x['start'],x['fde']) for x in h};t=next(x for x in s if x['name']=='.text')
def read(a,n):
 assert t['address']<=a and a+n<=t['address']+t['size'];p=t['offset']+a-t['address'];return b[p:p+n]
bodies={0x5acca00:(0x5accc71,'8fbc9e12bde4d8eb49f62cf1ab939a35392b1ca843ad3593537008290b7aa57c'),0x5a5dbc0:(0x5a5e281,'5d9b8d4faa0106747b55edfc16afc1e706f6f7a0aeb979b95803bab4e6523320')}
m=Cs(CS_ARCH_X86,CS_MODE_64);m.detail=True;ins={}
for a,(z,d) in bodies.items():
 assert any(x['start']==a and x['end']==z and (a,x['fde']) in idx for x in f)
 raw=read(a,z-a);assert hashlib.sha256(raw).hexdigest()==d
 seq=list(m.disasm(raw,a));assert sum(x.size for x in seq)==len(raw);ins.update({x.address:x for x in seq})
rows={}
with (P/'instructions.tsv').open() as fp:
 for x in csv.DictReader(fp,delimiter='\t'):
  a=int(x['va'],16);v=bytes.fromhex(x['bytes']);assert a not in rows and a in ins and ins[a].bytes==v and read(a,len(v))==v;rows[a]=v
pins={94757292: '0f10442428', 94757297: '0f104c2438', 94757302: '0f10542448', 94757325: '488b442458', 94757330: '4889842490000000', 94757338: '488d7c2428', 94757343: '488d742460', 94757348: 'e817e80600', 95209998: '4989f6', 95210001: '4989fd', 95210007: 'e834c234ff', 95210012: '4885c0', 95210015: '0f84a0000000', 95210021: '488b1a', 95210024: '4c8b6208', 95210028: 'f048ff03', 95210032: '0f8e8d000000', 95210038: 'f049ff0424', 95210043: '0f8e82000000', 95210059: 'bd04000000', 95210064: '41833e01', 95210068: '753d', 95210070: '498b4610', 95210074: '498b4e20', 95210078: '492b4608', 95210082: '48c1e803', 95210086: '48baabaaaaaaaaaaaaaa', 95210096: '480fafc2', 95210100: '492b4e18', 95210104: '48c1e903', 95210108: '480fafca', 95210112: '4801c1', 95210115: '4883f904', 95210119: 'bd03000000', 95210124: '480f43e9', 95210128: '48ffc5', 95210134: '49c1e704', 95210141: '48c1e83c', 95210145: '0f95c0', 95210148: '48b9f8ffffffffffff7f', 95210158: '4939cf', 95210161: '0f97c1', 95210164: '08c1', 95210166: '742a', 95210181: '49c7450000000000', 95210189: '49c7450808000000', 95210197: '49c7451000000000', 95210218: 'ff159029a100', 95210227: '0f8431010000', 95210236: '488918', 95210239: '4c896008', 95210243: '48892c24', 95210247: '4889442408', 95210252: '48c744241001000000', 95210337: 'e8aa6ee9ff', 95210347: '49895c2df8', 95210352: '4d89642d00', 95210357: '49ffc6', 95210360: '4c89742410', 95210372: 'e8c7c034ff', 95210380: '7473', 95210389: 'f048ff03', 95210399: 'f049ff0424', 95210420: '4c3b3424', 95210424: '75b1', 95210497: '488b442410', 95210507: '49894510', 95210515: '410f114500'}
def check(r):
 for a,v in pins.items():assert r[a]==bytes.fromhex(v),hex(a)
check(rows)
for a,v in [(0x5a5e1e4,0x5acca00),(0x5acca17,0x4e18c50),(0x5acca1f,0x5accac5),(0x5acca30,0x5accac3),(0x5acca3b,0x5accac3),(0x5acca54,0x5acca93),(0x5accab6,0x5accae2),(0x5accaf3,0x5accc2a),(0x5accb61,0x5963a10),(0x5accb84,0x4e18c50),(0x5accb8c,0x5accc01),(0x5accbb8,0x5accb6b)]:assert ins[a].operands[0].type==X86_OP_IMM and ins[a].operands[0].imm==v
a=0x5accaea;slot=a+len(rows[a])+int.from_bytes(rows[a][-4:],'little',signed=True);assert slot==0x64df480
r=next(x for x in s if x['name']=='.rela.dyn');rel={a:(i,d) for a,i,d in struct.iter_unpack('<QQq',b[r['offset']:r['offset']+r['size']])};assert rel[slot]==(8,0x6355830)
for remain,want in [(0,4),(3,4),(4,5),(100,101)]:assert max(3,remain)+1==want
limit=0x7ffffffffffffff8;assert ((1<<59)-1)*16<=limit and (1<<59)*16>limit
for a in [0x5a5e1e4,0x5acca17,0x5acca1f,0x5acca50,0x5acca66,0x5acca8c,0x5acca96,0x5accaa4,0x5accab6,0x5accacd,0x5accaea,0x5accb6b,0x5accb84,0x5accc13]:
 q=dict(rows);q[a]=q[a][:-1]+bytes([q[a][-1]^1])
 try:check(q)
 except AssertionError:pass
 else:raise AssertionError(hex(a))
print(f'{len(bodies)} FDEs, {len(rows)} instructions, {len(pins)} pins, 12 targets, relocation, 5 capacity cases and 14 controls: OK')
