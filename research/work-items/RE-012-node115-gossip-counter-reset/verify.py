#!/usr/bin/env python3
"""Static evidence checks; never execute or emulate the captured target."""
import csv,hashlib
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86_const import X86_OP_IMM
from elf_index import unwind_index
from fde_extents import eh_frame_records
P=Path('research/work-items/RE-012-node115-gossip-counter-reset')
b=Path('artifacts/node/115/hl-node').read_bytes();assert hashlib.sha256(b).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
s,h=unwind_index(b);_,f=eh_frame_records(b,s);idx={(x['start'],x['fde']) for x in h}
def read(a,n):
 x=next(x for x in s if x['address']<=a and a+n<=x['address']+x['size'] and x['name'] in ('.text','.rodata'));p=x['offset']+a-x['address'];return b[p:p+n]
bodies={0x5a5dbc0:(0x5a5e281,'5d9b8d4faa0106747b55edfc16afc1e706f6f7a0aeb979b95803bab4e6523320'),0x5617370:(0x561777f,'3377b5e65b9c97f4c094a68e682d1db1009e6ecada826bed5f6d7cce9a7a249d'),0x59db990:(0x59dbc1d,'5d3506a86664fe53a12d16371a1b2cf21c0b012122d677ae7249b39e7ecab8a1')}
m=Cs(CS_ARCH_X86,CS_MODE_64);m.detail=True;ins={}
for a,(z,d) in bodies.items():
 assert any(x['start']==a and x['end']==z and (a,x['fde']) in idx for x in f)
 raw=read(a,z-a);assert hashlib.sha256(raw).hexdigest()==d
 seq=list(m.disasm(raw,a));assert sum(x.size for x in seq)==len(raw);ins.update({x.address:x for x in seq})
rows={}
with (P/'instructions.tsv').open() as fp:
 for x in csv.DictReader(fp,delimiter='\t'):
  a=int(x['va'],16);v=bytes.fromhex(x['bytes']);assert a not in rows and a in ins and ins[a].bytes==v and read(a,len(v))==v;rows[a]=v
pins={94756279: '31c0', 94756281: '4885c9', 94756284: '480f4fc1', 94756288: '488b8d70010000', 94756298: '4809ca', 94756301: '48c1ea20', 94756305: '0f84db000000', 94756313: '48f7f1', 94756316: '4c8d6518', 94756320: '488b8d78010000', 94756327: '4839c8', 94756330: '7607', 94756332: '48898578010000', 94756339: '4839c8', 94756342: '488d0574a8edfa', 94756354: '48c74424300e000000', 94756375: '0f97442448', 94756380: '488d7c2428', 94756385: '4c89e6', 94756388: 'e84795bbff', 94756532: 'f7f1', 94756534: '4c8d6518', 94756538: '488b8d78010000', 94756545: '4839c8', 94756548: '0f8722ffffff', 94756554: 'e924ffffff', 90272641: '440fb67720', 90272646: '4180fe01', 90272650: '0f855c030000', 90272656: '4989f7', 90272677: '4c89ff', 90272680: 'e8e3453c00', 94222746: '488b8788010000', 94222756: '746b', 94222829: 'e80ecb1b00', 94222865: '488b83e8010000', 94222878: '840b', 94222880: '746b', 94222989: '4883bb4001000000', 94222997: '7452', 94223063: '48c7834001000000000000', 94223074: '48898338010000', 94223081: '4883bb8801000000', 94223089: '7452', 94223155: '48c7838801000000000000', 94223166: '48898380010000', 94223173: '4883bbe801000000', 94223181: '7452', 94223247: '48c783e801000000000000', 94223258: '488983e0010000', 94223289: '4883bbb801000000', 94223297: '7452', 94223363: '48c783b801000000000000', 94223374: '488983b0010000'}
def check(r):
 for a,v in pins.items():assert r[a]==bytes.fromhex(v),hex(a)
check(rows)
for a,v in [(0x5a5ddd1,0x5a5deb2),(0x5a5ddea,0x5a5ddf3),(0x5a5de24,0x5617370),(0x5a5dec4,0x5a5ddec),(0x5a5deca,0x5a5ddf3),(0x561738a,0x56176ec),(0x56173a8,0x59db990),(0x59db9a4,0x59dba11),(0x59db9ed,0x5b98500),(0x59dba20,0x59dba8d),(0x59dba95,0x59dbae9),(0x59dbaf1,0x59dbb45),(0x59dbb4d,0x59dbba1),(0x59dbbc1,0x59dbc15)]:assert ins[a].operands[0].type==X86_OP_IMM and ins[a].operands[0].imm==v
a=0x5a5ddf6;assert a+len(rows[a])+int.from_bytes(rows[a][-4:],'little',signed=True)==0x938671 and read(0x938671,14)==b'reset_counters'
for n,d,old,want in [(0,1,0,False),(9,3,3,False),(10,3,2,True),((1<<32)+2,2,1,True)]:assert (n//d>old)==want
for a in [0x5a5ddbc,0x5a5ddc0,0x5a5ddd1,0x5a5ddd9,0x5a5ddec,0x5a5de17,0x5a5de24,0x561738a,0x56173a8,0x59dbad7,0x59dbb33,0x59dbb8f,0x59dbc03]:
 q=dict(rows);q[a]=q[a][:-1]+bytes([q[a][-1]^1])
 try:check(q)
 except AssertionError:pass
 else:raise AssertionError(hex(a))
print(f'{len(bodies)} FDEs, {len(rows)} instructions, {len(pins)} pins, 14 targets, literal, 4 arithmetic cases and 13 controls: OK')
