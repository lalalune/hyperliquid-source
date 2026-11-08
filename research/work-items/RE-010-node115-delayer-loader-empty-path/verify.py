#!/usr/bin/env python3
"""Static evidence only: no target instruction execution or emulation."""
import csv,hashlib,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86_const import X86_OP_IMM
from elf_index import unwind_index
from fde_extents import eh_frame_records
P=Path('research/work-items/RE-010-node115-delayer-loader-empty-path')
b=Path('artifacts/node/115/hl-node').read_bytes();assert hashlib.sha256(b).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
s,h=unwind_index(b);_,f=eh_frame_records(b,s);idx={(x['start'],x['fde']) for x in h};t=next(x for x in s if x['name']=='.text')
def read(a,n):
 assert t['address']<=a and a+n<=t['address']+t['size'];p=t['offset']+a-t['address'];return b[p:p+n]
bodies={0x3bec320:(0x3becd9a,'4d2d247246e6bc942ff12681bc4ab13ff3f5ac8580b5863a512a7e0a32463a91'),0x3c12800:(0x3c12af5,'52e2718331566ec5c5cf72a65e69764441372b67802a9f3e8a04445e7d10949a'),0x4505c60:(0x4505ea1,'739f71a2d424a878b7955b9a60b475f1a237acfdfde1e5c6f59f5ef295adaaa7'),0x4550060:(0x455061f,'0877c0e1711c58557b9fd5c7c0b59d73df72311d9339a19ce7ce10e992fa8314')}
ins={};md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
for a,(z,d) in bodies.items():
 assert any(x['start']==a and x['end']==z and (a,x['fde']) in idx for x in f);raw=read(a,z-a);assert hashlib.sha256(raw).hexdigest()==d
 seq=list(md.disasm(raw,a));assert sum(x.size for x in seq)==len(raw);ins.update({x.address:x for x in seq})
rows={}
with (P/'instructions.tsv').open() as fp:
 for x in csv.DictReader(fp,delimiter='\t'):
  a=int(x['va'],16);v=bytes.fromhex(x['bytes']);assert a not in rows and a in ins and ins[a].bytes==v and read(a,len(v))==v;rows[a]=v
pins={0x3c1294b:'498dbc24c0400000',0x3c12953:'ff15b7258d02',0x3bec331:'4889fb',0x3bec334:'488b07',0x3bec33a:'48f7d9',0x3bec33d:'7124',0x3bec363:'488b5318',0x3bec367:'4885d2',0x3bec36a:'7428',0x3bec394:'31c9',0x3bec396:'31c0',0x3bec398:'31f6',0x3bec39a:'488b5308',0x3bec3a2:'488d3cca',0x3bec3aa:'488d04c2',0x3bec3b2:'488d0cca',0x3bec3b6:'41b802000000',0x3bec3bc:'49bf0000000000000080',0x3bec3c6:'4c89442408',0x3bec3cb:'48897c2410',0x3bec3d0:'4889442418',0x3bec3d5:'4889542420',0x3bec3da:'48894c2428',0x3bec3fc:'e85f989100',0x3bec401:'4885c0',0x3bec404:'741f',0x3bec425:'4c393b',0x3bec428:'752f',0x3bec45e:'4889df',0x3bec461:'e8fa3b9600',0x3bec46a:'4c393b',0x3bec46d:'0f94c1',0x3bec470:'4883f820',0x3bec474:'0f92c2',0x3bec477:'20ca',0x3bec479:'80fa01',0x3bec47c:'0f85fa040000',0x3bec97c:'48c744247000000000',0x3bec985:'48c744247808000000',0x3bec98e:'0f57c0',0x3bec991:'0f11842480000000',0x3bec99f:'48899c24e8000000',0x3bec9a7:'7524',0x3bec9cd:'488b5318',0x3bec9d1:'4885d2',0x3bec9d4:'7428',0x3bec9fe:'31c9',0x3beca00:'31c0',0x3beca02:'31f6',0x3beca04:'488b5308',0x3beca20:'41b802000000',0x3beca26:'4c89442408',0x3beca30:'48897c2410',0x3beca35:'4889442418',0x3beca3a:'4889542420',0x3beca3f:'48894c2428',0x3beca5c:'48c744245000000000',0x3beca65:'48c744246000000000',0x3beca6e:'31ed',0x3beca8c:'31c0',0x3beca8e:'4885c0',0x3beca93:'eb49',0x3becade:'488b442408',0x3becae3:'4883f802',0x3becae7:'7417',0x3becb00:'488b442410',0x3becb05:'488b4c2418',0x3becb0a:'4839c8',0x3becb0d:'7521',0x3becb0f:'0f104310',0x3becb13:'0f1103',0x3becb20:'488b442410',0x3becb25:'483b442418',0x3becb2a:'0f84a0000000',0x3becbd0:'31c0',0x3becbd6:'4885c0',0x3becbdf:'e967ffffff',0x3becb4b:'488b442460',0x3becb50:'4885c0',0x3becb53:'0f848b000000',0x3becbe4:'0f10442470',0x3becbe9:'0f108c2480000000',0x3becbf1:'0f298424f0000000',0x3becbf9:'0f298c2400010000',0x3becc01:'4c8ba424e8000000',0x3becc09:'498d5c2420',0x3becc0e:'498b742420',0x3becc13:'48b80000000000000080',0x3becc1d:'4839c6',0x3becc20:'7541',0x3becc63:'4885f6',0x3becc66:'744e',0x3beccb6:'0f288424f0000000',0x3beccbe:'0f288c2400010000',0x3beccc6:'0f114b10',0x3beccca:'0f1103',0x3becccd:'49896c2460',0x3becce3:'c3',0x4505c61:'488b07',0x4505c64:'4883f802',0x4505c68:'753b',0x4505c6e:'488b4708',0x4505c72:'488b5710',0x4505c76:'4839d0',0x4505c79:'751d',0x4505c7b:'0f104718',0x4505c7f:'0f1101',0x4505c8a:'488b4708',0x4505c8e:'483b4710',0x4505c92:'0f84d1010000',0x4505e69:'31c0',0x4505e70:'c3',0x455006e:'4c8b7f18',0x4550072:'4d85ff',0x4550075:'744f',0x45500c6:'31c0',0x45500c8:'4531d2',0x45500cb:'4d39fa',0x45500ce:'7217',0x45500d0:'4939c2',0x45500d3:'0f850e010000',0x45500d9:'e9c0020000',0x45503ac:'c3'}
def check(r):
 for a,v in pins.items():assert r[a]==bytes.fromhex(v),hex(a)
check(rows)
for a,v in [(0x3bec33d,0x3bec363),(0x3bec36a,0x3bec394),(0x3bec3fc,0x4505c60),(0x3bec404,0x3bec425),(0x3bec428,0x3bec459),(0x3bec461,0x4550060),(0x3bec47c,0x3bec97c),(0x3bec9a7,0x3bec9cd),(0x3bec9d4,0x3bec9fe),(0x3beca93,0x3becade),(0x3becae7,0x3becb00),(0x3becb2a,0x3becbd0),(0x3becbdf,0x3becb4b),(0x3becb53,0x3becbe4),(0x3becc20,0x3becc63),(0x3becc66,0x3beccb6),(0x4505c92,0x4505e69),(0x4550075,0x45500c6),(0x45500d9,0x455039e)]:
 assert ins[a].operands[0].type==X86_OP_IMM and ins[a].operands[0].imm==v
x=rows[0x3c12953];slot=0x3c12953+len(x)+int.from_bytes(x[-4:],'little',signed=True);assert slot==0x64e4f10
r=next(x for x in s if x['name']=='.rela.dyn');rel={a:(i,d) for a,i,d in struct.iter_unpack('<QQq',b[r['offset']:r['offset']+r['size']])};assert rel[slot]==(8,0x3bec320)
for a in (0x3bec33d,0x3bec36a,0x3bec3fc,0x3bec47c,0x3bec985,0x3beca20,0x3beca6e,0x3becb2a,0x3becc66,0x3beccc6,0x3becccd,0x4550075):
 m=dict(rows);m[a]=m[a][:-1]+bytes([m[a][-1]^1])
 try:check(m)
 except AssertionError:pass
 else:raise AssertionError(hex(a))
print(f'{len(bodies)} FDEs, {len(rows)} instruction spans, {len(pins)} pins, 19 direct targets, 1 relocation and 12 controls: OK')
