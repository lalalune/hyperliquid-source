#!/usr/bin/env python3
"""Authenticate selected call/branch evidence without executing target instructions."""
import hashlib,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from elf_index import unwind_index
from fde_extents import eh_frame_records
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
BODIES={
 0x2accee0:(0x2ad0db0,'73de7d70235eee244bbfc1b605d48e680c3753eda7399dbe284ae2a2420a8847'),
 0x2ad0db0:(0x2ad4db7,'efa7a22d973e50959dd1c0eb347fb907e9e488aa73801c5b6ec965504c5bb45f'),
 0x5a628d0:(0x5a630f2,'7ee3fff5e3a94a4e82d5d2da9234ad2592ed6435c73cbd0b2d56450eec6d5b90'),
 0x57d2f80:(0x57d329b,'2d0888c35ad76496ae435dfe159b7053f3ffe7edd091746e8109a1ca79808f58'),
}
PINS={
 0x2acd87a:'488b8358210000',0x2acd881:'80b89000000004',0x2acd888:'0f84e7000000',
 0x2acd88e:'4883c078',0x2acd892:'48898310220000',0x2acd8b3:'488dbc24d0020000',
 0x2acd8c1:'e85a300100',0x2acd8c6:'440fb6bc24d0020000',0x2acd8cf:'4180ff45',
 0x2acd8d3:'750d',0x2acd8d5:'b004',0x2acd8d7:'888304220000',0x2acd8dd:'e9ce000000',
 0x2acd93a:'4c89f7',0x2acd93d:'e87e2effff',0x2acd942:'4180ff44',0x2acd946:'0f85b3000000',
 0x2acd94c:'488bbb10220000',0x2acd953:'8bb300220000',0x2acd959:'0fb69306220000',
 0x2acd960:'488b8b58210000',0x2acd967:'ff15ab99a103',0x2acd96d:'3c03',0x2acd96f:'0f8533020000',
 0x2ad1774:'488bbb58210000',0x2ad177b:'80bf9000000004',0x2ad1782:'0f8406010000',
 0x2ad1788:'488d4778',0x2ad178c:'48898310220000',0x2ad1793:'80bb0622000001',
 0x2ad179a:'7515',0x2ad17a3:'ff159f5ba103',0x2ad17a9:'84c0',0x2ad17ab:'0f842c050000',
 0x2ad17cb:'488dbc24a0020000',0x2ad17db:'e840f10000',0x2ad17e0:'0fb6ac24a0020000',
 0x2ad17e8:'4080fd45',0x2ad17ec:'750d',0x2ad17ee:'b004',0x2ad17f0:'888304220000',
 0x2ad17f6:'e9ce000000',0x2ad1853:'4c89f7',0x2ad1856:'e865effeff',0x2ad185b:'4080fd44',
 0x2ad185f:'0f85b2000000',0x2ad1865:'488bbb10220000',0x2ad186c:'8bb300220000',
 0x2ad1872:'0fb69306220000',0x2ad1879:'488b8b58210000',0x2ad1880:'ff15925aa103',
 0x2ad1886:'3c03',0x2ad1888:'0f853b020000',
 0x5a628e3:'4889fb',0x5a628ea:'803900',0x5a628ed:'0f8492000000',0x5a628f8:'4c8b6b10',
 0x5a628fc:'41807d1000',0x5a62901:'7539',0x5a62903:'4d8d7518',0x5a62907:'b908000000',
 0x5a6290c:'31c0',0x5a6290e:'f0490fb14d18',0x5a62914:'0f85f9060000',
 0x5a6291a:'498d7d20',0x5a6291e:'488d35bb85a400',0x5a62925:'e85606d7ff',
 0x5a6292a:'31c9',0x5a6292c:'b808000000',0x5a62931:'f0490fb10e',0x5a62936:'0f85ea060000',
 0x5a6301b:'ff15cfdfa700',0x5a63021:'e9f4f8ffff',0x5a6302b:'ff15cfdfa700',0x5a63031:'e906f9ffff',
}
b=Path('artifacts/node/115/hl-node').read_bytes();assert hashlib.sha256(b).hexdigest()==SHA
secs,hdr=unwind_index(b);_,fdes=eh_frame_records(b,secs);idx={(x['start'],x['fde']) for x in hdr}
def read(a,n):
 s=next(x for x in secs if x['address']<=a and a+n<=x['address']+x['size']);p=s['offset']+a-s['address'];return b[p:p+n]
starts=set();cs=Cs(CS_ARCH_X86,CS_MODE_64)
for a,(z,digest) in BODIES.items():
 assert any(x['start']==a and x['end']==z and (a,x['fde']) in idx for x in fdes)
 body=read(a,z-a);assert hashlib.sha256(body).hexdigest()==digest
 rows=list(cs.disasm(body,a));assert sum(x.size for x in rows)==len(body)
 starts.update(x.address for x in rows)
spans={a:read(a,len(bytes.fromhex(v))) for a,v in PINS.items()}
def check(rows):
 for a,v in PINS.items():assert a in starts and rows[a]==bytes.fromhex(v),hex(a)
check(spans)
def target(a):
 raw=spans[a];return a+len(raw)+struct.unpack_from('<i',raw,len(raw)-4)[0]
for a,t in [(0x2acd8c1,0x2ae0920),(0x2acd93d,0x2ac07c0),(0x2acd967,0x64e7318),
            (0x2ad17a3,0x64e7348),(0x2ad17db,0x2ae0920),(0x2ad1856,0x2ac07c0),(0x2ad1880,0x64e7318),
            (0x5a6291e,0x64aaee0),(0x5a62925,0x57d2f80),(0x5a6301b,0x64e0ff0),
            (0x5a63021,0x5a6291a),(0x5a6302b,0x64e1000),(0x5a63031,0x5a6293c)]:assert target(a)==t
sec=next(x for x in secs if x['name']=='.rela.dyn')
rel={a:(i,d) for a,i,d in struct.iter_unpack('<QQq',b[sec['offset']:sec['offset']+sec['size']])}
for a,v in [(0x64e7318,0x5a628d0),(0x64e7348,0x4fb98f0),(0x64e0ff0,0x5bb2440),(0x64e1000,0x5bb35f0),(0x64aaee0,0x449029)]:assert rel[a]==(8,v)
assert read(0x449029,25)==b'node/src/gossip_config.rs'
assert struct.unpack('<QII',read(0x64aaee8,16))==(25,103,32)
for a in (0x2acd942,0x2ad185b,0x5a6290e,0x5a62925):
 altered=dict(spans);altered[a]=altered[a][:-1]+bytes([altered[a][-1]^1])
 try:check(altered)
 except AssertionError:pass
 else:raise AssertionError('mutation accepted '+hex(a))
print(f'{len(BODIES)} indexed FDEs decoded, {len(PINS)} instruction spans, 13 targets, 5 relocations and 4 corruption controls: OK')
