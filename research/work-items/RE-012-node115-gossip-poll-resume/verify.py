#!/usr/bin/env python3
"""Static identity, branch and table checks; no target instruction evaluation."""
import hashlib,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from elf_index import unwind_index
from fde_extents import eh_frame_records
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
BODIES={0x2ae0920:(0x2ae135b,'c842a6d6b0c05a9b3978bcf786d556c62d71c4b055da335bf4b5617bbeb859be'),0x2ae0100:(0x2ae0917,'17ba33c03bd1b37e26619290295566665c7d760d7de93ebb1929f4fb7311a5f9'),0x5ce94c0:(0x5ce95b7,'e1db2f2068ff64f842ccac3e4607101bd76d9d59eb5a0cc5a0218388f616fadf')}
PINS={
 0x2ae0931:'4989d5',0x2ae0934:'4889f3',0x2ae0937:'4989ff',0x2ae093a:'0fb606',
 0x2ae093d:'488d0d1437b2fd',0x2ae0944:'48630481',0x2ae0948:'4801c8',0x2ae094b:'ffe0',
 0x2ae094d:'8b4301',0x2ae0950:'894305',0x2ae0953:'488d4b09',0x2ae0957:'894309',
 0x2ae095a:'48c7431001000000',0x2ae0962:'48894b28',0x2ae0966:'c683980d000000',
 0x2ae096d:'4c8d7310',0x2ae0971:'488dbc2440030000',0x2ae0979:'4c89f6',0x2ae097c:'4c89ea',
 0x2ae097f:'e87cf7ffff',0x2ae0984:'0fb6ac2440030000',0x2ae098c:'4080fd45',0x2ae0990:'7557',
 0x2ae0992:'41c60745',0x2ae0996:'b003',0x2ae0998:'e9e2070000',
 0x2ae099d:'488d83b0030000',0x2ae09a4:'4889442418',0x2ae09a9:'0fb683b0030000',
 0x2ae09b4:'488d0db136b2fd',0x2ae09bb:'48630481',0x2ae09bf:'4801c8',0x2ae09c7:'ffe0',
 0x2ae0e75:'e866740900',0x2ae0e7a:'4c8bb42450020000',0x2ae0e82:'4983fe03',0x2ae0e86:'753b',
 0x2ae0e88:'4080fd02',0x2ae0e8c:'0f94c0',0x2ae0e8f:'4008e8',0x2ae0e92:'0fb6f8',
 0x2ae0e95:'83e701',0x2ae0e98:'4c89e6',0x2ae0e9b:'4c89ea',0x2ae0e9e:'ff15b404a003',
 0x2ae0ea4:'84c0',0x2ae0ea6:'743e',0x2ae0ea8:'488b442408',0x2ae0ead:'c60003',
 0x2ae0eb0:'488b442418',0x2ae0eb5:'c60003',0x2ae0eb8:'41c60745',0x2ae0ebc:'b004',
 0x2ae0ebe:'e9bc020000',0x2ae112e:'41882f',0x2ae1131:'45897701',0x2ae113c:'41884707',
 0x2ae1144:'6645897705',0x2ae1169:'410f114708',0x2ae116e:'410f114f18',
 0x2ae1173:'410f115728',0x2ae1178:'410f115f38',0x2ae117d:'b001',0x2ae117f:'8803',
}
b=Path('artifacts/node/115/hl-node').read_bytes();assert hashlib.sha256(b).hexdigest()==SHA
secs,hdr=unwind_index(b);_,fdes=eh_frame_records(b,secs);idx={(x['start'],x['fde']) for x in hdr}
def read(a,n):
 s=next(x for x in secs if x['address']<=a and a+n<=x['address']+x['size']);p=s['offset']+a-s['address'];return b[p:p+n]
starts=set();cs=Cs(CS_ARCH_X86,CS_MODE_64)
for a,(z,digest) in BODIES.items():
 assert any(x['start']==a and x['end']==z and (a,x['fde']) in idx for x in fdes)
 body=read(a,z-a);assert hashlib.sha256(body).hexdigest()==digest
 rows=list(cs.disasm(body,a));assert sum(x.size for x in rows)==len(body);starts.update(x.address for x in rows)
spans={a:read(a,len(bytes.fromhex(v))) for a,v in PINS.items()}
def check(rows):
 for a,v in PINS.items():assert a in starts and rows[a]==bytes.fromhex(v),hex(a)
check(spans)
def target(a):
 raw=spans[a];return a+len(raw)+struct.unpack_from('<i',raw,len(raw)-4)[0]
for a,t in [(0x2ae093d,0x604058),(0x2ae097f,0x2ae0100),(0x2ae0998,0x2ae117f),
            (0x2ae09b4,0x60406c),(0x2ae0e75,0x2b782e0),(0x2ae0e9e,0x64e1358),(0x2ae0ebe,0x2ae117f)]:assert target(a)==t
assert [0x604058+x for x in struct.unpack('<5i',read(0x604058,20))]==[0x2ae094d,0x2ae11ae,0x2ae11bb,0x2ae096d,0x2ae099d]
s=next(x for x in secs if x['name']=='.rela.dyn');rel={a:(i,d) for a,i,d in struct.iter_unpack('<QQq',b[s['offset']:s['offset']+s['size']])}
assert rel[0x64e1358]==(8,0x5ce94c0)
for a in (0x2ae0992,0x2ae0996,0x2ae0eb8,0x2ae0ebc,0x2ae117f):
 changed=dict(spans);changed[a]=changed[a][:-1]+bytes([changed[a][-1]^1])
 try:check(changed)
 except AssertionError:pass
 else:raise AssertionError('mutation accepted '+hex(a))
print(f'{len(BODIES)} indexed FDEs decoded, {len(PINS)} spans, 7 targets, 5 table entries, 1 relocation and 5 corruption controls: OK')
