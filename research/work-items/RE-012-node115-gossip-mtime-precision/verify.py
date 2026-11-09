#!/usr/bin/env python3
"""Authenticate static data flow; no captured instruction evaluation."""
import hashlib
import struct
from pathlib import Path
from elf_index import unwind_index
from fde_extents import eh_frame_records

SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
BODIES={
 0x15027d0:(0x15028e1,'1311182c4378a093d4c47706484bd711345066cfa22734437dd94c52de88f8bd'),
 0x57d2f80:(0x57d329b,'2d0888c35ad76496ae435dfe159b7053f3ffe7edd091746e8109a1ca79808f58'),
 0x5c84210:(0x5c842d6,'f9d8d8a41505bf8c9552d4a34ac4e190a6d0665c245595be11f2848e1a333a4a'),
 0x5c9c810:(0x5c9ca28,'6ce20119c3543cdfeae06be3764719ec70f24c7d0ef15dc381c455f2c39f47cd'),
 0x5c9f780:(0x5c9fa97,'38c0f7879fc3b0724f85b10db5654c2046b5aa06d6bf4a442104fe51195cfc2f'),
}
PINS={
 0x5c9f95a:'488b8540ffffff',0x5c9f961:'48894378',0x5c9f965:'8b8548ffffff',0x5c9f96b:'48898380000000',
 0x5c9c948:'e8332e0000',0x5c9c94d:'83bd30ffffff03',0x5c9c954:'0f8591000000',
 0x15027df:'488d7c2420',0x15027e4:'ff1546e1fd04',0x15027ea:'837c242002',0x15027ef:'0f8497000000',
 0x15027f5:'488b8424a0000000',0x15027fd:'483d00ca9a3b',0x1502803:'0f838f000000',
 0x1502809:'488b8c2498000000',0x1502811:'48890c24',0x1502815:'89442408',
 0x1502819:'48c744241000000000',0x1502822:'c744241800000000',0x1502837:'e8d4197804',
 0x150283c:'4c8b742428',0x1502841:'837c242001',0x1502846:'745e',
 0x150284b:'48c1e820',0x150284f:'7563',0x1502851:'41bf07452ec2',0x1502857:'4d0faffe',
 0x150285b:'49c1ef30',0x150285f:'418dbf3bf90a00',0x1502866:'ff1584d7fd04',
 0x150286c:'85c0',0x150286e:'7464',0x1502870:'4169cf80510100',0x1502877:'4129ce',
 0x150287a:'894304',0x150287d:'44897308',0x1502881:'c7430c00000000',0x1502888:'31c0',0x15028c2:'8903',
 0x5c8421f:'488b36',0x5c84222:'488b0a',0x5c84225:'448b4008',0x5c84229:'8b7a08',
 0x5c8422f:'4139f8',0x5c84232:'410f93c1',0x5c84239:'4839ce',0x5c8423c:'410f9dc2',0x5c84240:'450f44d1',0x5c84247:'744a',
 0x5c84249:'418d8000ca9a3b',0x5c84250:'4889ca',0x5c84253:'48f7da',0x5c84256:'4139f8',
 0x5c84259:'48f7d1',0x5c8425c:'410f43c0',0x5c84260:'480f43ca',0x5c84264:'4801f1',
 0x5c84267:'29f8',0x5c84269:'3d00ca9a3b',0x5c8426e:'720e',0x5c8427e:'48894b08',0x5c84282:'894310',0x5c84285:'48c70300000000',
 0x57d2fc5:'488d7c2408',0x57d2fca:'4c89e6',0x57d2fcd:'4c89ea',0x57d2fd0:'ff153adad000',0x57d2fda:'83fd01',0x57d2fdd:'7513',
 0x57d2ff2:'8b44240c',0x57d2ff6:'8b4c2410',0x57d2ffe:'8b4c2414',
 0x57d2ffa:'894c2404',0x57d3002:'890c24',0x57d3005:'89442424',0x57d3009:'3b8380000000',0x57d300f:'0f9fc0',0x57d3018:'3b8384000000',0x57d301e:'0f97c0',
 0x57d3023:'8b0424',0x57d3026:'3b8388000000',0x57d302c:'0f86d6000000',0x57d303c:'488dbc2480000000',0x57d3044:'4c89e6',0x57d3047:'4c89ea',0x57d304a:'4c89f1',0x57d304d:'e85e8c90ff',
 0x57d317b:'8b442424',0x57d317f:'898380000000',0x57d3185:'8b442404',
 0x57d3189:'898384000000',0x57d318f:'8b0424',0x57d3192:'898388000000',
}
b=Path('artifacts/node/115/hl-node').read_bytes();assert hashlib.sha256(b).hexdigest()==SHA
secs,hdr=unwind_index(b);_,fdes=eh_frame_records(b,secs);idx={(x['start'],x['fde']) for x in hdr}
def read(a,n):
 s=next(x for x in secs if x['address']<=a and a+n<=x['address']+x['size']);p=s['offset']+a-s['address'];return b[p:p+n]
for start,(end,digest) in BODIES.items():
 assert any(x['start']==start and x['end']==end and (start,x['fde']) in idx for x in fdes)
 assert hashlib.sha256(read(start,end-start)).hexdigest()==digest
spans={a:read(a,len(bytes.fromhex(raw))) for a,raw in PINS.items()}
def check(rows):
 for a,raw in PINS.items(): assert rows[a]==bytes.fromhex(raw),hex(a)
check(spans)
def target(a):
 raw=spans[a];return a+len(raw)+struct.unpack_from('<i',raw,len(raw)-4)[0]
for a,t in [(0x15027e4,0x64e0930),(0x1502837,0x5c84210),(0x1502866,0x64dfff0),
            (0x57d2fd0,0x64e0a10),(0x57d304d,0x50dbcb0),(0x5c9c948,0x5c9f780)]:assert target(a)==t
s=next(x for x in secs if x['name']=='.rela.dyn')
rel={a:(i,d) for a,i,d in struct.iter_unpack('<QQq',b[s['offset']:s['offset']+s['size']])}
for slot,dest in [(0x64e0930,0x5c9c810),(0x64dfff0,0x1628f50),(0x64e0a10,0x15027d0)]:assert rel[slot]==(8,dest)
# Exact reciprocal bound proves the u32 seconds quotient for all inputs, not a native execution.
m=0xc22e4507; assert m*86400==2**48+47744 and ((2**32)-1)*47744 < 2**48
for sec in [0,1,86399,86400,86401,2**32-1]:
 q=(sec*m)>>48;assert q==sec//86400
 for ns in [0,1,999999999]:
  assert 0<=ns<10**9 and (q,sec-q*86400,0)==(sec//86400,sec%86400,0)
for a in (0x15027fd,0x1502881,0x57d302c,0x57d3192):
 changed=dict(spans);changed[a]=changed[a][:-1]+bytes([changed[a][-1]^1])
 try:check(changed)
 except AssertionError:pass
 else:raise AssertionError('mutation accepted '+hex(a))
print(f'{len(BODIES)} indexed FDEs, {len(PINS)} exact spans, 6 call targets, 3 relocations, reciprocal proof and 4 corruptions: OK')
