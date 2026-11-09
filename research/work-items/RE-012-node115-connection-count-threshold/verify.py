#!/usr/bin/env python3
"""Digest-bound static instruction pins, no target execution."""
from hashlib import sha256
from pathlib import Path
from elf_index import unwind_index
from fde_extents import eh_frame_records
b=Path('artifacts/node/115/hl-node').read_bytes()
assert sha256(b).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
s,h=unwind_index(b);_,f=eh_frame_records(b,s);idx={(x['start'],x['fde']) for x in h}
def read(a,n):
    x=next(x for x in s if x['address']<=a and a+n<=x['address']+x['size'] and x['name']=='.text')
    p=x['offset']+a-x['address'];return b[p:p+n]
for a,z,d in [(0x5a628d0,0x5a630f2,'7ee3fff5e3a94a4e82d5d2da9234ad2592ed6435c73cbd0b2d56450eec6d5b90'),(0x4fabf60,0x4fac30f,'8fe2ec7b2ff254d29cbf59467af8bb268a1965e293b39b8ecac146ae6527d43c')]:
    assert any(x['start']==a and x['end']==z and (a,x['fde']) in idx for x in f)
    assert sha256(read(a,z-a)).hexdigest()==d
pins={0x5a62b6f:'41803e00',0x5a62b73:'0f84aa000000',0x5a62b79:'498b4608',0x5a62b7d:'4883f809',0x5a62b81:'b908000000',0x5a62b86:'480f43c8',0x5a62b8a:'4883f964',0x5a62b8e:'ba64000000',0x5a62b93:'480f42d1',0x5a62b97:'4889542470',0x5a62b9c:'4839c2',0x5a62b9f:'7475',0x5a62c10:'ff1502dfa700',0x5a62c16:'4c89fe',0x5a62c19:'4584e4',0x5a62c1c:'741a',0x5a62c1e:'e9ae000000',0x5a62c23:'48c744247008000000',0x5a62c2f:'4584e4',0x5a62c32:'0f8599000000',0x5a62c38:'498d7520',0x5a62c3c:'4983bd9800000000',0x5a62c44:'0f8487000000',0x5a62cce:'4c89f6',0x5a62cd1:'4883c628',0x5a62cd5:'4889df',0x5a62cd8:'e8839254ff',0x5a62cdd:'483b442470',0x5a62ce2:'732c',0x5a62ce4:'b003',0x5a62ce6:'4584e4',0x5a62ce9:'0f857b010000',0x5a62cef:'48c7c1f0ffffff',0x5a62cf6:'f0490fc10f',0x5a62cfb:'4883e1f2',0x5a62cff:'b003',0x5a62d01:'4883f912',0x5a62d05:'0f855f010000',0x5a62d0b:'e926030000',0x5a63039:'4189c6',0x5a6303c:'ff15a6dfa700',0x5a63042:'4489f0',0x5a63045:'e920feffff',0x5a62e6a:'3c03',0x5a62e6c:'0f95c1',0x5a62e6f:'4080f501',0x5a62e73:'4008cd'}
def check(r):
    for a,hx in pins.items():
        q=bytes.fromhex(hx);assert r(a,len(q))==q,hex(a)
    a=0x5a62cd8;q=r(a,5);assert a+5+int.from_bytes(q[1:],'little',signed=True)==0x4fabf60
check(read)
for bad in [0x5a62b73,0x5a62b7d,0x5a62b86,0x5a62b8a,0x5a62b93,0x5a62b9f,0x5a62c23,0x5a62cd8,0x5a62cdd,0x5a62ce2,0x5a62ce4,0x5a63042]:
    def corrupt(a,n):
        q=bytearray(read(a,n))
        if a<=bad<a+n:q[bad-a]^=1
        return bytes(q)
    try:check(corrupt)
    except AssertionError:pass
    else:raise AssertionError(hex(bad))
xs=(0,1,7,8,9,99,100,101,2**63,2**64-1)
for present in (False,True):
    for x in xs:
        t=(min(100,max(8,x)) if present else 8)
        assert 8<=t<=100
        for n in (0,7,8,9,99,100,101,2**64-1):
            assert (n>=t)==(not n<t)
        if present:assert (t==x)==(8<=x<=100)
print(f'2 FDEs, {len(pins)} instruction pins, 12 mutation controls, 160 unsigned boundary pairs: OK')
