#!/usr/bin/env python3
"""Selected static helper/caller evidence, no target execution."""
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
for a,z,d in [(0x5a628d0,0x5a630f2,'7ee3fff5e3a94a4e82d5d2da9234ad2592ed6435c73cbd0b2d56450eec6d5b90'),(0x59db3a0,0x59db6f4,'669c5b78a31be6b0f7a03396b8ec6f72effc257f87ed4d03027a8d9759be034e')]:
    assert any(x['start']==a and x['end']==z and (a,x['fde']) in idx for x in f)
    assert sha256(read(a,z-a)).hexdigest()==d
pins={0x5a62fc2:'ba01000000',0x5a62fc7:'b901000000',0x5a62fcf:'e8cc83f7ff',0x5a62fd4:'89c5',0x5a62fda:'f00fb00b',0x5a62fde:'757d',0x5a62fe0:'89e8',0x5a62fe2:'3403',0x5a63068:'e973ffffff',0x59db3ae:'4989cf',0x59db3b1:'4989d4',0x59db3ba:'488b8768010000',0x59db3d5:'ffd0',0x59db3d7:'84c0',0x59db3d9:'0f85c8020000',0x59db4c3:'4d0365f0',0x59db4c7:'48c7c5ffffffff',0x59db4ce:'4c89e0',0x59db4d1:'480f42c5',0x59db4d5:'490f43c4',0x59db4d9:'498945f0',0x59db554:'498b45f8',0x59db558:'48ffc0',0x59db55b:'480f44c5',0x59db55f:'498945f8',0x59db569:'0f80ba000000',0x59db5fb:'49f76640',0x59db5ff:'7028',0x59db601:'4939c4',0x59db604:'7623',0x59db624:'e887c951ff',0x59db629:'4d397df0',0x59db62d:'7678',0x59db64a:'e861d551ff',0x59db64f:'89c1',0x59db651:'b001',0x59db653:'84c9',0x59db655:'7552',0x59db657:'48b90000000000000080',0x59db661:'49394e78',0x59db665:'7442',0x59db69e:'e81d3646ff',0x59db6a3:'b001',0x59db6a5:'eb02',0x59db6a7:'31c0',0x59db6b7:'c3'}
def check(r):
    for a,hx in pins.items():
        q=bytes.fromhex(hx);assert r(a,len(q))==q,hex(a)
    for a,dst in [(0x5a62fcf,0x59db3a0),(0x59db64a,0x4ef8bb0),(0x59db624,0x4ef7fb0),(0x59db69e,0x4e3ecc0)]:
        q=r(a,5);assert a+5+int.from_bytes(q[1:],'little',signed=True)==dst
check(read)
for bad in [0x5a62fc2,0x5a62fc7,0x5a62fcf,0x5a62fe2,0x59db3d9,0x59db4c3,0x59db4d1,0x59db4d9,0x59db629,0x59db62d,0x59db64a,0x59db651,0x59db655,0x59db6a3,0x59db6a7]:
    def corrupt(a,n):
        q=bytearray(read(a,n))
        if a<=bad<a+n:q[bad-a]^=1
        return bytes(q)
    try:check(corrupt)
    except AssertionError:pass
    else:raise AssertionError(hex(bad))
for s in (0,1,2,3,2**32-1,2**63,2**64-2,2**64-1):
    c=min(2**64-1,s+1);raw=int(c>1);final=raw^3
    assert final==(3 if s==0 else 2)
print(f'2 FDEs, {len(pins)} instruction pins, 4 call targets, 15 corruption controls, 8 arithmetic boundaries: OK')
