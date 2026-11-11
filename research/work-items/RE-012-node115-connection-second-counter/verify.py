#!/usr/bin/env python3
"""Static target pins only, no target execution or emulation."""
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
for a,z,d in [(0x5a628d0,0x5a630f2,'7ee3fff5e3a94a4e82d5d2da9234ad2592ed6435c73cbd0b2d56450eec6d5b90'),(0x59db3a0,0x59db6f4,'669c5b78a31be6b0f7a03396b8ec6f72effc257f87ed4d03027a8d9759be034e'),(0x5617370,0x561777f,'3377b5e65b9c97f4c094a68e682d1db1009e6ecada826bed5f6d7cce9a7a249d')]:
    assert any(x['start']==a and x['end']==z and (a,x['fde']) in idx for x in f)
    assert sha256(read(a,z-a)).hexdigest()==d
pins={0x5a628e1:'89d5',0x5a628e6:'89742414',0x5a62cd8:'e8839254ff',0x5a62cdd:'483b442470',0x5a62ce2:'732c',0x5a62ce4:'b003',0x5a62ce9:'0f857b010000',0x5a62cf6:'f0490fc10f',0x5a62cff:'b003',0x5a62d05:'0f855f010000',0x5a62d0b:'e926030000',0x5a63039:'4189c6',0x5a63042:'4489f0',0x5a63045:'e920feffff',0x5a62e6a:'3c03',0x5a62e6c:'0f95c1',0x5a62e6f:'4080f501',0x5a62e73:'4008cd',0x5a62e76:'0f8568010000',0x5a62e7c:'4c8b7b08',0x5a62e80:'498d5f10',0x5a62e84:'b101',0x5a62e86:'31c0',0x5a62e88:'f0410fb04f10',0x5a62e8e:'0f85b6010000',0x5a62e94:'8b442414',0x5a62e98:'89442419',0x5a62e9c:'c644241800',0x5a62f70:'4d8d7718',0x5a62fb0:'488d7c2430',0x5a62fb5:'4c89f6',0x5a62fb8:'e8b343bbff',0x5a62fbd:'488d742418',0x5a62fc2:'ba01000000',0x5a62fc7:'b901000000',0x5a62fcc:'4c89f7',0x5a62fcf:'e8cc83f7ff',0x5a62fd4:'89c5',0x5a62fd6:'31c9',0x5a62fd8:'b001',0x5a62fda:'f00fb00b',0x5a62fde:'757d',0x5a62fe0:'89e8',0x5a62fe2:'3403',0x5a62fe4:'4881c498000000',0x5a62ff5:'c3',0x5a63058:'e937feffff',0x5a63068:'e973ffffff'}
def check(r):
    for a,hx in pins.items():
        q=bytes.fromhex(hx);assert r(a,len(q))==q,hex(a)
    for a,dst in [(0x5a62cd8,0x4fabf60),(0x5a62fb8,0x5617370),(0x5a62fcf,0x59db3a0)]:
        q=r(a,5);assert a+5+int.from_bytes(q[1:],'little',signed=True)==dst
check(read)
for bad in [0x5a628e1,0x5a62ce2,0x5a62ce4,0x5a62e6f,0x5a62e76,0x5a62e88,0x5a62e9c,0x5a62fb8,0x5a62fc2,0x5a62fc7,0x5a62fcf,0x5a62fda,0x5a62fe2,0x5a63068]:
    def corrupt(a,n):
        q=bytearray(read(a,n))
        if a<=bad<a+n:q[bad-a]^=1
        return bytes(q)
    try:check(corrupt)
    except AssertionError:pass
    else:raise AssertionError(hex(bad))
assert (0^3,1^3)==(3,2)
for v in range(256):assert ((v^3)^3)==v
print(f'3 FDEs, {len(pins)} instruction pins, 3 call targets, 14 corruption controls, 256 byte cases: OK')
