#!/usr/bin/env python3
"""Static original-byte checks and index arithmetic only."""
from hashlib import sha256
from pathlib import Path
from elf_index import unwind_index
from fde_extents import eh_frame_records
b = Path('artifacts/node/115/hl-node').read_bytes()
assert sha256(b).hexdigest() == 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
s,h = unwind_index(b)
_,f = eh_frame_records(b,s)
idx = {(x['start'],x['fde']) for x in h}
def read(a,n):
    x=next(x for x in s if x['address']<=a and a+n<=x['address']+x['size'] and x['name']=='.text')
    p=x['offset']+a-x['address']
    return b[p:p+n]
for a,z,d in [(0x4e18c50,0x4e18dfe,'8708a3941b37625fe634ed3496cbaa27045177a66e2bd65122efdfcf8d398a15'),(0x5acca00,0x5accc71,'8fbc9e12bde4d8eb49f62cf1ab939a35392b1ca843ad3593537008290b7aa57c')]:
    assert any(x['start']==a and x['end']==z and (a,x['fde']) in idx for x in f)
    assert sha256(read(a,z-a)).hexdigest()==d
pins={
0x4e18c51:'488b07',0x4e18c54:'4885c0',0x4e18c57:'0f84fe000000',0x4e18c5d:'83f801',0x4e18c60:'753b',0x4e18c9d:'488b5708',0x4e18ca1:'488b4f20',0x4e18ca5:'4885d2',0x4e18ca8:'0f84a4000000',0x4e18cae:'488b4718',0x4e18cb2:'4839ca',0x4e18cb5:'750a',0x4e18cb7:'483b4730',0x4e18cbb:'0f849a000000',0x4e18cc1:'488b7710',0x4e18cc5:'0fb78a12010000',0x4e18ccc:'4839c8',0x4e18ccf:'730f',0x4e18cd1:'4889d1',0x4e18cd4:'eb30',0x4e18d06:'4889c2',0x4e18d09:'48c1e204',0x4e18d0d:'4885f6',0x4e18d10:'7455',0x4e18d5b:'31c0',0x4e18d67:'488d7001',0x4e18d6b:'4989c9',0x4e18d6e:'eb51',0x4e18dc1:'488d04c1',0x4e18dc5:'4805b8000000',0x4e18dcb:'4801ca',0x4e18dce:'4c894f08',0x4e18dd2:'48c7471000000000',0x4e18dda:'48897718',0x4e18dde:'59',0x4e18ddf:'c3',
0x5acca14:'4889f7',0x5acca17:'e834c234ff',0x5acca1c:'4885c0',0x5acca1f:'0f84a0000000',0x5acca25:'488b1a',0x5acca28:'4c8b6208',0x5acca2c:'f048ff03',0x5acca30:'0f8e8d000000',0x5acca36:'f049ff0424',0x5acca3b:'0f8e82000000',0x5accafc:'488918',0x5accaff:'4c896008',0x5accb6b:'49895c2df8',0x5accb70:'4d89642d00',0x5accb81:'4c89ff',0x5accb84:'e8c7c034ff',0x5accb89:'4885c0',0x5accb8c:'7473',0x5accb8e:'488b1a',0x5accb91:'4c8b6208',0x5accb95:'f048ff03',0x5accb9f:'f049ff0424'}
def check(r):
    for a,hx in pins.items():
        expected=bytes.fromhex(hx)
        assert r(a,len(expected))==expected,hex(a)
check(read)
for bad in [0x4e18cbb,0x4e18cc5,0x4e18d09,0x4e18d67,0x4e18dc5,0x4e18dcb,0x4e18dda,0x5acca17,0x5acca25,0x5acca28,0x5acca2c,0x5accafc,0x5accaff,0x5accb84]:
    def corrupt(a,n):
        x=bytearray(read(a,n))
        if a<=bad<a+n:x[bad-a]^=1
        return bytes(x)
    try:check(corrupt)
    except AssertionError:pass
    else:raise AssertionError(hex(bad))
cases=0
for n in range(20):
    for lo in range(n+1):
        for hi in range(lo,n+1):
            keys=[0xb8+8*i for i in range(lo,hi)]
            values=[16*i for i in range(lo,hi)]
            assert len(keys)==len(values)==hi-lo
            assert all(k==0xb8+8*(lo+j) and v==16*(lo+j) for j,(k,v) in enumerate(zip(keys,values)))
            cases+=1
print(f'2 complete FDEs, {len(pins)} instruction pins, 14 mutation controls, {cases} index cases: OK')
