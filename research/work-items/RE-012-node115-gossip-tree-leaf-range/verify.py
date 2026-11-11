#!/usr/bin/env python3
"""Static pins and arithmetic checks; never run captured machine code."""
from bisect import bisect_left, bisect_right
from hashlib import sha256
from pathlib import Path
from elf_index import unwind_index
from fde_extents import eh_frame_records

b = Path('artifacts/node/115/hl-node').read_bytes()
assert sha256(b).hexdigest() == 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
s, h = unwind_index(b)
_, fdes = eh_frame_records(b, s)
idx = {(x['start'], x['fde']) for x in h}
def read(a, n):
    sec = next(x for x in s if x['address'] <= a and a + n <= x['address'] + x['size'] and x['name'] in ('.text', '.rodata'))
    p = sec['offset'] + a - sec['address']
    return b[p:p+n]
for a, z, digest in [(0x4dce320,0x4dce480,'7efde4e09efe7d39c34fbf61836b5310290659a24082d5e2928b477ae24c0855'), (0x4d39ef0,0x4d3a43c,'c46eb4e03fb37d3413fc270b4a75e9b521f4a1fa45fd03b51287095f6a3e7175')]:
    assert any(x['start'] == a and x['end'] == z and (a, x['fde']) in idx for x in fdes)
    assert sha256(read(a,z-a)).hexdigest() == digest
pins = {
0x4dce331:'488b02',0x4dce334:'483b4208',0x4dce338:'7619',0x4dce35c:'48f7d8',0x4dce35f:'7135',0x4dce361:'498b7608',0x4dce365:'4885f6',0x4dce368:'745d',0x4dce36a:'488d7b08',0x4dce36e:'498b4610',0x4dce372:'488b4a10',0x4dce37b:'0f1002',0x4dce382:'4889e1',0x4dce385:'4889c2',0x4dce388:'e863bbf6ff',0x4dce38d:'48c70302000000',
0x4d39efb:'488b01',0x4d39efe:'483b4108',0x4d39f02:'7723',0x4d39f08:'488d4108',0x4d39f0c:'440fb64110',0x4d39f11:'4531c9',0x4d39f17:'488d1d2691bdfb',0x4d39f40:'4c8b31',0x4d39f43:'440fb79612010000',0x4d39f52:'49c7c3ffffffff',0x4d39f63:'0f84f7000000',0x4d39f69:'4e3bb4dec0000000',0x4d39f71:'400f97c5',0x4d39f75:'4080dd00',0x4d39f79:'49ffc3',0x4d39f80:'4080fd01',0x4d39f84:'74da',0x4d39f8c:'751a',0x4d39f94:'488d3db990bdfb',0x4d39fa2:'4d89da',0x4d39fab:'488d3da290bdfb',0x4d39fb9:'4d89da',0x4d3a060:'488d3ded8fbdfb',0x4d3a06e:'4d89d3',
0x4d3a074:'4c8b38',0x4d3a077:'440fb79e12010000',0x4d3a087:'4a8d3cd500000000',0x4d3a08f:'4929fc',0x4d3a095:'4d89d6',0x4d3a0a3:'0f84c1000000',0x4d3a0a9:'4e3bbcf6b8000000',0x4d3a0b1:'400f97c5',0x4d3a0b5:'4080dd00',0x4d3a0b9:'49ffc6',0x4d3a0c0:'4080fd01',0x4d3a0c4:'74da',0x4d3a0cc:'0f858f000000',0x4d3a0d8:'4d89f3',0x4d3a0db:'4d39da',0x4d3a0de:'0f838b000000',0x4d3a161:'49ffce',0x4d3a167:'4d89f3',0x4d3a16a:'4d39da',0x4d3a16d:'7222',0x4d3a16f:'4883ea01',0x4d3a173:'7243',0x4d3a191:'4889f3',0x4d3a194:'4885d2',0x4d3a197:'7434',0x4d3a1bc:'48c70000000000',0x4d3a1c3:'48c7401800000000',0x4d3a1d1:'488930',0x4d3a1d4:'48c7400800000000',0x4d3a1dc:'4c895010',0x4d3a1e0:'48895818',0x4d3a1e4:'48c7402000000000',0x4d3a1ec:'4c895828'}
def check(read_fn):
    for a, hx in pins.items(): assert read_fn(a, len(bytes.fromhex(hx))) == bytes.fromhex(hx), hex(a)
    for table, entry, target in [(0x913044,0,0x4d39f40),(0x913054,0,0x4d3a074)]:
        assert table + int.from_bytes(read_fn(table+4*entry,4),'little',signed=True) == target
check(read)
for bad in (0x4dce35f,0x4dce388,0x4d39f69,0x4d39f84,0x4d3a0a9,0x4d3a0c4,0x4d3a173,0x4d3a1dc,0x4d3a1ec,0x913044,0x913054):
    def mutate(a,n):
        raw = bytearray(read(a,n))
        if a <= bad < a+n: raw[bad-a] ^= 1
        return bytes(raw)
    try: check(mutate)
    except AssertionError: pass
    else: raise AssertionError(f'undetected corruption at {bad:#x}')

def scan(keys, a, b):
    lo = 0
    while lo < len(keys) and a > keys[lo]: lo += 1
    hi = lo
    while hi < len(keys) and b > keys[hi]: hi += 1
    if hi < len(keys) and b == keys[hi]: hi += 1
    return lo, hi
from itertools import combinations
values = (0, 1, 2, 250, 251, 2**63, 2**64-1)
cases = 0
for count in range(5):
    for keys in combinations(values, count):
        for a in values:
            for end in values:
                if a <= end:
                    assert scan(keys,a,end) == (bisect_left(keys,a), bisect_right(keys,end))
                    cases += 1
print(f'2 complete FDEs, {len(pins)} instruction pins, 2 jump entries, 11 corruption controls, {cases} arithmetic cases: OK')
