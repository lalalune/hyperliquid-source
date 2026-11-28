#!/usr/bin/env python3
"""Digest-bound static instruction checks; no target execution or emulation."""
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
for a,z,d in [(0x2b13800,0x2b13a23,'d6bd02af3b1df380083c3b76bbff1f592a79f09bcb07a660c2d053aee7e1cb3c'),(0x2b782e0,0x2b788de,'0efc07af79d5f7edaff41580f98c7ebdbc6e7ea98bb1d8e0a294cec2fc5bb8bc'),(0x2ae0920,0x2ae135b,'c842a6d6b0c05a9b3978bcf786d556c62d71c4b055da335bf4b5617bbeb859be')]:
    assert any(x['start']==a and x['end']==z and (a,x['fde']) in idx for x in f)
    assert sha256(read(a,z-a)).hexdigest()==d
pins={0x2b138ba:'0fb6442411',0x2b138bf:'3c03',0x2b138c3:'49c70603000000',0x2b138d1:'3c02',0x2b138d3:'7507',0x2b138e8:'c744240400000000',0x2b138f0:'c744240804000000',0x2b13902:'be01000000',0x2b13907:'ba04000000',0x2b1390c:'ff15cedb9c03',0x2b13912:'83f8ff',0x2b13915:'741c',0x2b13917:'4c637c2404',0x2b1391f:'751b',0x2b13933:'ff158fc69c03',0x2b1393c:'49c1e720',0x2b13940:'4983cf02',0x2b13947:'e83474bdff',0x2b1394f:'83ffff',0x2b13952:'7406',0x2b13954:'ff151ec59c03',0x2b1395a:'41bc02000000',0x2b13968:'4d8926',0x2b1396b:'4d897e08',0x2b78642:'e8b9b1f9ff',0x2b78647:'4c8bbc24a8000000',0x2b7864f:'4983ff03',0x2b78653:'0f8492010000',0x2b78659:'4c8bac24b0000000',0x2b78694:'4183ff02',0x2b78698:'0f84cffeffff',0x2b78581:'4c896b68',0x2b78585:'0fb783c8000000',0x2b78595:'6683f802',0x2b78599:'0f8472feffff',0x2b78415:'4d85ed',0x2b7841c:'751a',0x2b7843c:'41bf02000000',0x2b78442:'e96f020000',0x2b786d3:'4183ff02',0x2b786d7:'7516',0x2b786d9:'4c89ef',0x2b786dc:'e8ef9fe8ff',0x2b786e4:'41bf02000000',0x2b786ea:'e9bf000000',0x2b787b3:'4c893f',0x2b787b6:'4c897708',0x2b787fc:'48c70003000000',0x2ae0e63:'488db388010000',0x2ae0e75:'e866740900',0x2ae0e7a:'4c8bb42450020000',0x2ae0e82:'4983fe03',0x2ae1003:'4183fe02',0x2ae1007:'7511',0x2ae1009:'498b4500',0x2ae1010:'ff10',0x2ae1012:'40b534'}
def check(r):
    for a,hx in pins.items():
        q=bytes.fromhex(hx);assert r(a,len(q))==q,hex(a)
    for a,dst in [(0x2ae0e75,0x2b782e0),(0x2b78642,0x2b13800),(0x2b786dc,0x2a026d0)]:
        q=r(a,5);assert a+5+int.from_bytes(q[1:],'little',signed=True)==dst
    for a,dst in [(0x2b1390c,0x64e14e0),(0x2b13933,0x64dffc8),(0x2b13954,0x64dfe78)]:
        q=r(a,6);assert a+6+int.from_bytes(q[2:],'little',signed=True)==dst
check(read)
for bad in [0x2b138bf,0x2b13902,0x2b13907,0x2b1390c,0x2b13915,0x2b1391f,0x2b13940,0x2b1395a,0x2b78642,0x2b78698,0x2b78599,0x2b7843c,0x2b786dc,0x2b787b3,0x2ae0e75,0x2ae1003,0x2ae1012]:
    def corrupt(a,n):
        q=bytearray(read(a,n))
        if a<=bad<a+n:q[bad-a]^=1
        return bytes(q)
    try:check(corrupt)
    except AssertionError:pass
    else:raise AssertionError(hex(bad))
print(f'3 FDEs, {len(pins)} instruction pins, 3 direct calls, 3 RIP slots, 17 byte-corruption controls: OK')
