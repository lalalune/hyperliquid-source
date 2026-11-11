#!/usr/bin/env python3
"""Static target-bound descriptor and call-order checks."""
from hashlib import sha256
from pathlib import Path
from elf_index import unwind_index
from fde_extents import eh_frame_records
b=Path('artifacts/node/115/hl-node').read_bytes()
assert sha256(b).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
s,h=unwind_index(b);_,f=eh_frame_records(b,s);idx={(x['start'],x['fde']) for x in h}
def read(a,n):
    x=next(x for x in s if x['address']<=a and a+n<=x['address']+x['size'] and x['name'] in ('.text','.rodata'))
    p=x['offset']+a-x['address'];return b[p:p+n]
for a,z,d in [(0x4fac470,0x4fac699,'6b4154b37863f247d5dbfc7880d6b689e25e7ae40b4c468bbb9554855b8aaf17'),(0x4e40010,0x4e40219,'aea19d9224b7a80dafbc4d09c3819a5a1502db343f3b296623b5df49d484a5a3'),(0x50e9340,0x50e96f3,'66fc0bf716a2ef40bc2f9ca42c80c58fb25fdcf200a5c7517dd694f2c0e31b8d'),(0x5a2ff40,0x5a300ad,'5725dbd046e2e74168f69ece3af6b09ecce118d8d87e54b008610c02571568aa')]:
    assert any(x['start']==a and x['end']==z and (a,x['fde']) in idx for x in f)
    assert sha256(read(a,z-a)).hexdigest()==d
pins={0x4fac47a:'89f5',0x4fac48e:'f00fb04e10',0x4fac49d:'488d057dd496fb',0x4fac4a4:'4889442410',0x4fac4a9:'48c74424181b000000',0x4fac4b2:'896c2420',0x4fac4bb:'488d542410',0x4fac4c0:'e84b3be9ff',0x4fac4c9:'f00fb00b',0x4fac4d3:'4d8b36',0x4fac4e1:'f0490fb14e10',0x4fac4ed:'4d8b7e18',0x4e40021:'4989d7',0x4e40024:'4989f6',0x4e4002a:'49bc0000000000000080',0x4e4004f:'410f1007',0x4e40053:'0f118424a0000000',0x4e4005b:'498b4710',0x4e4005f:'48898424b0000000',0x4e40086:'31c0',0x4e40088:'493b4648',0x4e40091:'7124',0x4e400b7:'4d8d7e48',0x4e400be:'0f848e000000',0x4e40152:'4c893c24',0x4e4016a:'488d942490000000',0x4e40172:'4c89ff',0x4e40175:'e8c6912a00',0x50e9382:'c6005b',0x50e93a5:'e8b644eeff',0x50e93ad:'4885c0',0x50e93b0:'0f85cb000000',0x50e93ce:'c604302c',0x50e93f2:'c604305b',0x50e93fe:'4d8b6f10',0x50e9402:'498b6f18',0x50e9415:'c6043022',0x50e9424:'4c89ee',0x50e9427:'4889ea',0x50e942a:'e8e1a0fbff',0x50e9443:'c6043022',0x50e945e:'c604302c',0x50e946a:'4983c720',0x50e9471:'4c89ff',0x50e9474:'e8c76a9400',0x50e947c:'4885c0',0x50e947f:'7468',0x50e94fe:'c604305d',0x50e951e:'c604305d',0x50e9569:'0f841a010000',0x50e956f:'41c604040a',0x50e9585:'e866a23dfc'}
def check(r):
    for a,hx in pins.items():
        q=bytes.fromhex(hx);assert r(a,len(q))==q,hex(a)
    assert r(0x919921,27)==b'marking node_ip as verified'
    a=0x4fac49d;q=r(a,7);assert a+7+int.from_bytes(q[-4:],'little',signed=True)==0x919921
    for a,dst in [(0x4fac4c0,0x4e40010),(0x4e40175,0x50e9340),(0x50e93a5,0x4fcd860),(0x50e942a,0x50a3510),(0x50e9474,0x5a2ff40),(0x50e9585,0x14c37f0)]:
        q=r(a,5);assert a+5+int.from_bytes(q[1:],'little',signed=True)==dst
check(read)
for bad in [0x4fac49d,0x4fac4a9,0x4fac4b2,0x4fac4c0,0x4e40053,0x4e4005f,0x4e40091,0x4e40175,0x50e9382,0x50e93fe,0x50e942a,0x50e9474,0x50e951e,0x50e956f,0x919921]:
    def corrupt(a,n):
        q=bytearray(read(a,n))
        if a<=bad<a+n:q[bad-a]^=1
        return bytes(q)
    try:check(corrupt)
    except AssertionError:pass
    else:raise AssertionError(hex(bad))
print(f'4 FDEs, {len(pins)} instruction pins, 1 literal, 6 direct calls, 15 corruption controls: OK')
