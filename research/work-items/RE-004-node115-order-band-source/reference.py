#!/usr/bin/env python3
"""Synthetic Python binary64 reference, not captured execution."""
import hashlib, random, struct, sys
from pathlib import Path

root=Path(__file__).resolve().parents[3]
out=root/'src/node115-spot-price-band/tests/reference-vectors.txt'
def val(bits): return struct.unpack('>d',bits.to_bytes(8,'big'))[0]
def bits(value): return int.from_bytes(struct.pack('>d',value),'big')
def run(a,b,p):
    ratio = (float(a)/float(b) if b else (float('inf') if a else float('nan'))) - 1.0
    ok = p > abs(ratio) or (1.0 > p and ratio > 0.0 and 1.0/(1.0-p)-1.0 >= ratio)
    return (0x1a2,0) if ok else (0x63,bits(p*100.0))
r=random.Random(1154262); rows=['# a b pbits status payloadbits']; specials=[0,1,2,50,51,100,200,201,2**53-1,2**53,2**53+1,2**64-1]
ps=[0,0x8000000000000000,0x3fe0000000000000,0x3ff0000000000000,0x3fe999999999999a,0x7ff0000000000000,0xfff0000000000000,0x7ff8000000000000]
for i in range(10000):
    a=specials[i%len(specials)] if i%3==0 else r.getrandbits(64)
    b=specials[(i//3)%len(specials)] if i%4==0 else r.getrandbits(64)
    pb=ps[i%len(ps)] if i%2==0 else r.getrandbits(64)
    p=val(pb); st,payload=run(a,b,p)
    rows.append(f'{a} {b} {pb:016x} {st:x} {payload:016x}')
data=('\n'.join(rows)+'\n').encode()
if '--write' in sys.argv: out.write_bytes(data)
else:
    assert out.read_bytes()==data
    print('10000 Python binary64 cases; sha256',hashlib.sha256(data).hexdigest())
