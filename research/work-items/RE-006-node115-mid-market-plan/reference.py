#!/usr/bin/env python3
"""Synthetic exact-rational price/tick oracle; never runs captured code."""
import hashlib
import json
import random
import sys
from fractions import Fraction
from pathlib import Path

FACTORS = (0x3ff07ae147ae147b, 0x3fef0a3d70a3d70a, 0x3ff3333333333333, 0x3fe999999999999a)
MAX = (1 << 64) - 1

def rational(bits):
    exponent = ((bits >> 52) & 2047) - 1075
    mantissa = (bits & ((1 << 52) - 1)) | (1 << 52)
    return Fraction(mantissa) * Fraction(2) ** exponent

def nearest_even(n, d):
    q, r = divmod(n, d)
    return q + int(2*r > d or (2*r == d and q & 1))

def binary64(x):
    if not x: return Fraction(0)
    exponent = x.numerator.bit_length() - x.denominator.bit_length()
    if x < Fraction(2) ** exponent: exponent -= 1
    shift = 52 - exponent
    n,d = x.numerator,x.denominator
    if shift >= 0: n <<= shift
    else: d <<= -shift
    q = nearest_even(n,d)
    return Fraction(q, 1 << shift) if shift >= 0 else Fraction(q << -shift)

def reference(a,b,side,decimals,family,mutation=None):
    midpoint = (a+b)//2
    if mutation == 'wrapping-midpoint': midpoint = ((a+b)&MAX)//2
    selector = 2*family + int(side != 0)
    if mutation == 'wrong-factor': selector ^= 1
    scaled = binary64(binary64(Fraction(midpoint))*rational(FACTORS[selector]))
    whole, rem = divmod(scaled.numerator,scaled.denominator)
    price = whole + int(2*rem >= scaled.denominator)
    price = max(1,min(MAX,price))
    digits = len(str(price)); tick = min(10**max(0,digits-5), 10**(6-decimals))
    if mutation == 'wrong-tick-cap': tick = min(10**max(0,digits-5), 10**(7-decimals))
    q, rem = divmod(price,tick)
    if side != 0 and (mutation != 'sell-ceiling' or rem): q = min(MAX,q+1)
    return max(1,min(MAX,q*tick))

rng=random.Random(1153915);special=[1,2,3,9,10,99,100,999,1000,9999,10000,99999,100000,2500000,(1<<53)-1,1<<53,(1<<53)+1,MAX-1,MAX]
lines=['# bid ask side decimals family limit'];mutations={x:0 for x in ('wrapping-midpoint','wrong-factor','wrong-tick-cap','sell-ceiling')}
for index in range(6000):
    a = special[index % len(special)] if index < 3000 else rng.randrange(1,MAX+1)
    b = special[(index*7+3) % len(special)] if index < 3000 else rng.randrange(1,MAX+1)
    side = (0,1,2,255)[index%4];decimals=(index//4)%7;family=(index//28)%2
    result=reference(a,b,side,decimals,family)
    lines.append(f'{a} {b} {side} {decimals} {family} {result}')
    for name in mutations:mutations[name] += reference(a,b,side,decimals,family,name)!=result
text='\n'.join(lines)+'\n';root=Path(__file__).resolve().parents[3];fixture=root/'src/node115-mid-market-plan/tests/reference-vectors.txt'
if '--write' in sys.argv:fixture.write_text(text)
else:assert fixture.read_text()==text
assert all(mutations.values()),mutations
print(json.dumps({'cases':6000,'fixture_sha256':hashlib.sha256(text.encode()).hexdigest(),'controls_differing_cases':mutations,'method':'exact rational binary64 rounding and integer arithmetic; not target execution'},indent=2))
