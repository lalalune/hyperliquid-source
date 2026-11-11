#!/usr/bin/env python3
"""Rational binary64/FMA reference for the selected TWAP sizing contract."""
from fractions import Fraction as F
from pathlib import Path
import hashlib
import json
import math
import random
import struct
import sys

MAX = (1 << 64) - 1


def bits(x):
    return struct.pack('>d',x).hex()


def rounded(x):
    if x == 0:
        return F(0)
    sign = -1 if x < 0 else 1
    x = abs(x)
    e = x.numerator.bit_length() - x.denominator.bit_length()
    if x < F(2)**e:
        e -= 1
    shift = 52-e
    n,d = x.numerator,x.denominator
    if shift >= 0:
        n <<= shift
    else:
        d <<= -shift
    q,r = divmod(n,d)
    q += int(2*r>d or (2*r==d and q&1))
    return sign * (F(q,1<<shift) if shift>=0 else F(q<<-shift))


def unsigned(x):
    return min(MAX,max(0,x.numerator//x.denominator))


def model(total,filled,index,duration,jitter,price,ms,unfused=False,ceil_target=False,always_round=False):
    # Finite duration division cannot overflow; tiny values have quotient zero.
    divided = duration/60
    chunks = min(MAX,max(0,int(divided))) if math.isfinite(divided) else 0
    count = min(MAX,2*chunks+1)
    avg = rounded(rounded(F(total))/rounded(F(count)))
    if index == count:
        target = total
    else:
        i = rounded(F(index))
        if jitter:
            phase = rounded(rounded(F(ms%40,100))+F.from_float(-0.2))
            offset = rounded(phase*avg)
            value = rounded((rounded(avg*i) if unfused else avg*i)+offset)
        else:
            value = rounded(avg*i)
        target = unsigned(value)
        if ceil_target and value > 0:
            target = min(MAX,-((-value.numerator)//value.denominator))
    if target < filled:
        return count,target,0
    remaining = max(0,total-filled)
    quantity = remaining
    if remaining*price > 30_000_000:
        floor_avg = unsigned(avg)
        cap = min(MAX,3*floor_avg+1)
        minimum = (12_000_000+price-1)//price
        quantity = min(remaining,max(min(target-filled,cap),minimum))
        if (index < count or always_round) and quantity:
            step = 10**max(0,len(str(quantity))-5)
            quantity = (quantity//step)*step
    return count,target,quantity


def main():
    rng = random.Random(11539154238)
    durations = [-math.inf,-1.0,-0.0,0.0,1.0,math.nextafter(60.0,0.0),60.0,120.0,3600.0,1e8,1e20,1e308,math.inf,math.nan]
    rows = ['# total filled index duration_bits jitter price timestamp_ms count target quantity_or_zero']
    controls = {'ceil_target':0,'unfused_target':0,'round_terminal':0}
    outcomes={'some':0,'none':0}
    for i in range(12000):
        duration = durations[i%len(durations)] if i<2000 else float(rng.randrange(0,100000))
        total = (0,1,99999,100000,1000001,(1<<53)-1,(1<<53)+1,(1<<63)+3,MAX)[i%9] if i<2000 else rng.randrange(1,MAX+1)
        divided=duration/60
        count=min(MAX,2*(min(MAX,max(0,int(divided))) if math.isfinite(divided) else 0)+1)
        index = (0,1,max(0,count-1),count,min(MAX,count+1),MAX)[i%6] if i<2000 else rng.randrange(0,min(MAX,count+4)+1)
        filled = (0,total//2,total,min(MAX,total+1))[i%4] if i<2000 else rng.randrange(0,total+1)
        price = (1,2,29,30,31,12000000,30000000,MAX)[i%8] if i<2000 else rng.randrange(1,1000001)
        ms = (0,1,19,20,39,40,(1<<53)-1)[i%7] if i<2000 else rng.randrange(0,1<<53)
        high = (ms * 0x0ccccccccccccccd) >> 64
        native_phase = (ms - (((high << 2) & 0xfffffff8) * 5)) & 0xffffffff
        assert native_phase == ms % 40
        jitter=bool(i%2)
        result=model(total,filled,index,duration,jitter,price,ms)
        outcomes['some' if result[2] else 'none']+=1
        for name,kw in [('ceil_target',{'ceil_target':True}),('unfused_target',{'unfused':True}),('round_terminal',{'always_round':True})]:
            controls[name]+=model(total,filled,index,duration,jitter,price,ms,**kw)!=result
        rows.append(' '.join(map(str,[total,filled,index,bits(duration),int(jitter),price,ms,*result])))
    contents='\n'.join(rows)+'\n'
    path=Path(__file__).resolve().parents[3]/'src/node115-twap-quantity/tests/reference-vectors.txt'
    if '--write' in sys.argv:path.write_text(contents)
    else:assert path.read_text()==contents
    assert all(controls.values()),controls
    print(json.dumps({'cases':12000,'outcomes':outcomes,'controls_differing':controls,'sha256':hashlib.sha256(contents.encode()).hexdigest(),'method':'Rational arithmetic with explicit binary64 rounding; synthetic reference, no native execution'},indent=2))

if __name__=='__main__':main()
