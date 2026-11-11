#!/usr/bin/env python3
"""Independent sequential IEEE binary64 reference; never executes target code."""
from pathlib import Path
import hashlib
import json
import math
import random
import struct
import sys


def bits(x):return struct.pack('>d',x).hex()
def value(x):return struct.unpack('>d',int(x,16).to_bytes(8,'big'))[0]
def equal(a,b):return math.isnan(a) and math.isnan(b) or bits(a)==bits(b)
def minimum(a,b):return a if a<b else b
def maximum(a,b):return a if a>b else b


def calculate(samples,base,bound,mult,positive_zero=False,reverse=False,wrong_band=False,always_clip=False):
    total=0.0 if positive_zero else -0.0
    for x in samples[::-1] if reverse else samples:total=total+x
    mean=total/len(samples)
    correction=base-mean
    if always_clip or (math.isfinite(bound) and math.isfinite(correction)):
        lo,hi=minimum(bound,-bound),maximum(-bound,bound)
        correction=minimum(hi,maximum(lo,correction))
    out=(mean+correction)*mult
    if math.isfinite(out):
        limit=0.05 if wrong_band else 0.04
        out=minimum(limit,maximum(-limit,out))
    return out*0.125


def main():
    rng=random.Random(11539134316)
    special=[0.0,-0.0,0.0001,-0.0001,0.04,-0.04,1.0,-1.0,1e-300,-1e-300,1e308,-1e308,math.inf,-math.inf,math.nan]
    rows=['# present baseline_override bound_override multiplier_override default_bound baseline bound multiplier n sample_bits... result_bits_or_none']
    controls={k:0 for k in ('positive_zero','reverse','wrong_band','always_clip')}
    outcomes={'finite':0,'infinite':0,'nan':0,'none':0}
    for i in range(12000):
        present=i%31!=0
        n=(0,1,2,7,8,9,15,16,17,25)[i%10]
        flags=[bool((i>>j)&1) for j in range(3)]
        if i<6000:
            samples=[rng.choice(special) for _ in range(n)]
            default,baseline,bound,mult=[rng.choice(special) for _ in range(4)]
        else:
            samples=[rng.uniform(-0.3,0.3) for _ in range(n)]
            default,baseline,bound,mult=(rng.uniform(-.1,.1),rng.uniform(-.1,.1),rng.uniform(-.1,.1),rng.uniform(-5,5))
        # Deliberate signed-zero and cancellation-order cases cannot be found
        # reliably by uniform random values.
        if i%101==0:
            present=True;n=1;samples=[-0.0];flags=[True,True,False]
            baseline,bound=-1.0,0.0
        elif i%103==0:
            present=True;n=3;samples=[1e16,-1e16,1.0];flags=[True,True,True]
            baseline,bound,mult=0.0,0.0,0.001
        active_base=baseline if flags[0] else .0001
        active_bound=bound if flags[1] else default
        active_mult=mult if flags[2] else 1.0
        if present and n:
            result=calculate(samples,active_base,active_bound,active_mult)
            out=bits(result)
            outcomes['nan' if math.isnan(result) else 'infinite' if math.isinf(result) else 'finite']+=1
            for control in controls:
                controls[control]+=not equal(result,calculate(samples,active_base,active_bound,active_mult,**{control:True}))
        else:
            out='none';outcomes['none']+=1
        row=[int(present),*map(int,flags),*map(bits,[default,baseline,bound,mult]),n,*map(bits,samples),out]
        rows.append(' '.join(map(str,row)))
    data=('\n'.join(rows)+'\n').encode()
    path=Path(__file__).resolve().parents[3]/'src/node115-funding-rate/tests/reference-vectors.txt'
    if '--write' in sys.argv:path.write_bytes(data)
    else:assert path.read_bytes()==data
    assert all(controls.values()),controls
    print(json.dumps({'cases':12000,'outcomes':outcomes,'controls_differing':controls,'sha256':hashlib.sha256(data).hexdigest(),'method':'Synthetic ordered Python binary64 operations; NaN classification only, no native execution'},indent=2))

if __name__=='__main__':main()
