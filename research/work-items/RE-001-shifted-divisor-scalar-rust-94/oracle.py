#!/usr/bin/env python3
"""Monotone weighted-cost inversion, not a subtraction/restore loop emulator."""
import argparse
import hashlib
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
SHA='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
R=2**64
M=R-1
U=2**128-1


def cost(q,threshold):
    return sum(((q >> (64-k)) & 1) * (threshold >> k) for k in range(1,65))


def value(n,threshold):
    # 0 is feasible; monotonicity permits binary search for the largest
    # feasible q even when zero weights give a flat cost suffix.
    lo,hi=0,M
    while lo<hi:
        middle=(lo+hi+1)//2
        if cost(middle,threshold)<=n: lo=middle
        else: hi=middle-1
    return lo


def fixtures():
    hand=[('zero-zero',0,0,M),('zero-one',0,1,M),('zero-two',0,2,2**63-1),
          ('zero-three',0,3,2**63-1),('one-three',1,3,M),
          ('aligned-zero',0,R,0),('aligned-one',1,R,1),
          ('aligned-max-unsaturated',M,R,M),('aligned-first-bit',R,R,M),
          ('aligned-three',4,3*R,1),('last-bit',2**63,2**127,1)]
    for label,n,d,expected in hand:
        if value(n,d)!=expected: raise ValueError(f'hand calculation: {label}')
        yield 'hand-'+label,n,d
    for bit in range(128):
        d=2**bit
        for j,n in enumerate((0,d-1,d,min(U,d+1),U)):
            yield f'power-{bit}-{j}',n,d
    thresholds={0,1,2,3,M,R,R+1,U,0xac45a4010001a402*R+2**32,0xd201000000010000*R}
    for bit in (1,2,31,32,33,63,64,65,95,96,97,126,127):
        thresholds.update((2**bit-1,2**bit,2**bit+1))
    for i,d in enumerate(sorted(thresholds)):
        for j,q in enumerate((0,1,2**31-1,2**32,2**63,M-1,M)):
            boundary=cost(q,d)
            for k,n in enumerate((max(0,boundary-1),boundary,min(U,boundary+1))):
                yield f'cost-boundary-{i}-{j}-{k}',n,d
        for j,n in enumerate((max(0,d-1),d,min(U,d+1))):
            yield f'saturation-boundary-{i}-{j}',n,d
    for i in range(512):
        raw=hashlib.sha256(f'shifted-scalar-v1:{i}'.encode()).digest()
        n=int.from_bytes(raw[:16],'little');d=int.from_bytes(raw[16:],'little')
        yield f'varied-{i}',n,d
        yield f'varied-bounded-{i}',n%(d+1),d


def generate():
    inputs=[];expected=[];counts={'first_bit_saturated':0,'first_bit_clear':0,'threshold_low_nonzero':0}
    for label,n,d in fixtures():
        inputs.append(f'{label}\t{n:032x}\t{d:032x}\n')
        expected.append(f'{label}\t{value(n,d):016x}\n')
        counts['first_bit_saturated' if n>=d else 'first_bit_clear']+=1
        counts['threshold_low_nonzero']+=int(bool(d&M))
    files={'inputs.tsv':''.join(inputs).encode(),'expected.tsv':''.join(expected).encode()}
    freeze={'target_sha256':SHA,'window':['0x565ede0','0x565ee3d'],'cases':len(inputs),'counts':counts,
            'method':'binary search of whole-integer weighted cost; no instruction evaluation or native target execution',
            'oracle_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'sha256':{k:hashlib.sha256(v).hexdigest() for k,v in files.items()}}
    files['freeze.json']=(json.dumps(freeze,sort_keys=True,indent=2)+'\n').encode()
    return files


def check():
    files=generate()
    for name,raw in files.items():
        if (HERE/'fixtures'/name).read_bytes()!=raw: raise ValueError(f'fixture drift: {name}')
    return json.loads(files['freeze.json'])


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path);args=p.parse_args()
    if args.out:
        args.out.mkdir(parents=True,exist_ok=False)
        for name,raw in generate().items(): (args.out/name).write_bytes(raw)
    else: print(json.dumps(check(),indent=2,sort_keys=True))
