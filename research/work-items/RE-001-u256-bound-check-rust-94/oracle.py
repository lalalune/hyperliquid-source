#!/usr/bin/env python3
"""Pre-Rust whole-integer oracle for complete u256 comparison observations."""
import argparse
from collections import Counter
from datetime import datetime,timezone
import gzip
import hashlib
import json
from pathlib import Path
import random
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
MOD=1<<256
WORD=1<<64
BOUND=int('73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001',16)
TARGET='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
def sha(raw):return hashlib.sha256(raw).hexdigest()

def relation(mode,a,b):
    # One unbounded subtraction and quotient/remainder extraction, independent
    # of the source's four-word overflowing-subtract/borrow recurrence.
    if mode=='W':b=BOUND
    residue=(a-b)%MOD
    flags=(int(a<b and (mode=='W' or a!=0)),int(a==0) if mode=='W' else 1,(WORD-1)*int(a<b))
    return flags+tuple((residue//(WORD**i))%WORD for i in range(4))

def cases():
    edge=(0,1,2,255,256,WORD-1,WORD,WORD+1,1<<127,1<<128,1<<191,1<<192,1<<255,MOD-2,MOD-1,BOUND-1,BOUND,BOUND+1)
    for a in edge:
        yield 'W',a,0
        for b in edge:yield 'G',a,b
    for bit in range(256):
        p=1<<bit
        # Each bit reaches outputs and nonzero tests; dense neighbors force
        # borrowing across all lower words and distinguish strict equality.
        for a in (p-1,p,min(p+1,MOD-1),MOD-1-p):
            yield 'W',a,0
            for b in (0,1,p-1,p,min(p+1,MOD-1),MOD-1):yield 'G',a,b
        for delta in (-p,-1,0,1,p):yield 'W',(BOUND+delta)%MOD,0
    for limb in range(4):
        for bit in range(64):
            delta=1<<(64*limb+bit)
            for a in ((BOUND-delta)%MOD,(BOUND+delta)%MOD):yield 'W',a,0
    # The second subtraction must propagate borrow when its first operand is
    # zero, even when subtracting MAX already underflowed in another limb.
    for i in range(1,4):
        for top in (0,1,WORD-1):
            a=top*(WORD**i)
            for b in (1,(WORD-1)*(WORD**i)+1,WORD**i+1):yield 'G',a%MOD,b%MOD
    rng=random.Random(0x565dd80)
    for i in range(4096):
        a=rng.getrandbits(256);b=rng.getrandbits(256)
        yield 'G',a,b
        if i%4==0:yield 'W',a,0

def words(value):return ':'.join(f'{(value//(WORD**i))%WORD:016x}' for i in range(4))

def render():
    inputs=[];expected=[];coverage=Counter()
    for i,(mode,a,b) in enumerate(cases()):
        out=relation(mode,a,b);actual_b=BOUND if mode=='W' else b
        coverage[mode]+=1;coverage[mode+('-below' if a<actual_b else '-equal' if a==actual_b else '-above')]+=1
        if a==0:coverage[mode+'-zero']+=1
        label=f'case-{i:05d}'
        inputs.append(f'{label}\t{mode}\t{words(a)}\t{words(b) if mode=="G" else "-"}\n')
        expected.append(label+'\tV:'+':'.join(f'{v:016x}' for v in out)+'\n')
    return ''.join(inputs).encode(),''.join(expected).encode(),dict(sorted(coverage.items()))

def check():
    frozen=json.loads((HERE/'fixtures/freeze.json').read_text());inputs,expected,coverage=render()
    if frozen['cases']!=len(inputs.splitlines()) or frozen['target_sha256']!=TARGET:raise ValueError('freeze identity/count')
    for name,raw in [('inputs.tsv',inputs),('expected.tsv',expected)]:
        path=HERE/'fixtures'/(name+'.gz')
        if gzip.decompress(path.read_bytes())!=raw or sha(raw)!=frozen['sha256'][name]:raise ValueError('frozen fixture drift')
        if sha(path.read_bytes())!=frozen['sha256'][name+'.gz']:raise ValueError('compressed fixture drift')
    if sha(Path(__file__).read_bytes())!=frozen['sha256']['oracle.py']:raise ValueError('oracle changed after freeze')
    if coverage!=frozen['coverage']:raise ValueError('coverage drift')
    return frozen

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--freeze',action='store_true');args=p.parse_args()
    if args.freeze:
        if (ROOT/'src/node94-u256-bound-check').exists():raise ValueError('freeze must precede Rust')
        if (HERE/'fixtures/freeze.json').exists():raise ValueError('already frozen')
        inputs,expected,coverage=render();files={'inputs.tsv':inputs,'expected.tsv':expected}
        for name,raw in list(files.items()):
            compressed=gzip.compress(raw,compresslevel=9,mtime=0);(HERE/'fixtures'/(name+'.gz')).write_bytes(compressed);files[name+'.gz']=compressed
        files['oracle.py']=Path(__file__).read_bytes()
        frozen={'target_sha256':TARGET,'cases':len(inputs.splitlines()),'coverage':coverage,'frozen_at_utc':datetime.now(timezone.utc).isoformat(),'rust_source_absent':True,'sha256':{n:sha(v) for n,v in files.items()}}
        (HERE/'fixtures/freeze.json').write_text(json.dumps(frozen,sort_keys=True,indent=2)+'\n');print(json.dumps(frozen,indent=2))
    else:print('PASS frozen oracle:',check()['cases'],'cases')
