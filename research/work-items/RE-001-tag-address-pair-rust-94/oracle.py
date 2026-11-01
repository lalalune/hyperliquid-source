#!/usr/bin/env python3
"""Pre-Rust interval-rank oracle; unbounded integer address arithmetic."""
import argparse
from bisect import bisect_right
from collections import Counter
from datetime import datetime,timezone
import gzip
import hashlib
import json
from pathlib import Path
import random
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
MOD=1<<64
HALF=MOD//2
TARGET='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
def sha(raw):return hashlib.sha256(raw).hexdigest()

def relation(obj,tag,bias):
    # Disjoint interval rank, with a table of mathematical output pairs.
    # No NEG, flags, native branch interpretation or fixed-width arithmetic.
    rank=bisect_right((HALF,HALF+1,HALF+2),tag)
    pairs=((obj,(bias+0x5676c20)%MOD),((obj+8)%MOD,(bias+0x5676ba8)%MOD),(0,HALF+1),(0,HALF+2))
    return pairs[rank],('below-half','equal-half','half-plus-one','upper-tail')[rank]

def cases():
    tags=(0,1,2,255,256,0xffffffff,1<<32,HALF-2,HALF-1,HALF,HALF+1,HALF+2,HALF+3,MOD-1)
    objects=(0,1,7,8,0xffffffff,1<<32,HALF-1,HALF,MOD-9,MOD-8,MOD-7,MOD-2,MOD-1)
    biases=(0,1,1<<32,HALF,MOD-1,MOD-0x5676ba8-1,MOD-0x5676ba8,MOD-0x5676ba8+1,MOD-0x5676c20-1,MOD-0x5676c20,MOD-0x5676c20+1)
    for t in tags:
        for o in objects:
            for b in biases:yield o,t,b
    # Every tag bit and its two neighbors, both below and above bit 63.
    for bit in range(64):
        for t in sorted({(v+d)%MOD for v in (1<<bit,HALF|(1<<bit),MOD-1-(1<<bit)) for d in (-1,0,1)}):
            for o,b in ((0,0),(MOD-1,HALF),(HALF+3,MOD-0x5676ba8),(1<<32,MOD-0x5676c20)):
                yield o,t,b
    # Dense boundary bands distinguish low-byte/word casts and off-by-one gates.
    for d in range(-512,513):
        for t in ((HALF+d)%MOD,d%MOD):
            yield (MOD-8+d)%MOD,t,(MOD-0x5676ba8+d)%MOD
    # Each bit in object and bias is observed on both address-producing paths.
    for bit in range(64):
        for t in (0,HALF):
            yield 1<<bit,t,1<<bit
            yield MOD-1-(1<<bit),t,MOD-1-(1<<bit)
    rng=random.Random(0x15d65b0)
    for _ in range(4096):
        yield rng.getrandbits(64),rng.choice((HALF,HALF+1,rng.getrandbits(64))),rng.getrandbits(64)

def render():
    inputs=[];expected=[];coverage=Counter()
    for i,(obj,tag,bias) in enumerate(cases()):
        (rax,rdx),kind=relation(obj,tag,bias);coverage[kind]+=1
        if tag==HALF and obj+8>=MOD:coverage['object-add-wrap']+=1
        if tag<HALF+1 and bias+(0x5676ba8 if tag==HALF else 0x5676c20)>=MOD:coverage['slot-address-wrap']+=1
        label=f'case-{i:05d}'
        inputs.append(f'{label}\t{obj:016x}\t{tag:016x}\t{bias:016x}\n')
        expected.append(f'{label}\tV:{rax:016x}:{rdx:016x}\n')
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
        if (ROOT/'src/node94-tag-address-pair').exists():raise ValueError('freeze must precede Rust')
        if (HERE/'fixtures/freeze.json').exists():raise ValueError('already frozen')
        inputs,expected,coverage=render();files={'inputs.tsv':inputs,'expected.tsv':expected}
        for name,raw in list(files.items()):
            compressed=gzip.compress(raw,compresslevel=9,mtime=0);(HERE/'fixtures'/(name+'.gz')).write_bytes(compressed);files[name+'.gz']=compressed
        files['oracle.py']=Path(__file__).read_bytes()
        frozen={'target_sha256':TARGET,'cases':len(inputs.splitlines()),'coverage':coverage,'frozen_at_utc':datetime.now(timezone.utc).isoformat(),'rust_source_absent':True,'sha256':{n:sha(v) for n,v in files.items()}}
        (HERE/'fixtures/freeze.json').write_text(json.dumps(frozen,sort_keys=True,indent=2)+'\n');print(json.dumps(frozen,indent=2))
    else:print('PASS frozen oracle:',check()['cases'],'cases')
