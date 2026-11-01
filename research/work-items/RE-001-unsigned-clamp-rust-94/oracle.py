#!/usr/bin/env python3
"""Pre-Rust clamp relation via unbounded absolute-value formulas and availability."""
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
MOD=1<<64
TARGET='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
def sha(raw):return hashlib.sha256(raw).hexdigest()

def relation(tag,first,second,cap):
    # Availability is part of the projection's domain, not a simulated fault.
    if cap is None:return None,'missing-cap'
    if tag==0:
        if second is None:return None,'missing-zero-field'
        candidate=second;kind='tag-zero'
    elif tag%(1<<32)==1:
        if first is None or second is None:return None,'missing-difference-field'
        difference=first-second
        candidate=(difference+abs(difference))//2
        kind='low32-one'
    else:
        candidate=0;kind='other-tag'
    value=(candidate+cap-abs(candidate-cap))//2
    return (value,cap),kind

def cases():
    serial=0
    def make(tag,x,y,c):
        nonlocal serial
        serial+=1;return f'case-{serial:05d}',tag,x,y,c
    edges=(0,1,2,255,256,(1<<31)-1,1<<31,(1<<32)-1,1<<32,(1<<63)-1,1<<63,(1<<63)+1,MOD-2,MOD-1)
    for tag in (0,1,(1<<32)+1,1<<32,2,MOD-1):
        for x in edges:
            for y in edges:
                for c in edges:yield make(tag,x,y,c)
    # Every bit boundary of the difference and cap, including high-word
    # values and both subtraction orders, independently of bit-width flags.
    for bit in range(64):
        v=1<<bit
        for x,y in ((0,v),(v,0),(v,v),(v,v-1),(v-1,v),(MOD-1,v),(v,MOD-1),(MOD-1,MOD-1)):
            for c in (0,1,v-1,v,MOD-1):
                for tag in (0,1,(1<<63)+1,1<<63):yield make(tag,x,y,c)
    # All availability masks: no eagerly demanded unused field and no
    # successful other-tag result with the mandatory cap absent.
    for tag in (0,1,2,3,1<<32,(1<<32)+1,(1<<32)+2,1<<63,(1<<63)+1,MOD-1):
        for mask in range(8):
            for x,y,c in ((0,0,0),(10,4,8),(4,10,8),(MOD-1,1,MOD-1),(1,MOD-1,MOD-1),(MOD-1,MOD-2,MOD-2)):
                yield make(tag,x if mask&1 else None,y if mask&2 else None,c if mask&4 else None)
    for bit in range(32,64):
        for low in (0,1,2,(1<<32)-1):
            for x,y,c in ((9,2,100),(2,9,100),(MOD-1,1,MOD-1),(0,MOD-1,MOD-1),(0,0,0)):
                yield make((1<<bit)+low,x,y,c)
    rng=random.Random(0x15e4f70)
    for _ in range(3072):
        tag=rng.choice((0,1,rng.getrandbits(32)*(1<<32)+1,rng.getrandbits(64)))
        fields=[rng.getrandbits(64) if rng.randrange(8) else None for _ in range(3)]
        yield make(tag,*fields)

def render():
    inputs=[];expected=[];coverage=Counter()
    for label,tag,first,second,cap in cases():
        value,kind=relation(tag,first,second,cap);coverage[kind]+=1
        encoded=['-' if v is None else f'{v:016x}' for v in (tag,first,second,cap)]
        status='E' if value is None else f'V:{value[0]:016x}:{value[1]:016x}'
        inputs.append(label+'\t'+'\t'.join(encoded)+'\n');expected.append(label+'\t'+status+'\n')
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
        if (ROOT/'src/node94-unsigned-clamp').exists():raise ValueError('freeze must precede Rust')
        if (HERE/'fixtures/freeze.json').exists():raise ValueError('already frozen')
        inputs,expected,coverage=render();files={'inputs.tsv':inputs,'expected.tsv':expected}
        for name,raw in list(files.items()):
            compressed=gzip.compress(raw,compresslevel=9,mtime=0);(HERE/'fixtures'/(name+'.gz')).write_bytes(compressed);files[name+'.gz']=compressed
        files['oracle.py']=Path(__file__).read_bytes()
        frozen={'target_sha256':TARGET,'cases':len(inputs.splitlines()),'coverage':coverage,'frozen_at_utc':datetime.now(timezone.utc).isoformat(),'rust_source_absent':True,'sha256':{n:sha(v) for n,v in files.items()}}
        (HERE/'fixtures/freeze.json').write_text(json.dumps(frozen,sort_keys=True,indent=2)+'\n');print(json.dumps(frozen,indent=2))
    else:print('PASS frozen oracle:',check()['cases'],'cases')
