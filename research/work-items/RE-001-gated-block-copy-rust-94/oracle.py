#!/usr/bin/env python3
"""Independent immutable-image selection and pointwise-copy oracle; no instruction model."""
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
MOD=2**64
TARGET='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
def sha(raw):return hashlib.sha256(raw).hexdigest()

def relation(d,s,p,b,f,m):
    n=len(m)
    def available(start,size):return 0<=start and start+size<=n
    if f==0:
        a=344;category='flag_fallback'
    else:
        if not available(p+20,4):return 'E',m,'index_refusal'
        bits=sum(m[p+20+j]*256**j for j in range(4))
        residue=(bits-1)%(2**32)
        signed=residue if residue<2**31 else residue-2**32
        if signed>b:
            a=344;category='bound_fallback'
        else:
            if not available(s+416,1):return 'E',m,'gate_refusal'
            a=392 if m[s+416] else 344
            category='preferred' if a==392 else 'gate_fallback'
    if not available(s+a,48):return 'E',m,'source_refusal'
    if not available(d,48):return 'E',m,'destination_refusal'
    final=bytes(m[s+a+x-d] if d<=x<d+48 else byte for x,byte in enumerate(m))
    return f'V:{d:016x}',final,category

def differences(old,new):
    return ','.join(f'{i:x}:{b:02x}' for i,(a,b) in enumerate(zip(old,new,strict=True)) if a!=b) or '-'

def cases():
    serial=0
    rng=random.Random(0x4ff8b30)
    def make(d,s,p,b,f,index,gate,n,seed=None):
        nonlocal serial
        serial+=1
        if seed is None:seed=serial
        # All byte values, unaligned positions and separate chunk identities.
        m=bytearray((x*71+(x//16)*17+seed)%256 for x in range(n))
        for j,v in enumerate((index%(2**32)).to_bytes(4,'little')):
            if p+20+j<n:m[p+20+j]=v
        if s+416<n:m[s+416]=gate
        return f'case-{serial:05d}',d,s,p,b,f,bytes(m)
    for f in (0,1,2,127,128,255):
        for index in (-(2**31),-(2**31)+1,-2,-1,0,1,2,2**31-1):
            t=((index-1+2**31)%(2**32))-2**31
            for b in sorted(set((-2**31,-1,0,1,2**31-1,max(-2**31,t-1),t,min(2**31-1,t+1)))):
                for g in (0,1,128,255):yield make(500,3,17,b,f,index,g,600)
    for preferred in (False,True):
        s=64;a=392 if preferred else 344
        for shift in range(-47,48):
            for seed in (0,127,255):yield make(s+a+shift,s,1,0,1,1,int(preferred),640,seed)
    # Aliased index/gate/source/destination: initialized image is authoritative.
    for s in (0,3,64):
        for p in (0,s+324,s+372,s+396,s+412):
            for d in (p,p+20,s+344,s+368,s+392,s+416,s+440):
                for b in (-2**31,0,2**31-1):yield make(d,s,p,b,255,1,255,640)
    # Exact ends and one-byte shortages. Index/gate are intentionally absent on skipped paths.
    for n in (0,20,23,24,343,344,391,392,393,415,416,417,439,440,441,500,547,548):
        for f in (0,1,255):
            for index,b in ((1,0),(0,-1),(2,0),(-2**31,0)):
                for g in (0,1):yield make(0,0,0,b,f,index,g,n)
    for offset in (MOD-1,MOD-20,MOD-344,MOD-416,2**63,601):
        for f in (0,1):
            yield make(0,0,offset,0,f,1,1,440)
            yield make(0,offset,0,0,f,1,1,440)
            yield make(offset,0,0,0,f,1,1,440)
    for byte in range(256):
        yield make(500,0,1,0,0,1,1,560,byte)
        yield make(500,0,1,0,1,1,1,560,byte)
    for _ in range(2048):
        n=rng.randrange(350,700);s=rng.randrange(80);p=rng.randrange(0,n+2);d=rng.randrange(0,n+2)
        index=rng.randrange(-2**31,2**31);b=rng.randrange(-2**31,2**31)
        yield make(d,s,p,b,rng.choice((0,1,255)),index,rng.randrange(256),n)

def render():
    inputs=[];expected=[];coverage=Counter()
    for label,d,s,p,b,f,m in cases():
        result,new,category=relation(d,s,p,b,f,m);coverage[category]+=1
        inputs.append(f'{label}\t{d:016x}\t{s:016x}\t{p:016x}\t{b}\t{f}\t{m.hex() or "-"}\n')
        expected.append(f'{label}\t{result}\t{differences(m,new)}\n')
    return ''.join(inputs).encode(),''.join(expected).encode(),dict(sorted(coverage.items()))

def check():
    frozen=json.loads((HERE/'fixtures/freeze.json').read_text())
    inputs,expected,coverage=render()
    if frozen['cases']!=len(inputs.splitlines()) or frozen['target_sha256']!=TARGET:raise ValueError('freeze identity/count')
    for name,raw in [('inputs.tsv',inputs),('expected.tsv',expected)]:
        retained=gzip.decompress((HERE/'fixtures'/(name+'.gz')).read_bytes())
        if retained!=raw or sha(raw)!=frozen['sha256'][name]:raise ValueError('frozen fixture drift: '+name)
        if sha((HERE/'fixtures'/(name+'.gz')).read_bytes())!=frozen['sha256'][name+'.gz']:raise ValueError('compressed fixture drift')
    if sha(Path(__file__).read_bytes())!=frozen['sha256']['oracle.py']:raise ValueError('oracle changed after freeze')
    if coverage!=frozen['coverage']:raise ValueError('coverage drift')
    return frozen


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--freeze',action='store_true');args=parser.parse_args()
    if args.freeze:
        if (ROOT/'src/node94-gated-block-copy').exists():raise ValueError('freeze must precede Rust')
        if (HERE/'fixtures/freeze.json').exists():raise ValueError('already frozen')
        inputs,expected,coverage=render();files={'inputs.tsv':inputs,'expected.tsv':expected}
        compressed={name+'.gz':gzip.compress(raw,compresslevel=9,mtime=0) for name,raw in files.items()}
        for name,raw in compressed.items():(HERE/'fixtures'/name).write_bytes(raw)
        files.update(compressed);files['oracle.py']=Path(__file__).read_bytes()
        frozen={'target_sha256':TARGET,'cases':len(inputs.splitlines()),'coverage':coverage,'frozen_at_utc':datetime.now(timezone.utc).isoformat(),
                'rust_source_absent':True,'sha256':{name:sha(raw) for name,raw in files.items()}}
        (HERE/'fixtures/freeze.json').write_text(json.dumps(frozen,sort_keys=True,indent=2)+'\n')
        print(json.dumps(frozen,indent=2))
    else:print('PASS frozen oracle:',check()['cases'],'cases')
