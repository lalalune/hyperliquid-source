#!/usr/bin/env python3
"""Immutable-image polynomial addresses and last-writer byte-priority oracle."""
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

def relation(base,a,i,d,j,m):
    end=base+len(m)
    if end>MOD:return 'E',m,'image_refusal'
    def valid(address,n):return base<=address and address+n<=end and address+n<=MOD
    fields=[a+(264 if i<=31 else 272),d+(264 if j<=31 else 272)]
    if not all(valid(f,8) for f in fields):return 'E',m,'field_refusal'
    values=[int.from_bytes(m[f-base:f-base+8],'little') for f in fields]
    p=(values[0]+8*i-(0 if i<=31 else 256))%MOD
    q=(values[1]+8*j-(0 if j<=31 else 256))%MOD
    if not valid(p,8) or not valid(q,8):return 'E',m,'value_refusal'
    x=m[p-base:p-base+8];y=m[q-base:q-base+8]
    final=bytes(y[base+k-p] if p<=base+k<p+8 else x[base+k-q] if q<=base+k<q+8 else v for k,v in enumerate(m))
    category='same' if p==q else 'partial_overlap' if abs(p-q)<8 else 'disjoint'
    return f'V:{p:016x}',final,category

def differences(old,new):
    return ','.join(f'{i:x}:{b:02x}' for i,(a,b) in enumerate(zip(old,new,strict=True)) if a!=b) or '-'

def cases():
    serial=0
    def make(base,ao,i,do,j,po,qo,n,seed=None):
        nonlocal serial
        serial+=1
        if seed is None:seed=serial
        m=bytearray((k*71+k//8*19+seed)%256 for k in range(n))
        def put(off,value):
            for t,b in enumerate((value%MOD).to_bytes(8,'little')):
                if 0<=off+t<n:m[off+t]=b
        # Unselected fields intentionally retain unrelated bytes. Selected base
        # values are engineered to reach requested byte locations, with all
        # actual collisions resolved by this concrete initialized input image.
        put(ao+(264 if i<=31 else 272),base+po-8*i+(0 if i<=31 else 256))
        put(do+(264 if j<=31 else 272),base+qo-8*j+(0 if j<=31 else 256))
        return f'case-{serial:05d}',base,(base+ao)%MOD,i,(base+do)%MOD,j,bytes(m)
    indices=(0,1,30,31,32,33,63,2**32+31,2**61,2**61+31,2**61+32,2**63,MOD-1)
    for i in indices:
        for j in indices:
            for delta in range(-7,8):yield make(0x1000,0,i,32,j,500,500+delta,768)
    for i in range(66):
        for j in (0,31,32,MOD-1):yield make(0x1000,3,i,35,j,480,520,768)
    # Same table, table-field/data aliases, and every overlap byte.
    for i,j in ((0,0),(0,31),(31,32),(32,31),(32,33),(MOD-1,2**61+31)):
        for ao,do in ((0,0),(0,1),(0,8),(3,35)):
            for po in (264,265,272,273,296,304,500):
                for delta in (-7,-1,0,1,7):yield make(0x1000,ao,i,do,j,po,po+delta,768)
    for base in (0,1,MOD-768,MOD-767):
        for i,j in ((0,31),(31,32),(32,31),(MOD-1,2**61+31)):
            for delta in (-7,0,7):yield make(base,0,i,32,j,753,753+delta,768)
    # Minimal field availability, including table bases before the image.
    for n in (0,1,7,8,15,16,23,24,263,264,271,272,279,280,767,768):
        for i,j in ((0,0),(0,32),(32,0),(32,32)):
            yield make(0x1000,-264,i,-256,j,0,8,n)
            yield make(0x1000,0,i,0,j,0,8,n)
    for byte in range(256):
        yield make(0x1000,0,31,32,32,500,503,768,byte)
        yield make(0x1000,0,MOD-1,32,0,600,500,768,byte)
    for bad in (MOD-1,MOD-263,MOD-271,2**63,0):
        label,b,a,i,d,j,m=make(0x1000,0,31,32,32,500,504,768)
        yield label+'-a',b,bad,i,d,j,m
        yield label+'-d',b,a,i,bad,j,m
    rng=random.Random(0x4fa90a0)
    for _ in range(1536):
        n=rng.randrange(280,900);ao=rng.randrange(-264,48);do=rng.randrange(-264,48)
        i=rng.choice(indices+(rng.getrandbits(64),));j=rng.choice(indices+(rng.getrandbits(64),))
        po=rng.randrange(n+8);qo=rng.choice((rng.randrange(n+8),po+rng.randrange(-7,8)))
        yield make(0x1000,ao,i,do,j,po,qo,n)

def render():
    inputs=[];expected=[];coverage=Counter()
    for label,base,a,i,d,j,m in cases():
        result,new,category=relation(base,a,i,d,j,m);coverage[category]+=1
        inputs.append(f'{label}\t{base:016x}\t{a:016x}\t{i:016x}\t{d:016x}\t{j:016x}\t{m.hex() or "-"}\n')
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
        if (ROOT/'src/node94-indexed-qword-swap').exists():raise ValueError('freeze must precede Rust')
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
