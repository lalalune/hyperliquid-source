#!/usr/bin/env python3
"""Pre-Rust signed whole-integer relation, zero correction and staged image."""
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
HALF=MOD//2
L=1<<256
WIDE=1<<320
SIGN=1<<319
TARGET='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
def sha(raw):return hashlib.sha256(raw).hexdigest()
def signed(v):return v if v<HALF else v-MOD

def relation(base,source,dest,x,y,image):
    end=base+len(image)
    if end>MOD:return None,image,'image-refusal',{}
    if not(base<=source and source+64<=end and base<=dest and dest+32<=end):
        return None,image,'range-refusal',{}
    s,d=source-base,dest-base
    early=x.to_bytes(8,'little')+y.to_bytes(8,'little')
    staged=image[:d]+early+image[d+16:]
    a=int.from_bytes(staged[s:s+32],'little');b=int.from_bytes(staged[s+32:s+64],'little')
    sx,sy=signed(x),signed(y)
    # The native four-word negation drops its carry. For a zero operand and
    # negative scalar this leaves the separate -magnitude*2^256 correction.
    missing_x=abs(sx)*L if sx<0 and a==0 else 0
    missing_y=abs(sy)*L if sy<0 and b==0 else 0
    total=sx*a+sy*b-missing_x-missing_y
    residue=total%WIDE
    signed_total=residue if residue<SIGN else residue-WIDE
    quotient=signed_total//(1<<31)
    output=(abs(quotient)%L).to_bytes(32,'little')
    negative=signed_total<0
    registers=(int(negative),(-x if negative else x)%MOD,(-y if negative else y)%MOD)
    after=staged[:d]+output+staged[d+32:]
    kind='early-store-alias' if max(d,s)<min(d+16,s+64) else ('other-alias' if max(d,s)<min(d+32,s+64) else 'disjoint')
    metrics={'negative-zero-x':bool(missing_x),'negative-zero-y':bool(missing_y),'sum-outside-signed320':not(-SIGN<=total<SIGN),'negative-sum':negative,'x-minimum':x==HALF,'y-minimum':y==HALF,'negative-with-zero-output':negative and output==bytes(32)}
    return registers,after,kind,metrics

def cases():
    serial=0
    scalars=(0,1,2,HALF-1,HALF,HALF+1,MOD-2,MOD-1,1<<31,MOD-(1<<31))
    patterns=(bytes(64),b'\xff'*64,bytes((i*73+19)%256 for i in range(64)),(1).to_bytes(64,'little'),(1<<256).to_bytes(64,'little'),((1<<255)|(1<<511)).to_bytes(64,'little'))
    def make(x=3,y=MOD-5,s=64,d=128,n=192,base=0x1000,payload=None,seed=19):
        nonlocal serial
        serial+=1;image=bytearray((i*37+i//8*11+seed)%256 for i in range(n))
        if payload is not None:
            for j,v in enumerate(payload):
                if 0<=s+j<n:image[s+j]=v
        return f'case-{serial:05d}',base,(base+s)%MOD,(base+d)%MOD,x,y,bytes(image)
    for delta in range(-32,65):
        for x,y in ((3,5),(MOD-1,2),(2,MOD-1),(HALF,HALF),(HALF-1,HALF-1),(0,MOD-1)):
            yield make(x,y,d=64+delta,payload=patterns[2])
    for x in scalars:
        for y in scalars:
            for payload in patterns:yield make(x,y,payload=payload)
    for bit in range(512):
        payload=(1<<bit).to_bytes(64,'little')
        for delta in (0,24,64):
            yield make(HALF if bit%2 else MOD-1,3 if bit%3 else HALF,d=64+delta,payload=payload)
    for bit in range(64):
        q=1<<bit
        for payload in (patterns[0],patterns[3],patterns[1]):
            for x,y in ((q,0),((-q)%MOD,0),(q,q),(q,(-q)%MOD)):
                yield make(x,y,payload=payload)
    for bit in (0,1,30,31,32,62,63,64,94,95,96,127,128,159,191,223,255):
        for delta in (-1,0,1):
            a=((1<<bit)+delta)%L
            for x in (1,MOD-1):yield make(x,0,payload=a.to_bytes(32,'little')+bytes(32))
    for n in (0,1,15,16,31,32,33,63,64,65,95,96,127,128,191,192):
        for s,d in ((0,0),(0,64),(32,0),(1,1),(64,64),(64,96)):
            for base in (0,MOD-n if n else MOD-1,MOD-n+1 if n else MOD-1):
                if base<MOD:yield make(HALF,HALF,s,d,n,base)
    for slot in (2,3):
        for address in (0,0xfff,1<<32,HALF,MOD-1,MOD-31,MOD-63):
            row=list(make());row[slot]=address;yield tuple(row)
    rng=random.Random(0x565eaa0)
    for _ in range(768):
        yield make(rng.getrandbits(64),rng.getrandbits(64),64,rng.randrange(32,161),192,rng.choice((0,0x1000,MOD-192)),rng.randbytes(64),rng.randrange(256))

def render():
    inputs=[];expected=[];coverage=Counter()
    for label,base,source,dest,x,y,image in cases():
        value,after,kind,metrics=relation(base,source,dest,x,y,image);coverage[kind]+=1
        coverage.update({k:int(v) for k,v in metrics.items()})
        changes=','.join(f'{i:x}:{v:02x}' for i,v in enumerate(after) if v!=image[i]) or '-'
        status='E' if value is None else f'V:{value[0]:016x}:{value[1]:016x}:{value[2]:016x}'
        inputs.append(f'{label}\t{base:016x}\t{source:016x}\t{dest:016x}\t{x:016x}\t{y:016x}\t{image.hex() or "-"}\n')
        expected.append(f'{label}\t{status}\t{changes}\n')
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
        if (ROOT/'src/node94-scalar-normalization').exists():raise ValueError('freeze must precede Rust')
        if (HERE/'fixtures/freeze.json').exists():raise ValueError('already frozen')
        inputs,expected,coverage=render();files={'inputs.tsv':inputs,'expected.tsv':expected}
        for name,raw in list(files.items()):
            compressed=gzip.compress(raw,compresslevel=9,mtime=0);(HERE/'fixtures'/(name+'.gz')).write_bytes(compressed);files[name+'.gz']=compressed
        files['oracle.py']=Path(__file__).read_bytes()
        frozen={'target_sha256':TARGET,'cases':len(inputs.splitlines()),'coverage':coverage,'frozen_at_utc':datetime.now(timezone.utc).isoformat(),'rust_source_absent':True,'sha256':{n:sha(v) for n,v in files.items()}}
        (HERE/'fixtures/freeze.json').write_text(json.dumps(frozen,sort_keys=True,indent=2)+'\n');print(json.dumps(frozen,indent=2))
    else:print('PASS frozen oracle:',check()['cases'],'cases')
