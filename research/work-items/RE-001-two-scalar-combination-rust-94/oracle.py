#!/usr/bin/env python3
"""Pre-Rust whole-integer relation with an entry-image patch between snapshots."""
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
B256=1<<256
B320=1<<320
B448=1<<448
B512=1<<512
TARGET='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
def sha(raw):return hashlib.sha256(raw).hexdigest()
def signed(v):return v if v<HALF else v-MOD

def relation(base,source,dest,x,y,image):
    end=base+len(image)
    if end>MOD:return None,image,'image-refusal'
    if not(base<=source and source+104<=end and base<=dest and dest+64<=end):
        return None,image,'range-refusal'
    s,d=source-base,dest-base
    a=int.from_bytes(image[s:s+40],'little')
    transformed=(-a if signed(x)<0 else a)%B320
    magnitude=abs(signed(x))
    product=(transformed%B256)*magnitude
    top=(product//B256-((transformed//B256)&magnitude))%MOD
    early=(product%B256).to_bytes(32,'little')
    staged=image[:d]+early+image[d+32:]
    b=int.from_bytes(staged[s+40:s+104],'little')
    result=(signed(y)*b+product%B256+signed(top)*B256)%B512
    after=staged[:d]+result.to_bytes(64,'little')+staged[d+64:]
    # Register observation: the final multiply uses signed operands only in
    # its high half; all earlier products feed one unsigned prefix carry.
    adjusted=(-b if signed(y)<0 else b)%B512
    m=abs(signed(y));last=adjusted//B448
    incoming=((adjusted%B448)*m)//B448
    tail_product=signed(last)*signed(m)
    rax=tail_product%MOD
    rdx=(tail_product//MOD+(rax+incoming)//MOD)%MOD
    kind='early-store-alias' if max(d,s+40)<min(d+32,s+104) else ('other-alias' if max(d,s)<min(d+64,s+104) else 'disjoint')
    return (rax,rdx),after,kind

def cases():
    serial=0
    scalars=(0,1,2,3,HALF-1,HALF,HALF+1,MOD-2,MOD-1)
    patterns=(bytes(104),b'\xff'*104,bytes((i*73+19)%256 for i in range(104)),b'\x00'*31+b'\x80'+b'\xff'*8+b'\x00'*63+b'\x80')
    def make(x=3,y=MOD-5,s=80,d=80,n=256,base=0x1000,payload=None,seed=19):
        nonlocal serial
        serial+=1;image=bytearray((i*37+i//8*11+seed)%256 for i in range(n))
        if payload is not None:
            for j,v in enumerate(payload):
                if 0<=s+j<n:image[s+j]=v
        return f'case-{serial:05d}',base,(base+s)%MOD,(base+d)%MOD,x,y,bytes(image)
    # All relative byte displacements of overlapping source/destination,
    # including where early stores overwrite the later 64-byte snapshot.
    for delta in range(-64,105):
        for x,y in ((3,5),(HALF,HALF),(MOD-1,HALF+1),(HALF-1,MOD-1)):
            yield make(x,y,d=80+delta,payload=patterns[2])
    for x in scalars:
        for y in scalars:
            for payload in patterns:yield make(x,y,d=184,n=256,payload=payload)
    # Every one of the 832 input bits is tested in disjoint and ordered-alias
    # layouts. Fifth-word bits are not assumed to encode a sign mask.
    for bit in range(832):
        payload=(1<<bit).to_bytes(104,'little')
        for delta in (0,40,104):
            yield make(HALF if bit%2 else MOD-1,3 if bit%3 else HALF,d=80+delta,n=256,payload=payload)
    for bit in range(64):
        for top in (1<<bit,MOD-1-(1<<bit)):
            payload=b'\xff'*32+top.to_bytes(8,'little')+patterns[2][40:]
            for x,y in ((1<<bit,MOD-1),(MOD-1-(1<<bit),HALF)):
                yield make(x,y,d=184,payload=payload)
    # Scalar bit boundaries on independently irregular full-width words.
    for bit in range(64):
        for delta in (-1,0,1):
            q=((1<<bit)+delta)%MOD
            yield make(q,MOD-1-q,d=104,payload=patterns[2])
    for n in (0,1,31,32,39,40,63,64,103,104,105,167,168,255,256):
        for s,d in ((0,0),(0,104),(64,0),(1,1),(80,80),(80,120)):
            for base in (0,MOD-n if n else MOD-1,MOD-n+1 if n else MOD-1):
                if base<MOD:yield make(HALF,HALF,s,d,n,base)
    for slot in (2,3):
        for address in (0,0xfff,1<<32,HALF,MOD-1,MOD-63,MOD-103):
            row=list(make());row[slot]=address;yield tuple(row)
    rng=random.Random(0x565e7a0)
    for _ in range(768):
        yield make(rng.getrandbits(64),rng.getrandbits(64),80,rng.randrange(16,193),256,rng.choice((0,0x1000,MOD-256)),rng.randbytes(104),rng.randrange(256))

def render():
    inputs=[];expected=[];coverage=Counter()
    for label,base,source,dest,x,y,image in cases():
        value,after,kind=relation(base,source,dest,x,y,image);coverage[kind]+=1
        if value is not None:
            coverage['x-minimum']+=x==HALF;coverage['y-minimum']+=y==HALF
        changes=','.join(f'{i:x}:{v:02x}' for i,v in enumerate(after) if v!=image[i]) or '-'
        status='E' if value is None else f'V:{value[0]:016x}:{value[1]:016x}'
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
        if (ROOT/'src/node94-two-scalar-combination').exists():raise ValueError('freeze must precede Rust')
        if (HERE/'fixtures/freeze.json').exists():raise ValueError('already frozen')
        inputs,expected,coverage=render();files={'inputs.tsv':inputs,'expected.tsv':expected}
        for name,raw in list(files.items()):
            compressed=gzip.compress(raw,compresslevel=9,mtime=0);(HERE/'fixtures'/(name+'.gz')).write_bytes(compressed);files[name+'.gz']=compressed
        files['oracle.py']=Path(__file__).read_bytes()
        frozen={'target_sha256':TARGET,'cases':len(inputs.splitlines()),'coverage':coverage,'frozen_at_utc':datetime.now(timezone.utc).isoformat(),'rust_source_absent':True,'sha256':{n:sha(v) for n,v in files.items()}}
        (HERE/'fixtures/freeze.json').write_text(json.dumps(frozen,sort_keys=True,indent=2)+'\n');print(json.dumps(frozen,indent=2))
    else:print('PASS frozen oracle:',check()['cases'],'cases')
