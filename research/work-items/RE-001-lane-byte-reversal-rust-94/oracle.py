#!/usr/bin/env python3
"""Pre-Rust entry-image byte permutation, independent of bswap/endian operations."""
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
def relation(base,source,destination,rax,image):
    end=base+len(image)
    if end>MOD:return None,image,'image-refusal'
    if not(base<=source and source+32<=end and base<=destination and destination+32<=end):
        return None,image,'range-refusal'
    s,d=source-base,destination-base
    # A direct byte-index permutation of the ENTRY image. No native-word
    # byte swap, instruction simulation or sequential live-source reads.
    patch={d+j:image[s+(j^3)] for j in range(32)}
    after=bytes(patch.get(i,byte) for i,byte in enumerate(image))
    kind='same-range' if s==d else ('partial-overlap' if max(s,d)<min(s+32,d+32) else 'disjoint')
    return rax,after,kind

def cases():
    serial=0
    rax_values=(0,1,255,256,0xffffffff,1<<32,(1<<63)-1,1<<63,MOD-1)
    def make(s=32,d=64,n=128,base=0x1000,seed=3,payload=None,rax=None):
        nonlocal serial
        serial+=1;image=bytearray((i*43+i//4*13+seed)%256 for i in range(n))
        if payload is not None:
            for j,byte in enumerate(payload):
                if 0<=s+j<n:image[s+j]=byte
        if rax is None:rax=rax_values[serial%len(rax_values)]
        return f'case-{serial:05d}',base,(base+s)%MOD,(base+d)%MOD,rax,bytes(image)
    # All relative byte positions of overlapping regions, both directions,
    # with unaligned boundaries and distinct lane/byte patterns.
    for s in range(33):
        for d in range(33):
            for seed in (0,29,255):yield make(s,d,96,seed=seed)
    patterns=(bytes(32),b'\xff'*32,bytes(range(32)),bytes(range(31,-1,-1)),bytes([0x80,0x01,0xff,0x00])*8,bytes((i*i+17*i)%256 for i in range(32)))
    for delta in range(-40,41):
        for payload in patterns:yield make(48,48+delta,128,payload=payload)
    # Every source bit basis is witnessed with equal, partial and disjoint
    # ranges. The meaningful permutation has no 32-bit type assumption.
    for bit in range(256):
        payload=(1<<bit).to_bytes(32,'little')
        for delta in (-32,-17,-1,0,1,17,32):yield make(48,48+delta,128,payload=payload)
    for n in range(97):
        for s,d in ((0,0),(0,32),(32,0),(1,33),(33,1),(0,1),(1,0),(32,32)):
            yield make(s,d,n)
    for n in (0,1,31,32,33,63,64,65,95,96,127,128):
        for s,d in ((0,0),(0,n-32),(n-32,0),(1,n-32),(n-31,0)):
            for base in (0,MOD-n,MOD-n+1 if n else MOD-1):
                if base<MOD:yield make(s,d,n,base)
    for slot in (2,3):
        for bad in (0,0xfff,1<<32,1<<63,MOD-1,MOD-7,MOD-31):
            row=list(make());row[slot]=bad;yield tuple(row)
    rng=random.Random(0x56544a0)
    for _ in range(2048):
        n=rng.choice((96,96,128,rng.randrange(129)))
        yield make(rng.randrange(-4,101),rng.randrange(-4,101),n,rng.choice((0,0x1000,MOD-128)),rng.randrange(256),rng.randbytes(32),rng.getrandbits(64))

def render():
    inputs=[];expected=[];coverage=Counter()
    for label,base,source,destination,rax,image in cases():
        value,after,kind=relation(base,source,destination,rax,image);coverage[kind]+=1
        changes=','.join(f'{i:x}:{b:02x}' for i,b in enumerate(after) if b!=image[i]) or '-'
        status='E' if value is None else f'V:{value:016x}'
        inputs.append(f'{label}\t{base:016x}\t{source:016x}\t{destination:016x}\t{rax:016x}\t{image.hex() or "-"}\n');expected.append(f'{label}\t{status}\t{changes}\n')
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
        if (ROOT/'src/node94-lane-byte-reversal').exists():raise ValueError('freeze must precede Rust')
        if (HERE/'fixtures/freeze.json').exists():raise ValueError('already frozen')
        inputs,expected,coverage=render();files={'inputs.tsv':inputs,'expected.tsv':expected}
        for name,raw in list(files.items()):
            compressed=gzip.compress(raw,compresslevel=9,mtime=0);(HERE/'fixtures'/(name+'.gz')).write_bytes(compressed);files[name+'.gz']=compressed
        files['oracle.py']=Path(__file__).read_bytes()
        frozen={'target_sha256':TARGET,'cases':len(inputs.splitlines()),'coverage':coverage,'frozen_at_utc':datetime.now(timezone.utc).isoformat(),'rust_source_absent':True,'sha256':{n:sha(v) for n,v in files.items()}}
        (HERE/'fixtures/freeze.json').write_text(json.dumps(frozen,sort_keys=True,indent=2)+'\n');print(json.dumps(frozen,indent=2))
    else:print('PASS frozen oracle:',check()['cases'],'cases')
