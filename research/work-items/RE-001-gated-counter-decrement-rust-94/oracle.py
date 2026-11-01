#!/usr/bin/env python3
"""Pre-Rust byte-equality and integer-residue relation, without instruction stepping."""
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

def relation(base,outer,image):
    end=base+len(image)
    if end>MOD:return None,image,'image_refusal'
    def chunk(address,size):
        if not base<=address or address+size>end:raise LookupError
        return image[address-base:address-base+size]
    def integer(raw):return sum(byte*256**i for i,byte in enumerate(raw))
    try:
        inner=integer(chunk(outer,8))
        # Qword equality is equivalently equality of the two byte strings.
        # The first unequal pair defines the required read prefix, regardless
        # of unavailable later pairs or the unused owner/counter path.
        for j,offset in enumerate((8,56,104,128,176)):
            if chunk((inner+offset)%MOD,8)!=chunk((inner+offset+8)%MOD,8):
                return inner,image,f'mismatch-{j+1}'
        owner=integer(chunk((outer+8)%MOD,8))
        address=(owner+5276)%MOD
        old=integer(chunk(address,4))
    except LookupError:return None,image,'access_refusal'
    after=bytearray(image);residue=(old-1)%(256**4)
    after[address-base:address-base+4]=bytes((residue//256**i)%256 for i in range(4))
    return owner,bytes(after),'decrement'

def cases():
    serial=0
    def make(mask=0,counter=0,outer=0,inner=64,slot=350,n=384,base=0x10000,difference=1,seed=13):
        nonlocal serial
        serial+=1;image=bytearray((i*43+i//8*17+seed)%256 for i in range(n))
        def put(at,value,width):
            for j in range(width):
                if 0<=at+j<n:image[at+j]=(value//256**j)%256
        # Intentional entry-image collisions are resolved by this fixed
        # initialization order; the oracle consumes only the final bytes.
        put(slot,counter,4)
        for j,offset in enumerate((8,56,104,128,176)):
            value=(0x123456789abcdef0*(j+1)+seed)%MOD
            put(inner+offset,value,8)
            put(inner+offset+8,value^(difference if mask&(1<<j) else 0),8)
        put(outer,(base+inner)%MOD,8)
        put(outer+8,(base+slot-5276)%MOD,8)
        return f'case-{serial:05d}',base,(base+outer)%MOD,bytes(image)
    edges=(0,1,2,255,256,0x7fffffff,0x80000000,0xfffffffe,0xffffffff)
    for mask in range(32):
        for counter in edges:
            for difference in (1,255,256,1<<31,1<<32,1<<63,MOD-1):
                yield make(mask,counter,difference=difference)
    # Every counter byte offset across outer/inner fields and nonfields;
    # writes happen after all gate reads and may change their former values.
    for slot in range(-4,385):
        for counter in (0,1,0x80000000,0xffffffff):
            yield make(counter=counter,slot=slot,seed=slot)
    # Exact read prefixes: every cutoff, each first-mismatch position, and
    # all-equal. Counter and owner need no mapping on mismatch paths.
    for n in range(0,289):
        for mask in (0,1,2,4,8,16):
            yield make(mask,0xffffffff,n=n,slot=280)
    for outer in (0,1,7,8,15,64,65,71,72,80,120,127,128,184,192,200,256,376):
        for inner in (-8,-7,-1,0,1,7,8,16,56,64,128,192,200):
            yield make(0,0,outer,inner,slot=350,base=0)
    for base in (0,MOD-384,MOD-383,MOD-1):
        for mask in (0,1,2,4,8,16):
            for counter in edges:yield make(mask,counter,base=base)
    # P=2^64-8: P itself is outside the image, all used positive fields
    # wrap into it. The unused helper argument similarly needs no range.
    for n in (191,192,207,208,211,212,255,256):
        for mask in (0,1,2,4,8,16):
            for slot in (0,8,16,48,56,96,104,120,128,168,176,208,252):
                yield make(mask,0,outer=200,inner=-8,slot=slot,n=n,base=0)
    for outer in (376,377,380,383,384):
        for mask in (0,1,2,4,8,16):yield make(mask,0,outer=outer)
    # Full high-address and malformed pointer values, without interpreting
    # process canonicality or speculatively requiring an unused address.
    for bad in (0,1,0xffff,1<<32,1<<63,MOD-1,MOD-7):
        for field in (0,8):
            row=list(make());image=bytearray(row[3]);image[field:field+8]=bad.to_bytes(8,'little');row[3]=bytes(image);yield tuple(row)
    rng=random.Random(0x50a90a0)
    for i in range(2048):
        yield make(rng.choice((0,0,0,1,2,4,8,16,31)),rng.getrandbits(32),
                   rng.choice((0,0,0,rng.randrange(384))),rng.choice((64,64,-8,rng.randrange(-8,200))),
                   rng.randrange(-4,385),rng.choice((384,384,rng.randrange(385))),
                   rng.choice((0,0x10000,MOD-384)),1<<rng.randrange(64),rng.randrange(256))

def render():
    inputs=[];expected=[];coverage=Counter()
    for label,base,outer,image in cases():
        value,after,kind=relation(base,outer,image);coverage[kind]+=1
        changes=','.join(f'{i:x}:{b:02x}' for i,b in enumerate(after) if b!=image[i]) or '-'
        status='E' if value is None else f'V:{value:016x}'
        inputs.append(f'{label}\t{base:016x}\t{outer:016x}\t{image.hex() or "-"}\n')
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
        if (ROOT/'src/node94-gated-counter-decrement').exists():raise ValueError('freeze must precede Rust')
        if (HERE/'fixtures/freeze.json').exists():raise ValueError('already frozen')
        inputs,expected,coverage=render();files={'inputs.tsv':inputs,'expected.tsv':expected}
        for name,raw in list(files.items()):
            compressed=gzip.compress(raw,compresslevel=9,mtime=0);(HERE/'fixtures'/(name+'.gz')).write_bytes(compressed);files[name+'.gz']=compressed
        files['oracle.py']=Path(__file__).read_bytes()
        frozen={'target_sha256':TARGET,'cases':len(inputs.splitlines()),'coverage':coverage,'frozen_at_utc':datetime.now(timezone.utc).isoformat(),'rust_source_absent':True,'sha256':{n:sha(v) for n,v in files.items()}}
        (HERE/'fixtures/freeze.json').write_text(json.dumps(frozen,sort_keys=True,indent=2)+'\n');print(json.dumps(frozen,indent=2))
    else:print('PASS frozen oracle:',check()['cases'],'cases')
