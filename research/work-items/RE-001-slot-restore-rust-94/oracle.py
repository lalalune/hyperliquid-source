#!/usr/bin/env python3
"""Independent immutable-image overlay for link, retained slot prefix and final tag."""
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

def relation(base,out,owner,state,m):
    end=base+len(m)
    if end>MOD:return 'E',m,'image_refusal'
    def valid(a,n):return base<=a and a+n<=end and a+n<=MOD
    if not valid(owner+216,8) or not valid(state,8):return 'E',m,'entry_refusal'
    u=lambda a:int.from_bytes(m[a-base:a-base+8],'little')
    h=u(owner+216);q=16 if u(state)==0 else 0
    slot=state+q+48;link=slot-8;kindaddr=slot+16
    if not valid(kindaddr,1) or not valid(slot,16) or not valid(h+568,8):return 'E',m,'snapshot_refusal'
    if not valid(link,8) or not valid(out,1):return 'E',m,'output_refusal'
    kind=m[kindaddr-base];r=16 if kind in {0,1,2,3,4} else 8 if kind in {16,17,18,19,20,21} else 0
    old=m[slot-base:slot-base+16];linkbytes=m[h+568-base:h+576-base]
    def at(i,oldbyte):
        a=base+i
        if a==out:return 5
        if slot<=a<slot+r:return old[a-slot]
        if slot+r<=a<slot+16:return 0
        if link<=a<link+8:return linkbytes[a-link]
        return oldbyte
    return f'V:{out:016x}',bytes(at(i,b) for i,b in enumerate(m)),f'retain_{r}'

def differences(old,new):
    return ','.join(f'{i:x}:{b:02x}' for i,(a,b) in enumerate(zip(old,new,strict=True)) if a!=b) or '-'

def cases():
    serial=0
    def make(base,outoff,owneroff,stateoff,selector,kind,hopread,n,seed=None):
        nonlocal serial
        serial+=1
        if seed is None:seed=serial
        m=bytearray((i*71+i//8*19+seed)%256 for i in range(n))
        def put(off,raw):
            for j,b in enumerate(raw):
                if 0<=off+j<n:m[off+j]=b
        q=16 if selector==0 else 0
        put(stateoff,selector.to_bytes(8,'little'))
        put(stateoff+q+64,bytes([kind]))
        put(owneroff+216,((base+hopread-568)%MOD).to_bytes(8,'little'))
        return f'case-{serial:05d}',base,(base+outoff)%MOD,(base+owneroff)%MOD,(base+stateoff)%MOD,bytes(m)
    # All 256 kinds in both selected slots, and final-tag aliases in every band.
    for selector in (0,1):
        q=16 if selector==0 else 0
        for kind in range(256):
            for out in (1000,q+40,q+47,q+48,q+55,q+56,q+63,q+64):
                yield make(0x1000,out,32,0,selector,kind,800,1024)
    # Every byte of slot/link as a possible tag, unaligned state and aliased hop read.
    for state in (0,3,19):
        for selector in (0,2**63,MOD-1):
            q=16 if selector==0 else 0
            for kind in (0,4,5,15,16,21,22,128,255):
                for delta in range(-8,17):
                    slot=state+q+48
                    yield make(0x1000,slot+delta,40,state,selector,kind,slot-4+(delta%17),1024)
    for base in (0,1,0x1000,MOD-1024,MOD-1023):
        for selector in (0,1):
            for kind in (4,5,16,21,22,255):
                yield make(base,1023,32,0,selector,kind,800,1024)
    # A hop/object base may be below the image if its accessed field fits.
    for owner in (-216,-200,32):
        for hopread in (0,1,8,40,48,64,80,800):
            yield make(0x1000,1000,owner,64,1,16,hopread,1024)
    for n in (0,1,7,8,39,40,47,48,55,56,63,64,65,79,80,81,223,224,255,256,799,800,807,808,1023,1024):
        for selector in (0,1):
            for kind in (0,5,16):yield make(0x1000,0,0,0,selector,kind,800,n)
    # Minimal selected-state availability with other read fields aliased inside it.
    for n in (63,64,65,79,80,81):
        for selector in (0,1):
            for kind in (0,5,16):yield make(0x1000,n-1,-208,0,selector,kind,8,n)
    # Full range of actual bytes and explicit unavailable/overflow address values.
    for b in range(256):yield make(0x1000,800,32,3,1,16,900,1024,b)
    for bad in (MOD-1,MOD-215,MOD-48,MOD-64,0,2**63):
        label,base,out,owner,state,m=make(0x1000,1000,32,0,1,16,800,1024)
        yield label+'-out',base,bad,owner,state,m
        yield label+'-owner',base,out,bad,state,m
        yield label+'-state',base,out,owner,bad,m
    rng=random.Random(0x3290130)
    for _ in range(1024):
        n=rng.randrange(500,1100);state=rng.randrange(0,96);owner=rng.randrange(-216,500)
        yield make(0x1000,rng.randrange(n+2),owner,state,rng.choice((0,1,rng.getrandbits(64))),rng.randrange(256),rng.randrange(n+2),n)

def render():
    inputs=[];expected=[];coverage=Counter()
    for label,base,out,owner,state,m in cases():
        result,new,category=relation(base,out,owner,state,m);coverage[category]+=1
        inputs.append(f'{label}\t{base:016x}\t{out:016x}\t{owner:016x}\t{state:016x}\t{m.hex() or "-"}\n')
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
        if (ROOT/'src/node94-slot-restore').exists():raise ValueError('freeze must precede Rust')
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
