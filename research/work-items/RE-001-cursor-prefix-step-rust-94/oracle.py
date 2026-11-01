#!/usr/bin/env python3
"""Frozen immutable-image relation, including post-counter-store prefix aliases."""
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
COUNTER,CURSOR,FLAG,MARKER=0x1e0,0x1d0,0x1f0,0x1f3


def sha(raw): return hashlib.sha256(raw).hexdigest()


def relation(base,state,old):
    length=len(old)
    if length and base+length>MOD: return 'E:R',old,'image_range'
    if state+FLAG>=length: return 'E:S',old,'state_bounds'
    flag=old[state+FLAG]
    counter=int.from_bytes(old[state+COUNTER:state+COUNTER+8],'little')
    if flag==0 or counter<=1:
        if state+MARKER>=length: return 'E:S',old,'state_bounds'
        marker=0x67 if flag==0 else 0x50
        updates={state+MARKER:marker}
        result='U' if flag==0 else f'V:{counter:016x}'
        category='flag_marker' if flag==0 else 'counter_marker'
    else:
        cursor=int.from_bytes(old[state+CURSOR:state+CURSOR+8],'little')
        index=cursor-base
        if index<0 or index+2>length: return 'E:P',old,'prefix_bounds'
        new_counter=counter-2
        counter_bytes=new_counter.to_bytes(8,'little')
        # The effective word is an overlay on the immutable entry image. This
        # accounts for aliases without replaying native instruction/store order.
        effective=bytes(counter_bytes[j-state-COUNTER] if state+COUNTER<=j<state+COUNTER+8 else old[j] for j in (index,index+1))
        signed=int.from_bytes(effective,'big',signed=True)
        new_cursor=(cursor+signed+2)%MOD
        updates={state+COUNTER+j:b for j,b in enumerate(counter_bytes)}
        updates.update({state+CURSOR+j:b for j,b in enumerate(new_cursor.to_bytes(8,'little'))})
        result=f'V:{new_cursor:016x}'
        category='advance_alias' if index<state+COUNTER+8 and state+COUNTER<index+2 else 'advance_disjoint'
    return result,bytes(updates.get(i,b) for i,b in enumerate(old)),category


def differences(old,new):
    # A lossless sparse image difference, not a mask: omitted indices must agree.
    return ','.join(f'{i:x}:{b:02x}' for i,(a,b) in enumerate(zip(old,new,strict=True)) if a!=b) or '-'


def make(base,state,size,flag,counter,prefix_index,word,seed):
    image=bytearray((i*37+seed)%256 for i in range(size))
    def patch(offset,raw):
        for i,b in enumerate(raw):
            if 0<=offset+i<size:image[offset+i]=b
    patch(state+FLAG,bytes([flag]));patch(state+MARKER,bytes([(seed*13)%256]))
    patch(state+COUNTER,counter.to_bytes(8,'little'))
    cursor=(base+prefix_index)%MOD
    patch(state+CURSOR,cursor.to_bytes(8,'little'))
    # Never clobber state to install a separate prefix; alias cases observe the
    # explicitly initialized state bytes, including self-referential cursors.
    state_bytes=set(range(state+CURSOR,state+CURSOR+8))|set(range(state+COUNTER,state+COUNTER+8))|{state+FLAG,state+MARKER}
    if not ({prefix_index,prefix_index+1}&state_bytes):patch(prefix_index,word.to_bytes(2,'big'))
    return base,state,bytes(image)


def cases():
    seed=0
    def row(*args):
        nonlocal seed
        seed+=1
        return (f'case-{seed:05d}',*make(*args,seed%256))
    for flag in (0,1,2,0x7f,0x80,0xff):
        for counter in (0,1,2,3,255,256,2**63,MOD-1):
            for word in (0,1,0x00ff,0x0100,0x7fff,0x8000,0x8001,0xfffe,0xffff):
                for base in (0,0x1000,MOD-512):
                    yield row(base,0,512,flag,counter,2,word)
    for counter in (2,3,255,256,257,65535,65536,2**63,MOD-1):
        for state in (0,7):
            for relative in (*range(COUNTER-1,COUNTER+8),*range(CURSOR-1,CURSOR+8),FLAG-1,FLAG,MARKER-1,MARKER):
                yield row(0x1000,state,544,1,counter,state+relative,0x1234)
    # Every byte value occurs in each half of a separately stored prefix.
    for b in range(256):
        yield row(0,0,512,1,3,0,(b<<8)|((b*71+3)%256))
        yield row(MOD-512,0,512,255,MOD-1,510,(((b*37+9)%256)<<8)|b)
    for flag in (0,1,255):
        for counter in (0,1,2,MOD-1):
            for size in (0,1,0x1f0,0x1f1,0x1f2,0x1f3,0x1f4,512):
                for index in (-1,511,512,MOD-1):
                    yield row(0x1000,0,size,flag,counter,index,0x8000)
    for base,state,size in ((MOD-511,0,512),(MOD-1,0,512),(0,MOD-1,512),(0,2**63,512),(0x1000,20,512)):
        for flag in (0,1):yield row(base,state,size,flag,2,0,0x1234)
    rng=random.Random(0x47d6b90)
    for _ in range(2048):
        state=rng.randrange(16);size=rng.randrange(0x1f0,0x230)
        base=rng.choice((0,0x1000,MOD-size,MOD-size+1))
        flag=rng.choice((0,1,rng.randrange(256)))
        counter=rng.choice((0,1,2,rng.getrandbits(64)))
        index=rng.choice((rng.randrange(size+3),state+COUNTER+rng.randrange(-1,8),state+CURSOR+rng.randrange(-1,8)))
        yield row(base,state,size,flag,counter,index,rng.randrange(65536))


def render():
    inputs=[];expected=[];coverage=Counter()
    for label,base,state,image in cases():
        result,new,category=relation(base,state,image);coverage[category]+=1
        inputs.append(f'{label}\t{base:016x}\t{state:016x}\t{image.hex() or "-"}\n')
        expected.append(f'{label}\t{result}\t{differences(image,new)}\n')
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
        if (ROOT/'src/node94-cursor-prefix-step').exists():raise ValueError('freeze must precede Rust')
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
