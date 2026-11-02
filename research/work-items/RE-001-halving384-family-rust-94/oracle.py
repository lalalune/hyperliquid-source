#!/usr/bin/env python3
"""Pre-Rust independent closed-form oracle; no limb recurrence or instruction model."""
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
TARGET='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
M=1<<384
B=1<<64
LOW=(1<<63)-1

def sha(x):return hashlib.sha256(x).hexdigest()
def count(raw):return raw%(1<<32) or 1<<32

def closed(a,c,n):
    if not a:return 0
    if not c:return a>>n if n<384 else 0
    d=c if c%2 else c-1
    if n<=384:
        scale=1<<n
        coefficient=(-a*pow(d,-1,scale))%scale
        return (a+d*coefficient)//scale
    if d==1:return 1
    residue=(a*pow(pow(2,-1,d),n,d))%d
    return residue or d

def words(v):return tuple((v//(B**i))%B for i in range(6))
def core_regs(v):
    w=words(v)
    return (w[2]&LOW,w[5]&LOW,w[3]&LOW,w[4]&LOW,w[0]&LOW,w[1]&LOW)+w

def image_case(mode,image,base,dst,src,corr,raw):
    original=bytes(image)
    if base+len(image)>B:return None,original,'image-wrap'
    offsets=[]
    for addr in (dst,src,corr):
        offset=addr-base
        if offset<0 or addr+48>B or offset+48>len(image):return None,original,'range-refusal'
        offsets.append(offset)
    dest,inp,fix=offsets
    a=int.from_bytes(image[inp:inp+48],'little');c=int.from_bytes(image[fix:fix+48],'little')
    v=closed(a,c,1 if mode=='S' else count(raw));w=words(v)
    regs=(w[2]&LOW,0 if mode=='R' else corr,w[5]&LOW,corr,dst)+w[:4]
    result=bytearray(image);result[dest:dest+48]=v.to_bytes(48,'little')
    overlap=any(dest<x+48 and x<dest+48 for x in (inp,fix))
    return regs,bytes(result),'output-alias' if overlap else 'disjoint'

def corpus():
    edge=(0,1,2,3,1<<63,(1<<64)-1,1<<64,1<<255,1<<383,M-2,M-1)
    for a in edge:
        for c in edge:yield ('C',a,c)
    for bit in range(384):
        p=1<<bit
        for a,c in ((p,M-1),(p+1 if p+1<M else p,M-1),(M-1-p,p),(M-1,p),(p,0)):
            yield ('C',a,c)
    counts=(1,2,3,63,64,127,128,383,384,385,386,511,1024,0,(1<<32)-1,1<<32,B-1)
    def case(mode,a,c,raw,dst=0,src=64,corr=128,base=0x1000,length=176):
        im=bytearray((i*37+19)%256 for i in range(length))
        if 0<=src and src+48<=length:im[src:src+48]=a.to_bytes(48,'little')
        if 0<=corr and corr+48<=length:im[corr:corr+48]=c.to_bytes(48,'little')
        return (mode,bytes(im),base,(base+dst)%B,(base+src)%B,(base+corr)%B,raw)
    for a in edge:
        for c in edge:
            yield case('S',a,c,0)
            for raw in counts:yield case('R',a,c,raw)
    # Every destination displacement relative to either input, including unaligned overlap.
    for shift in range(-47,48):
        for mode,raw in (('S',0),('R',385),('R',0)):
            yield case(mode,M-1,M-2,raw,64+shift,64,0)
            yield case(mode,M-3,M-1,raw,64+shift,0,64)
    for off in range(0,49):
        yield case('R',M-1,M-1,384,64,32,32+off)
    # Address-wrap, underflow, exact-end and short-span cases; zero still needs both reads.
    for mode in ('S','R'):
        for base in (0,0x1000,B-176,B-175,B-1):
            for length in (0,47,48,175,176):
                for dest,src,corr in ((0,0,0),(0,64,128),(129,64,128),(-1,64,128)):
                    yield case(mode,0,0,0,dest,src,corr,base,length)
    rng=random.Random(0x5656b20)
    for i in range(768):
        a=rng.getrandbits(384);c=rng.getrandbits(384)
        yield ('C',a,c)
        raw=rng.choice(counts) if i%2 else rng.getrandbits(64)
        yield case('R' if i%3 else 'S',a,c,raw,rng.randrange(129),rng.randrange(129),rng.randrange(129))

def render():
    inputs=[];outputs=[];coverage=Counter()
    for i,case in enumerate(corpus()):
        mode=case[0];label=f'case-{i:05d}';coverage[mode]+=1
        if mode=='C':
            _,a,c=case;v=closed(a,c,1);regs=core_regs(v);result='-'
            fields=(label,mode,f'{a:096x}',f'{c:096x}','-','-','-','-')
            if a+c>=M and a%2:coverage['core-carry']+=1
        else:
            _,im,base,dst,src,corr,raw=case
            regs,new,kind=image_case(mode,im,base,dst,src,corr,raw);coverage[kind]+=1
            fields=(label,mode,f'{base:016x}',f'{dst:016x}',f'{src:016x}',f'{corr:016x}',f'{raw:016x}',im.hex() or '-')
            result=new.hex() or '-'
            if mode=='R' and regs is not None:
                n=count(raw);coverage['count-zero-low32' if n==1<<32 else 'count-tail' if n>384 else 'count-direct']+=1
        outputs.append(label+'\t'+('E' if regs is None else 'V:'+':'.join(f'{x:016x}' for x in regs))+'\t'+result+'\n')
        inputs.append('\t'.join(fields)+'\n')
    return ''.join(inputs).encode(),''.join(outputs).encode(),dict(sorted(coverage.items()))

def check():
    f=json.loads((HERE/'fixtures/freeze.json').read_text());inp,out,cov=render()
    if f['cases']!=len(inp.splitlines()) or f['coverage']!=cov or f['target_sha256']!=TARGET:raise ValueError('freeze identity')
    for name,raw in [('inputs.tsv',inp),('expected.tsv',out)]:
        packed=(HERE/'fixtures'/(name+'.gz')).read_bytes()
        if gzip.decompress(packed)!=raw or sha(raw)!=f['sha256'][name] or sha(packed)!=f['sha256'][name+'.gz']:raise ValueError('fixture drift')
    if sha(Path(__file__).read_bytes())!=f['sha256']['oracle.py']:raise ValueError('oracle drift')
    return f

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--freeze',action='store_true');a=p.parse_args()
    if a.freeze:
        if (ROOT/'src/node94-halving384-family').exists() or (HERE/'fixtures/freeze.json').exists():raise ValueError('freeze must precede new source')
        inp,out,cov=render();files={'inputs.tsv':inp,'expected.tsv':out}
        for name,raw in list(files.items()):
            packed=gzip.compress(raw,mtime=0);(HERE/'fixtures'/(name+'.gz')).write_bytes(packed);files[name+'.gz']=packed
        files['oracle.py']=Path(__file__).read_bytes()
        f={'target_sha256':TARGET,'cases':len(inp.splitlines()),'coverage':cov,'frozen_at_utc':datetime.now(timezone.utc).isoformat(),'rust_source_absent':True,'sha256':{k:sha(v) for k,v in files.items()}}
        (HERE/'fixtures/freeze.json').write_text(json.dumps(f,sort_keys=True,indent=2)+'\n');print(json.dumps(f,indent=2))
    else:print('PASS frozen oracle',check()['cases'])
