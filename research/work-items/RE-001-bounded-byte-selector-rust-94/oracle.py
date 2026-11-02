#!/usr/bin/env python3
"""Pre-Rust piecewise byte-selection oracle over immutable abstract memory."""
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
U=2**32
TARGET='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
def sha(raw):return hashlib.sha256(raw).hexdigest()
def signed(x):return x if x<U//2 else x-U

def select(base,a,s,index,bound,flag,m):
    if flag==0:return 0,'disabled'
    end=base+len(m)
    if end>MOD:return None,'image_refusal'
    def valid(address,size):return base<=address and address+size<=end and address+size<=MOD
    def word(address,size):return int.from_bytes(m[address-base:address-base+size],'little')
    if not valid(s+340,1):return None,'cache_refusal'
    cached=word(s+340,1)
    if cached!=255:
        if not valid(a+20,4):return None,'inner_refusal'
        if signed((word(a+20,4)-1)%U)<=signed(index):return cached,'cached'
    if not valid(s+464,8) or not valid(s+456,8):return None,'span_refusal'
    high=word(s+464,8);low=word(s+456,8)
    if high==low:
        if not valid(s+339,1):return None,'default_refusal'
        return word(s+339,1),'empty_default'
    if index==0:address=low;kind='index_zero'
    else:
        relative=signed((index-bound+1)%U)
        last=signed((high-low-1)%U)
        address=(low+max(0,min(relative,last)))%MOD;kind='clamped'
    if not valid(address,1):return None,'byte_refusal'
    return word(address,1),kind

def relation(mode,base,a,s,index,bound,flag,m):
    if mode=='H':return select(base,a,s,index,bound,flag,m)
    end=base+len(m)
    if end>MOD:return None,'wrapper_image_refusal'
    def valid(address,size):return base<=address and address+size<=end and address+size<=MOD
    def word(address,size):return int.from_bytes(m[address-base:address-base+size],'little')
    outer=a
    if not valid(outer,8) or not valid(outer+8,4):return None,'wrapper_entry_refusal'
    inner=word(outer,8);index=word(outer+8,4)
    if not valid(inner+2800,4) or outer+904>=MOD:return None,'wrapper_bound_refusal'
    bound=word(inner+2800,4)
    value,kind=select(base,inner,outer+904,index,bound,1,m)
    if value is None:return None,'wrapper_'+kind
    if not valid(outer+4116,1):return None,'wrapper_comparison_refusal'
    answer=int(value==word(outer+4116,1))
    return answer,'wrapper_equal' if answer else 'wrapper_unequal'

def cases():
    serial=0
    def image(n,seed):return bytearray((k*71+k//16*19+seed)%256 for k in range(n))
    def put(m,off,value,size):
        for j,b in enumerate((value%(1<<(8*size))).to_bytes(size,'little')):
            if 0<=off+j<len(m):m[off+j]=b
    def helper(base,a,s,index,bound,flag,cached,w,low,difference,n,default=0x55):
        nonlocal serial
        serial+=1;m=image(n,serial)
        put(m,a+20,w,4);put(m,s+339,default,1);put(m,s+340,cached,1)
        put(m,s+456,base+low,8);put(m,s+464,base+low+difference,8)
        return f'case-{serial:05d}','H',base,(base+a)%MOD,(base+s)%MOD,index,bound,flag,bytes(m)
    words=(0,1,2,U//2-1,U//2,U-1)
    for cached in (0,1,127,128,254,255):
        for w in words:
            for index in words:
                for flag in (0,1,2,255):yield helper(0x1000,32,0,index,3,flag,cached,w,800,16,1024)
    differences=(-1,0,1,2,16,127,U//2,U//2+1,U-1,U,U+1,MOD-1)
    for index in words+(3,127,128):
        for bound in words:
            for difference in differences:yield helper(0x1000,MOD-1,0,index,bound,1,255,0,800,difference,1024)
    for cached in range(256):
        yield helper(0x1000,32,0,7,0,1,cached,8,800,0,1024,cached^255)
        yield helper(0x1000,32,0,1,0,1,cached,3,800,16,1024,cached)
    # The selected byte can fit while the initial low pointer is outside image.
    for low in (-127,-17,-1,0,1023,1024):
        for index,bound in ((0,0),(1,0),(16,0),(126,0),(1,U-127)):
            for difference in (0,1,128,U,U//2+1):yield helper(0x1000,32,0,index,bound,1,255,0,low,difference,1024)
    for n in (0,1,23,24,339,340,341,455,456,463,464,471,472,800,801,1024):
        for flag,cached,w,index in ((0,0,0,0),(1,7,0,0),(1,255,0,0),(1,255,0,1),(1,0,U//2,U-1)):
            yield helper(0x1000,0,0,index,0,flag,cached,w,800,0 if index==0 else 1,n)
    # Cache can be available while the preceding default byte is not.
    for difference in (0,1):
        yield helper(0x1000,32,-340,0,0,1,255,0,160,difference,256)
    for base in (0,MOD-1024,MOD-1023,MOD-1):
        for flag in (0,1):yield helper(base,32,0,1,0,flag,255,0,1023,1,1024)
    for bad in (MOD-1,MOD-340,MOD-20,2**63,0):
        label,mode,b,a,s,i,k,f,m=helper(0x1000,32,0,1,0,1,255,0,800,16,1024)
        yield label+'-a',mode,b,bad,s,i,k,f,m
        yield label+'-s',mode,b,a,bad,i,k,f,m
    def wrapper(index,bound,cached,w,difference,n,match,outer=0,inner=2000):
        nonlocal serial
        serial+=1;base=0x1000;m=image(n,serial);context=outer+904;low=4500
        put(m,outer,base+inner,8);put(m,outer+8,index,4);put(m,inner+20,w,4)
        put(m,inner+2800,bound,4);put(m,context+339,0x55,1);put(m,context+340,cached,1)
        put(m,context+456,base+low,8);put(m,context+464,base+low+difference,8)
        # Set a known comparison byte, independent of any Rust execution.
        # Positive cases are established directly for cache/empty/zero-index;
        # other rows retain a deliberate byte to exercise argument forwarding.
        known=cached if cached!=255 and signed((w-1)%U)<=signed(index) else 0x55 if difference==0 else m[low] if index==0 and low<n else serial%256
        put(m,outer+4116,known if match else known^1,1)
        return f'case-{serial:05d}','W',base,base+outer,0,0,0,0,bytes(m)
    for index in words:
        for bound in words:
            for cached in (0,128,255):
                for difference in (0,1,16,U+1):
                    for match in (False,True):yield wrapper(index,bound,cached,1,difference,5000,match)
    for n in (0,8,12,1244,1245,1375,1376,4116,4117,4200,4501,4803,4804,5000):
        for cached in (7,255):yield wrapper(0,0,cached,0,0,n,True)
    # Eager bound is available here; isolate the final comparison's boundary.
    for n in (4000,4116,4117):
        for cached in (0,255):yield wrapper(0,0,cached,0,0,n,True,inner=0)
    for inner in (-2790,0,16,2200):
        for cached in (0,255):yield wrapper(0,0,cached,0,1,5200,True,outer=7,inner=inner)
    rng=random.Random(0x4ff8ac0)
    for _ in range(1536):
        n=rng.randrange(340,1100);s=rng.randrange(16);a=rng.randrange(n+1)
        yield helper(0x1000,a,s,rng.randrange(U),rng.randrange(U),rng.choice((0,1,255)),rng.randrange(256),rng.randrange(U),rng.randrange(-128,n+16),rng.choice(differences),n)

def render():
    inputs=[];expected=[];coverage=Counter()
    for label,mode,base,a,s,index,bound,flag,m in cases():
        value,kind=relation(mode,base,a,s,index,bound,flag,m);coverage[kind]+=1
        result='E' if value is None else f'V:{value:016x}'
        inputs.append(f'{label}\t{mode}\t{base:016x}\t{a:016x}\t{s:016x}\t{index:08x}\t{bound:08x}\t{flag}\t{m.hex() or "-"}\n')
        expected.append(f'{label}\t{result}\n')
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
        if (ROOT/'src/node94-bounded-byte-selector').exists():raise ValueError('freeze must precede Rust')
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
