#!/usr/bin/env python3
"""Pre-Rust whole-prefix integer oracle for checked subtraction with aliases."""
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
WIDE=1<<256
TARGET='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
def sha(raw):return hashlib.sha256(raw).hexdigest()

def relation(base,left,right,out,image):
    end=base+len(image)
    if end>MOD:return None,image,'image_refusal'
    def at(address,size):
        return address-base if base<=address and address+size<=end else None
    a,b,o=at(left,32),at(right,32),at(out,8)
    if a is None or b is None or o is None:return None,image,'operand_refusal'
    entry=int.from_bytes(image[a:a+32],'little')
    current=bytearray(image);observed=0
    # Prefix invariant: lower 8*j minuend bytes represent the residue of
    # entry minus the concatenation of right words observed so far. Rewriting
    # the entire prefix is mathematical evaluation, not native instruction
    # stepping; no flags, registers, opcodes or executable bytes are used.
    for j in range(4):
        observed+=int.from_bytes(current[b+8*j:b+8*j+8],'little')*256**(8*j)
        width=8*(j+1)
        residue=(entry-observed)%256**width
        current[a:a+width]=residue.to_bytes(width,'little')
    success=int(entry>=observed)
    if success and at(out,40) is None:return None,image,'success_output_refusal'
    if success:
        snapshot=bytes(current[a:a+32])
        current[o+8:o+40]=snapshot
    current[o:o+8]=success.to_bytes(8,'little')
    kind='success' if success else 'failure'
    if max(a,b)<min(a+32,b+32):kind+='-operand-alias'
    if max(a,o)<min(a+32,o+(40 if success else 8)):kind+='-output-alias'
    return success,bytes(current),kind

def cases():
    serial=0
    def make(x,y,left=64,right=144,out=224,n=288,base=0x1000,seed=19):
        nonlocal serial
        serial+=1;m=bytearray((i*43+i//8*17+seed)%256 for i in range(n))
        def put(at,value):
            for j,v in enumerate((value%WIDE).to_bytes(32,'little')):
                if 0<=at+j<n:m[at+j]=v
        put(left,x);put(right,y)
        return f'case-{serial:05d}',base,(base+left)%MOD,(base+right)%MOD,(base+out)%MOD,bytes(m)
    edges=(0,1,2,255,256,(1<<63)-1,1<<63,(1<<64)-1,1<<64,(1<<64)+1,(1<<128)-1,1<<128,(1<<192)-1,1<<192,(1<<255)-1,1<<255,WIDE-2,WIDE-1)
    for x in edges:
        for y in edges:yield make(x,y)
    for bit in range(256):
        x=1<<bit
        for a,b in ((x,0),(x,1),(x,x-1),(x,x),(x,x+1),(0,x),(WIDE-1,x)):
            yield make(a,b)
    # All byte displacements where the operand ranges overlap and where the
    # output flag/payload overlaps the minuend. The initialized ENTRY image
    # defines the values, including collisions between fixture writes.
    for delta in range(-31,32):
        for output_delta in range(-39,32):
            yield make(0x8877665544332211*int('1'*64,16),0x1020304050607080*int('1234'*16,16),left=80,right=80+delta,out=80+output_delta,n=200,seed=delta+output_delta)
    # Equal operand pointers and exact aliases under zero/one/max patterns.
    for x in edges:
        for delta in (-40,-32,-24,-16,-8,-1,0,1,7,8,16,24,31,32,40):
            yield make(x,x,left=64,right=64,out=64+delta,n=160)
            yield make(x,WIDE-1-x,left=64,right=96,out=64+delta,n=160)
    # Failure writes only its flag: a short output tail is admitted, while
    # a successful payload shortage refuses before any observable mutation.
    for x,y in ((0,1),(1,0),(1,1),(WIDE-1,1)):
        for n in (0,7,8,31,32,63,64,95,96,103,104,111,112,127,128,135,136,143,144,151,152,159,160):
            yield make(x,y,left=0,right=32,out=96,n=n)
    for base in (0,MOD-288,MOD-287,MOD-1):
        for x,y in ((0,1),(1,0),(WIDE-1,WIDE-2)):
            yield make(x,y,base=base)
    for left,right,out in ((0,32,64),(1,33,65),(32,0,96),(64,64,8),(64,32,64)):
        for n in (96,97,103,104,135,136):yield make(1,0,left,right,out,n,MOD-n)
    # No wrapped 32-byte operand ranges admitted; invalid abstract addresses
    # must produce a safe refusal with the whole image unchanged.
    for field in range(3):
        for bad in (0,0xfff,1<<63,MOD-1,MOD-7,MOD-31):
            row=list(make(0,1));row[2+field]=bad;yield tuple(row)
    rng=random.Random(0x2760a10)
    for _ in range(2048):
        yield make(rng.getrandbits(256),rng.getrandbits(256),rng.randrange(0,169),rng.randrange(0,169),rng.randrange(0,193),rng.choice((200,200,rng.randrange(201))),rng.choice((0,0x1000,MOD-200)),rng.randrange(256))

def render():
    inputs=[];expected=[];coverage=Counter()
    for label,base,left,right,out,image in cases():
        value,after,kind=relation(base,left,right,out,image);coverage[kind]+=1
        changes=','.join(f'{i:x}:{b:02x}' for i,b in enumerate(after) if b!=image[i]) or '-'
        status='E' if value is None else f'V:{value:016x}'
        inputs.append(f'{label}\t{base:016x}\t{left:016x}\t{right:016x}\t{out:016x}\t{image.hex() or "-"}\n')
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
        if (ROOT/'src/node94-checked-subtract').exists():raise ValueError('freeze must precede Rust')
        if (HERE/'fixtures/freeze.json').exists():raise ValueError('already frozen')
        inputs,expected,coverage=render();files={'inputs.tsv':inputs,'expected.tsv':expected}
        for name,raw in list(files.items()):
            compressed=gzip.compress(raw,compresslevel=9,mtime=0);(HERE/'fixtures'/(name+'.gz')).write_bytes(compressed);files[name+'.gz']=compressed
        files['oracle.py']=Path(__file__).read_bytes()
        frozen={'target_sha256':TARGET,'cases':len(inputs.splitlines()),'coverage':coverage,'frozen_at_utc':datetime.now(timezone.utc).isoformat(),'rust_source_absent':True,'sha256':{n:sha(v) for n,v in files.items()}}
        (HERE/'fixtures/freeze.json').write_text(json.dumps(frozen,sort_keys=True,indent=2)+'\n');print(json.dumps(frozen,indent=2))
    else:print('PASS frozen oracle:',check()['cases'],'cases')
