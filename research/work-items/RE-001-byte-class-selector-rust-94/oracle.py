#!/usr/bin/env python3
"""Pre-Rust partition and base-256 value oracle; no instruction simulation."""
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
def sha(raw):return hashlib.sha256(raw).hexdigest()

# Disjoint explicit subsets partition all 256 first-byte values.
SETS={'first':set(range(192,224)), 'second':{0}|set(range(145,160))|set(range(161,192))|set(range(224,256)),
      'nibble80':set(range(1,144)), 'nibble90':{144}, 'low5a0':{160}}
TABLE={}
for name,values in SETS.items():
    for value in values:
        if value in TABLE:raise ValueError('overlapping classes')
        TABLE[value]=name
if set(TABLE)!=set(range(256)):raise ValueError('incomplete class partition')

def expected(first,second):
    kind=TABLE[first%256]
    if kind=='first':return first,kind
    if kind=='second':return second,kind
    prefix,width={'nibble80':(128,16),'nibble90':(144,16),'low5a0':(160,32)}[kind]
    return 256*(second//256)+prefix+(second%width),kind

def cases():
    serial=0
    def row(a,b):
        nonlocal serial
        serial+=1
        return f'case-{serial:06d}',a,b
    for a in range(256):
        for b in range(256):yield row(a,b)
    selectors=(0,1,143,144,145,159,160,161,191,192,223,224,255)
    low_values=(0,1,15,16,31,32,127,128,255)
    for bit in range(8,32):
        for a in selectors:
            for b in low_values:
                yield row((1<<bit)+a,0x13579b00+b)
                yield row(0xa5a5a500+a,(1<<bit)+b)
    highs=(0,1,127,128,255,256,0x7fffff,0x800000,0xffffff)
    for ah in highs:
        for bh in highs:
            for a in selectors:
                for b in (0,15,31,255):yield row(ah*256+a,bh*256+b)
    rng=random.Random(0x359be70)
    for _ in range(2048):yield row(rng.getrandbits(32),rng.getrandbits(32))

def render():
    inputs=[];outputs=[];coverage=Counter()
    for label,a,b in cases():
        result,kind=expected(a,b);coverage[kind]+=1
        inputs.append(f'{label}\t{a:08x}\t{b:08x}\n');outputs.append(f'{label}\t{result:016x}\n')
    return ''.join(inputs).encode(),''.join(outputs).encode(),dict(sorted(coverage.items()))

def check():
    frozen=json.loads((HERE/'fixtures/freeze.json').read_text());inputs,outputs,coverage=render()
    if frozen['cases']!=len(inputs.splitlines()) or frozen['target_sha256']!=TARGET:raise ValueError('freeze identity/count')
    for name,raw in [('inputs.tsv',inputs),('expected.tsv',outputs)]:
        p=HERE/'fixtures'/(name+'.gz')
        if gzip.decompress(p.read_bytes())!=raw or sha(raw)!=frozen['sha256'][name] or sha(p.read_bytes())!=frozen['sha256'][name+'.gz']:raise ValueError('frozen fixture drift')
    if sha(Path(__file__).read_bytes())!=frozen['sha256']['oracle.py']:raise ValueError('oracle drift')
    if coverage!=frozen['coverage']:raise ValueError('coverage drift')
    return frozen

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--freeze',action='store_true');args=p.parse_args()
    if args.freeze:
        if (ROOT/'src/node94-byte-class-selector').exists():raise ValueError('freeze must precede Rust')
        if (HERE/'fixtures/freeze.json').exists():raise ValueError('already frozen')
        inputs,outputs,coverage=render();files={'inputs.tsv':inputs,'expected.tsv':outputs}
        for name,raw in list(files.items()):
            compressed=gzip.compress(raw,compresslevel=9,mtime=0);(HERE/'fixtures'/(name+'.gz')).write_bytes(compressed);files[name+'.gz']=compressed
        files['oracle.py']=Path(__file__).read_bytes()
        frozen={'target_sha256':TARGET,'cases':len(inputs.splitlines()),'exhaustive_low_byte_pairs':65536,'coverage':coverage,'frozen_at_utc':datetime.now(timezone.utc).isoformat(),'rust_source_absent':True,'sha256':{n:sha(v) for n,v in files.items()}}
        (HERE/'fixtures/freeze.json').write_text(json.dumps(frozen,sort_keys=True,indent=2)+'\n');print(json.dumps(frozen,indent=2))
    else:print('PASS frozen oracle:',check()['cases'],'cases')
