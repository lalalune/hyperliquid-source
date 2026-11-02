#!/usr/bin/env python3
"""Post-Rust wrap-boundary supplement; uses the unchanged pre-Rust oracle."""
import argparse
from datetime import datetime,timezone
import gzip
import json
from pathlib import Path
from oracle import HERE,ROOT,MOD,check,relation,sha

def render():
    inputs=[];expected=[]
    for base in (0,16):
        for missing in (1,17,127):
            for step in (2,18,128,256):
                m=bytearray((k*73+21)%256 for k in range(1024))
                m[340]=255
                low=MOD-missing;high=(low+512)%MOD
                m[456:464]=low.to_bytes(8,'little');m[464:472]=high.to_bytes(8,'little')
                # All indices are positive; native clamp is min(step,511)=step.
                # Address wraps to step-missing. Availability is direct interval
                # membership, independent of the source and expectation parser.
                selected=step-missing
                known=m[selected-base] if base<=selected<base+len(m) else None
                value,_=relation('H',base,base+32,base,step-1,0,1,m)
                if value!=known:raise ValueError('independent wrapped-address witness')
                label=f'wrap-{base}-{missing}-{step}'
                inputs.append(f'{label}\tH\t{base:016x}\t{base+32:016x}\t{base:016x}\t{step-1:08x}\t00000000\t1\t{m.hex()}\n')
                expected.append(f'{label}\t'+('E' if value is None else f'V:{value:016x}')+'\n')
    return ''.join(inputs).encode(),''.join(expected).encode()

def verify():
    check();meta=json.loads((HERE/'fixtures/supplement.json').read_text())
    for name,raw in zip(('supplement-inputs.tsv','supplement-expected.tsv'),render()):
        path=HERE/'fixtures'/(name+'.gz')
        if gzip.decompress(path.read_bytes())!=raw or sha(raw)!=meta['sha256'][name] or sha(path.read_bytes())!=meta['sha256'][name+'.gz']:
            raise ValueError('supplement drift')
    if sha(Path(__file__).read_bytes())!=meta['sha256']['supplement.py']:raise ValueError('supplement generator drift')
    for name in ('lib.rs','client.rs'):
        if sha((ROOT/'src/node94-bounded-byte-selector'/name).read_bytes())!=meta['source_sha256_at_supplement'][name]:raise ValueError('source changed after supplement')
    return meta

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--freeze',action='store_true');args=p.parse_args()
    if args.freeze:
        check();path=HERE/'fixtures/supplement.json'
        if path.exists():raise ValueError('already frozen')
        files=dict(zip(('supplement-inputs.tsv','supplement-expected.tsv'),render()))
        for name,raw in list(files.items()):
            compressed=gzip.compress(raw,compresslevel=9,mtime=0)
            (HERE/'fixtures'/(name+'.gz')).write_bytes(compressed);files[name+'.gz']=compressed
        files['supplement.py']=Path(__file__).read_bytes()
        meta={'phase':'post-Rust; original frozen oracle/source/4716-case corpus unchanged','reason':'checked-selected-add compiled control survived original corpus; add concrete wrap-to-mapped-byte witnesses','frozen_at_utc':datetime.now(timezone.utc).isoformat(),'cases':24,'source_sha256_at_supplement':{n:sha((ROOT/'src/node94-bounded-byte-selector'/n).read_bytes()) for n in ('lib.rs','client.rs')},'sha256':{n:sha(raw) for n,raw in files.items()}}
        path.write_text(json.dumps(meta,sort_keys=True,indent=2)+'\n');print(json.dumps(meta,indent=2))
    else:print('PASS post-Rust supplement:',verify()['cases'],'cases')
