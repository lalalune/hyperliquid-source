#!/usr/bin/env python3
"""Immutable first-failure oracle for the admitted fixed-record cursor domain."""
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
WIDTH=56
MAX=2**64-1
TARGET='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'


def sha(raw):return hashlib.sha256(raw).hexdigest()


def relation(records,start,end):
    if start==end:return 'F',start,'entry_equal'
    if start>end or end>len(records):return 'E',start,'rejected'
    failures=[i for i in range(start,end) if (records[i][0],records[i][9])!=(0,2)]
    if failures:
        first=min(failures)
        return 'F',first+1,'first_failure' if first==start else 'later_failure'
    return 'T',end,'complete_nonempty'


def records(count,seed):
    result=[bytearray((seed+13*i+37*j)%256 for j in range(WIDTH)) for i in range(count)]
    for row in result:row[0]=0;row[9]=2
    return result


def cases():
    serial=0
    def case(rows,start,end):
        nonlocal serial
        serial+=1
        return f'case-{serial:05d}',[bytes(row) for row in rows],start,end
    for count in range(17):
        for start in range(count+2):
            for end in range(count+2):
                yield case(records(count,serial%256),start,end)
    for count in range(1,25):
        for fail in range(count):
            for field,value in ((9,0),(9,1),(9,3),(9,255),(0,1),(0,255)):
                rows=records(count,serial%256);rows[fail][field]=value
                yield case(rows,0,count)
    # Both byte predicates across all 256 values, at first and later positions.
    for value in range(256):
        for at in (1,3):
            for field in (0,9):
                rows=records(6,serial%256);rows[at][field]=value
                yield case(rows,1,5)
    # Bad records outside the selected interval must be ignored.
    for count in range(3,20):
        rows=records(count,serial%256)
        rows[0][0]=255;rows[-1][9]=3
        yield case(rows,1,count-1)
    for start,end in ((MAX,MAX),(2**63,2**63),(MAX,0),(0,MAX),(MAX,MAX-1),(2**63,1)):
        yield case([],start,end)
        yield case(records(3,serial%256),start,end)
    rng=random.Random(0x3c1d690)
    for trial in range(2048):
        count=rng.randrange(65);rows=records(count,rng.randrange(256))
        for _ in range(rng.randrange(4)):
            if count:
                row=rows[rng.randrange(count)];row[rng.choice((0,9))]=rng.randrange(256)
        start=rng.randrange(count+2);end=rng.randrange(count+2)
        if trial%3==0:start,end=sorted((start,end))
        yield case(rows,start,end)


def render():
    inputs=[];outputs=[];coverage=Counter()
    for name,rows,start,end in cases():
        status,position,kind=relation(rows,start,end);coverage[kind]+=1
        raw=b''.join(rows)
        inputs.append(f'{name}\t{start:016x}\t{end:016x}\t{raw.hex() or "-"}\n')
        outputs.append(f'{name}\t{status}\t{position:016x}\n')
    return ''.join(inputs).encode(),''.join(outputs).encode(),dict(sorted(coverage.items()))


def check():
    frozen=json.loads((HERE/'fixtures/freeze.json').read_text());inputs,expected,coverage=render()
    if frozen['cases']!=len(inputs.splitlines()) or frozen['target_sha256']!=TARGET:raise ValueError('freeze identity/count')
    for name,raw in [('inputs.tsv',inputs),('expected.tsv',expected)]:
        packed=(HERE/'fixtures'/(name+'.gz')).read_bytes()
        if gzip.decompress(packed)!=raw or sha(raw)!=frozen['sha256'][name]:raise ValueError('frozen fixture drift')
        if sha(packed)!=frozen['sha256'][name+'.gz']:raise ValueError('compressed fixture drift')
    if sha(Path(__file__).read_bytes())!=frozen['sha256']['oracle.py']:raise ValueError('pre-Rust oracle drift')
    if coverage!=frozen['coverage']:raise ValueError('coverage drift')
    return frozen


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--freeze',action='store_true');args=parser.parse_args()
    if args.freeze:
        if (ROOT/'src/node94-cursor-walk').exists():raise ValueError('freeze must precede Rust')
        if (HERE/'fixtures/freeze.json').exists():raise ValueError('already frozen')
        inputs,expected,coverage=render();files={'inputs.tsv':inputs,'expected.tsv':expected}
        compressed={name+'.gz':gzip.compress(raw,compresslevel=9,mtime=0) for name,raw in files.items()}
        for name,raw in compressed.items():(HERE/'fixtures'/name).write_bytes(raw)
        files.update(compressed);files['oracle.py']=Path(__file__).read_bytes()
        frozen={'target_sha256':TARGET,'cases':len(inputs.splitlines()),'coverage':coverage,'rust_source_absent':True,
                'frozen_at_utc':datetime.now(timezone.utc).isoformat(),'sha256':{name:sha(raw) for name,raw in files.items()}}
        (HERE/'fixtures/freeze.json').write_text(json.dumps(frozen,sort_keys=True,indent=2)+'\n');print(json.dumps(frozen,indent=2))
    else:print('PASS frozen oracle:',check()['cases'],'cases')
