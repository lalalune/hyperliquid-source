#!/usr/bin/env python3
"""Independent algebraic oracle; never imports Rust or predecessor drain model."""
import argparse
from collections import Counter
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import random

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
MOD=2**64
TARGET='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'


def sha(raw): return hashlib.sha256(raw).hexdigest()


def relation(c,a,p):
    # Classification partitions ALL signed32 values, not an assumed bit count range.
    n=2 if c==16 else int(c>=8)
    digits=[a%256,a//256]
    emitted=digits[:n]+[0]*(2-n)
    remaining_c={0:c,1:c-8,2:0}[n]
    remaining_a={0:a,1:a//256,2:0}[n]
    rax={0:c%2**32,1:p,2:0}[n]
    return n,bytes(emitted),remaining_c,remaining_a,(p+n)%MOD,rax


def output(label,c,a,p,buf):
    n,emitted,nc,na,np,rax=relation(c,a,p)
    admitted=(n==0 or p+n<=len(buf))
    # Mathematical interval replacement is separate from the native store schedule.
    final=buf if not admitted or not n else buf[:p]+emitted[:n]+buf[p+n:]
    ac,aa,ap=(nc,na,np) if admitted else (c,a,p)
    fields=[label,str(n),emitted.hex(),f'{nc%2**32:08x}',f'{na:04x}',f'{np:016x}',f'{rax:016x}',
            'S' if admitted else 'E',f'{ac%2**32:08x}',f'{aa:04x}',f'{ap:016x}',
            f'{rax:016x}' if admitted else '-'*16,final.hex() or '-']
    return '\t'.join(fields)+'\n'


def cases():
    counters=[-2**31,-2**31+1,-129,-128,-9,-8,-1,0,1,6,7,8,9,15,16,17,18,23,24,25,255,256,2**31-2,2**31-1]
    accs=[0,1,0x7f,0x80,0xff,0x100,0x101,0x7fff,0x8000,0xabcd,0xff00,0xffff]
    contexts=[(0,0),(0,1),(0,2),(1,2),(1,3),(7,8),(7,9),(8,8),(9,8),(2**32,16),(MOD-2,16),(MOD-1,16)]
    i=0
    def row(c,a,p,size):
        nonlocal i
        i+=1
        return (f'case-{i:05d}',c,a,p,bytes((j*71+i*29)%256 for j in range(size)))
    for c in counters:
        for a in accs:
            for p,size in contexts: yield row(c,a,p,size)
    # Every possible low and high byte appears independently on all three paths.
    for b in range(256):
        for c in (7,8,16,17):
            yield row(c,b+256*((b*73+19)%256),3,8)
            yield row(c,((b*149+61)%256)+256*b,0,2)
    rng=random.Random(0x5494050)
    for i_random in range(4096):
        c=rng.randrange(-2**31,2**31)
        if i_random%4==0: c=rng.choice((7,8,15,16,17))
        p=rng.choice((rng.randrange(20),rng.getrandbits(64),MOD-1,MOD-2))
        yield row(c,rng.randrange(65536),p,rng.randrange(17))


def render():
    inputs=[];expected=[];coverage=Counter()
    for label,c,a,p,buf in cases():
        inputs.append(f'{label}\t{c%2**32:08x}\t{a:04x}\t{p:016x}\t{buf.hex() or "-"}\n')
        expected.append(output(label,c,a,p,buf))
        n,_,_,_,_,_=relation(c,a,p)
        coverage[f'emit_{n}']+=1
        coverage['apply_success' if n==0 or p+n<=len(buf) else 'apply_rejected']+=1
        if p+n>=MOD: coverage['project_position_wrap']+=1
        if c<0: coverage['negative_counter']+=1
        if c>16: coverage['above_16_counter']+=1
    return ''.join(inputs).encode(),''.join(expected).encode(),dict(sorted(coverage.items()))


def check():
    frozen=json.loads((HERE/'fixtures/freeze.json').read_text())
    inputs,expected,coverage=render()
    for name,raw in [('inputs.tsv',inputs),('expected.tsv',expected)]:
        if (HERE/'fixtures'/name).read_bytes()!=raw or sha(raw)!=frozen['sha256'][name]: raise ValueError('frozen fixture drift: '+name)
    if sha(Path(__file__).read_bytes())!=frozen['sha256']['oracle.py']: raise ValueError('oracle changed after freeze')
    if coverage!=frozen['coverage']: raise ValueError('coverage drift')
    return frozen


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--freeze',action='store_true');args=parser.parse_args()
    if args.freeze:
        if (ROOT/'src/node94-bit-writer-drain').exists(): raise ValueError('freeze must precede Rust source')
        if (HERE/'fixtures/freeze.json').exists(): raise ValueError('already frozen')
        inputs,expected,coverage=render()
        files={'inputs.tsv':inputs,'expected.tsv':expected}
        for name,raw in files.items(): (HERE/'fixtures'/name).write_bytes(raw)
        files['oracle.py']=Path(__file__).read_bytes()
        frozen={'target_sha256':TARGET,'cases':len(inputs.splitlines()),'coverage':coverage,
                'frozen_at_utc':datetime.now(timezone.utc).isoformat(),'rust_source_absent':True,
                'sha256':{name:sha(raw) for name,raw in files.items()}}
        (HERE/'fixtures/freeze.json').write_text(json.dumps(frozen,indent=2,sort_keys=True)+'\n')
        print(json.dumps(frozen,indent=2))
    else: print('PASS frozen oracle:',check()['cases'],'cases')
