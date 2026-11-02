#!/usr/bin/env python3
"""Independent finite-observation oracle, authored before node115 Rust adaptation.

Fold uses the least terminal index and an error-owner list, not a simulated
instruction loop. Stage admission uses ordered failed predicates. No target
code, instruction interpreter, Rust source or expected-file input is used.
"""
import argparse
import gzip
import hashlib
import itertools
import json
from pathlib import Path
import random

HERE = Path(__file__).resolve().parent
MASK = (1 << 64) - 1
S, T = 46, 47


def cleanup(record):
    offsets = {16: (8, 32), 19: (8,), 32: (8,)}.get(record[0], ())
    pairs = [(int.from_bytes(record[i+8:i+16], 'little'),
              int.from_bytes(record[i:i+8], 'little')) for i in offsets]
    return [(p, n, 0) for p, n in pairs if n]


def drops_text(drops):
    return ','.join(':'.join(map(str, d)) for d in drops) or '-'


def solve(line):
    p = line.split('\t'); kind = p[0]
    if kind == 'M':
        seed, left, right = map(bytes.fromhex, p[1:])
        failures = [i for i, r in enumerate((left, right)) if r[0] != S]
        choice = failures[0] if failures else 2
        result = (left, right)[choice] if failures else bytes([S]) + seed[1:]
        drops = cleanup(right) if len(failures) == 2 else []
        return '\t'.join((result.hex(), str(choice), drops_text(drops), 'O'+'D'*len(drops)))
    if kind == 'F':
        folder = bytes.fromhex(p[1]); start, stride = map(int, p[2:4])
        rows = [] if p[4] == '-' else list(map(bytes.fromhex, p[4].split(',')))
        cancel = bytes.fromhex(p[5]) if p[5] != '-' else b''
        terminals = [(i, 1 if row[0] == T else 2 if folder[0] != S or row[0] != S else 3)
                     for i, row in enumerate(rows)
                     if row[0] == T or folder[0] != S or row[0] != S or cancel[i] != 0]
        end, reason = (terminals[0][0]+1, terminals[0][1]) if terminals else (len(rows), 0)
        processed = rows[:end - int(reason == 1)]
        owners = [folder[:72]] * int(folder[0] != S) + [r for r in processed if r[0] != S]
        chosen = owners[0] if owners else folder[:72]
        result = chosen + folder[72:]
        writes = int(bool(processed) and bool(owners))
        reads = len(processed) - writes
        dropped = cleanup(owners[1]) if len(owners) > 1 else []
        trace = 'CSR' * reads
        if writes:
            trace += 'C'+'D'*len(dropped)+'WS'
        if reason == 1:
            trace += 'C'
        trace += 'O'
        return '\t'.join((result.hex(),str(end),str(reads),str(writes),str(reason),
                           str((start+stride*end)&MASK),drops_text(dropped),trace))
    if kind == 'P':
        stride, cancel, logical, count, migrated, budget, minimum, workers, start = map(int,p[1:])
        h = logical // 2
        local = h < minimum or (migrated == 0 and budget == 0)
        region = 0 if cancel else 1 if local else 3 if count < h else 2
        observed = int(not cancel and h >= minimum and migrated != 0)
        nb = max(budget//2, workers) if observed else budget//2
        row = {0: (0,0,0,0,0,0),
               1: (h,0,0,0,(start+stride*count)&MASK,0),
               2: (h,nb,(count-h)&MASK,(start+stride*h)&MASK,0,observed),
               3: (h,nb,0,0,0,observed)}[region]
        return '\t'.join(map(str,(region,)+row))
    if kind == 'C':
        prefix=bytes.fromhex(p[1]); cert,value=map(int,p[2:4]); key=bytes.fromhex(p[4])
        valaddr,keyaddr,snapshot,heap,al,out=map(int,p[5:11]); seed=bytes.fromhex(p[11])
        initialized = prefix + cert.to_bytes(8,'little') + value.to_bytes(8,'little') + key
        tag = {False:9,True:46}[al != 0]
        return '\t'.join((initialized.hex(),(bytes([tag])+seed[1:]).hex(),
                           ':'.join(map(str,(2,heap,keyaddr,(valaddr+8)&MASK,snapshot))),str(out)))
    if kind == 'A':
        seed,hist,col,nested,parallel=map(bytes.fromhex,p[1:6])
        rows=[] if p[6]=='-' else list(map(int,p[6].split(',')))
        wanted,round_,quorum,out=map(int,p[7:])
        maximum=max(rows) if rows else None
        failures=(hist[0]!=S,col[0]!=S,not rows,
                  bool(rows) and (maximum!=wanted or maximum>=round_),
                  quorum==0,nested[0]!=S)
        stop=next((i for i,f in enumerate(failures) if f),6)
        selected={0:hist,1:col,2:bytes([8])+seed[1:],3:bytes([11])+seed[1:],
                  4:bytes([8])+seed[1:],5:nested,6:parallel}[stop]
        stages=('H','HC','HCI','HCI','HCIQ','HCIQN','HCIQNVP')[stop]
        drop=int(stop>=2)
        return '\t'.join((selected.hex(),stages+('D' if drop else ''),str(drop),str(out)))
    if kind == 'E':
        representation, capacity, count, start, workers, tls0, tls1, tls_pool, global_pool = map(int,p[1:])
        if representation:
            route = 0 if tls0 or (tls1 and tls_pool==global_pool) else 1 if not tls1 else 2
            return '\t'.join(map(str,(1,0,route,int(tls0==0),0,0,0,0)))
        bad=capacity<count
        return '\t'.join(map(str,(0,0,3 if bad else 4,int(not bad),
                                     0 if bad else count,0 if bad else workers,
                                     0 if bad else start,0 if bad else (capacity*16)&MASK)))
    raise ValueError('unknown category')


def corpus():
    r=random.Random(0x115564c120)
    def image(n,tag=None):
        b=bytearray(r.randbytes(n))
        if tag is not None: b[0]=tag
        return b
    def record(tag):
        b=image(72,tag)
        for off in (8,32):
            b[off:off+8]=r.choice((0,1,8,255,1<<63,MASK)).to_bytes(8,'little')
        return b
    def line(k,*args): return '\t'.join([k]+[x.hex() if isinstance(x,(bytes,bytearray)) else str(x) for x in args])
    tags=(0,9,16,19,32,46,47,255)
    for a,b in itertools.product(range(256),tags):
        yield line('M',image(72),record(a),record(b))
    for tag in tags:
        for ts in itertools.product(tags,repeat=3):
            rows=[record(t) for t in ts]
            cancellation=bytes(r.choice((0,0,0,1,128,255)) for _ in rows)
            yield line('F',image(88,tag),r.getrandbits(64),r.choice((16,104)),
                       ','.join(x.hex() for x in rows),cancellation)
    for _ in range(1000):
        n=r.randrange(17); rows=[record(r.choice((46,46,46,9,16,19,32,47,255))) for _ in range(n)]
        yield line('F',image(88,r.choice(tags)),r.getrandbits(64),r.choice((16,104)),
                   ','.join(x.hex() for x in rows) or '-',bytes(r.choice((0,0,0,1,255)) for _ in rows) or '-')
    edge=(0,1,2,3,4,7,8,15,16,17,1<<32,(1<<63)-1,1<<63,MASK-1,MASK)
    for i in range(4000):
        logical=r.choice(edge) if i<2500 else r.getrandbits(64); h=logical//2
        count=r.choice((0,h-1 if h else 0,h,min(h+1,MASK),logical,MASK))
        minimum=r.choice((0,1,h,h+1,MASK)); budget=r.choice(edge); workers=r.choice(edge)
        yield line('P',r.choice((16,104)),r.choice((0,0,0,1,128,255)),logical,count,
                   r.choice((0,0,1,128,255)),budget,minimum,workers,r.choice(edge))
    for al in range(256):
        for _ in range(3):
            yield line('C',image(16),r.getrandbits(64),r.getrandbits(64),image(20),
                       r.getrandbits(64),r.getrandbits(64),r.getrandbits(64),r.getrandbits(64),al,
                       r.getrandbits(64),image(72))
    for i in range(2500):
        n=r.randrange(9); rows=[r.choice(edge) for _ in range(n)]; maximum=max(rows) if rows else 0
        wanted=r.choice((maximum,maximum,r.getrandbits(64))); round_=r.choice((maximum,min(maximum+1,MASK),MASK))
        ts=[r.choice((S,S,S,9,11,16,19,32,255)) for _ in range(4)]
        yield line('A',image(72),*(record(t) for t in ts),','.join(map(str,rows)) or '-',
                   wanted,round_,r.choice((0,1,128,255)),r.getrandbits(64))
    for _ in range(1000):
        cap=r.choice(edge); count=r.choice((0,cap,min(cap+1,MASK),MASK)); pool=r.getrandbits(64)
        yield line('E',r.choice((0,0,1,1<<63,MASK)),cap,count,r.getrandbits(64),r.choice(edge),
                   r.choice((0,0,r.getrandbits(64))),r.choice((0,0,r.getrandbits(64))),r.choice((pool,r.getrandbits(64))),pool)


def generate():
    lines=list(corpus()); inputs=('\n'.join(lines)+'\n').encode()
    expected=('\n'.join(solve(s) for s in lines)+'\n').encode()
    return inputs, expected


if __name__=='__main__':
    p=argparse.ArgumentParser(); p.add_argument('--freeze',action='store_true'); args=p.parse_args()
    a,b=generate()
    if args.freeze:
        for name,data in (('inputs.tsv.gz',a),('expected.tsv.gz',b)):
            path=HERE/name
            if path.exists(): raise SystemExit('freeze already exists')
            path.write_bytes(gzip.compress(data,mtime=0))
    else:
        for name,data in (('inputs.tsv.gz',a),('expected.tsv.gz',b)):
            if gzip.decompress((HERE/name).read_bytes())!=data: raise SystemExit('frozen oracle mismatch')
    print(json.dumps({'cases':len(a.splitlines()),'inputs_sha256':hashlib.sha256(a).hexdigest(),
                      'expected_sha256':hashlib.sha256(b).hexdigest()},indent=2))
