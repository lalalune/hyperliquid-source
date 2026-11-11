#!/usr/bin/env python3
"""Independent list-state reference; never loads or executes native code."""
import hashlib
import random
from pathlib import Path

r = random.Random(0x3C3D480)
rows = []
counts = {}
empty = lambda xs: ';'.join(xs) or '-'

def encode(s):
    return '|'.join([
        empty(f'{k}:'+','.join(map(str,v)) for k,v in sorted(s['b'])),
        empty(f'{k}:{v}:{p}' for k,v,p in sorted(s['v'])),
        empty(f'{k}:'+','.join(map(str,v)) for k,v in sorted(s['a'])),
        empty(f'{k}:'+','.join(map(str,v)) for k,v in sorted(s['t'])),
        empty(f'{k}:{p}' for k,p in s['h']),
        empty(map(str, sorted(s['s']))),
        empty(f'{k}:{h}:{a}' for k,h,a in sorted(s['f'])),
    ])

for case in range(160):
    s = dict(b=[],v=[],a=[],t=[],h=[],s=[],f=[])
    for k in range(1,11):
        if r.randrange(3):
            s['b'].append((k,[r.getrandbits(64) for _ in range(4)]+[r.choice([0,0,0,1,(1<<64)-1])]))
        if r.randrange(5): s['v'].append((k,r.randrange(1,12),r.randbytes(4).hex()))
        if r.randrange(2): s['a'].append((k,[r.getrandbits(64) for _ in range(2)]))
        if r.randrange(2): s['t'].append((k,[r.getrandbits(64) for _ in range(3)]))
        if r.randrange(2): s['s'].append(k)
        if r.randrange(2): s['f'].append((k,r.getrandbits(64),r.randrange(1,12)))
    for _ in range(r.randrange(6)):
        s['h'].append((r.getrandbits(64),r.randbytes(3).hex()))
    rows.append('I\t'+encode(s))
    for _ in range(25):
        key = r.randrange(1,13)
        blocked = next((v[4] for k,v in s['b'] if k==key),0)
        found = next((row for row in s['v'] if row[0]==key),None)
        if blocked: status=0x144
        elif found is None: status=0x95
        else:
            status=0x1a2
            related=found[1]
            s['a']=[row for row in s['a'] if row[0]!=key]
            s['v']=[row for row in s['v'] if row[0]!=key]
            s['t']=[row for row in s['t'] if row[0]!=key]
            history=s['h'][-1][0] if s['h'] else 0
            if related not in s['s']: s['s'].append(related)
            s['f']=[row for row in s['f'] if row[0]!=related]+[(related,history,key)]
        counts[status]=counts.get(status,0)+1
        rows.append(f'A\t{key}\t{status}\t'+encode(s))

data=('\n'.join(rows)+'\n').encode()
Path(__file__).with_name('reference.tsv').write_bytes(data)
print({'scenarios':160,'actions':4000,'outcomes':counts,'sha256':hashlib.sha256(data).hexdigest()})
