#!/usr/bin/env python3
"""Independent list-backed synthetic relation model."""
import random, hashlib
from pathlib import Path
r=random.Random(2126);lines=[]
for scenario in range(200):
    staked={i for i in range(8) if r.randrange(2)}; links={}
    for _ in range(30):
        p=r.randrange(8);c=r.randrange(8);mode=r.choice([0,0,1,2,255]);before=dict(links)
        if mode==0:
            a,b=p,c
            if a not in staked: result=1
            elif a==b: result=2
            elif b in links and links[b][0]!=0: result=3
            elif a in links and links[a][0]!=0: result=4
            else: result=0;links[b]=(0,a)
        else:
            a,b=c,p
            if b not in links or links[b]!=(0,a): result=5
            elif a in links and links[a][0]!=0: result=4
            else: result=0;links[b]=(1,a);links[a]=(2,b)
        lines.append(f'{scenario} {p} {c} {mode} {result} '+(','.join(str(v) for v in sorted(staked)) or '-')+' '+(','.join(f'{k}:{v[0]}:{v[1]}' for k,v in sorted(links.items())) or '-')+'\n')
out=Path(__file__).with_name('reference-vectors.txt');out.write_text(''.join(lines));print(len(lines),hashlib.sha256(out.read_bytes()).hexdigest())
