#!/usr/bin/env python3
"""Independent integer model for one synthetic governance state transition."""
import hashlib,random
from pathlib import Path
r=random.Random(2237); lines=[]
for _ in range(8000):
    present=r.randrange(2); duplicate=r.randrange(2)
    end=(r.randrange(-2,3),r.randrange(3),r.randrange(3)); now=(r.randrange(-2,3),r.randrange(3),r.randrange(3))
    marker=(r.randrange(-2,3),r.randrange(3),r.randrange(3))
    marker_present=r.randrange(2); a=r.choice([0,1,3,(1<<62)-1,1<<62,(1<<64)-1]);b=r.choice([0,1,2])
    total=a+b;status=0x114 if not present else 0x117 if now>end else 0x115 if duplicate else 0x116 if total==0 or total >= 1<<64 else 0x1a2
    amount=total; marker_first=marker[0]
    if status==0x1a2 and marker_present and marker_first!=0:
        if now<marker:
            if amount < 1<<62: amount*=4
        else: marker_first=0
    fields=[present,duplicate,*end,*now,marker_present,*marker,a,b,status,amount if status==0x1a2 else 0,marker_first]
    lines.append(' '.join(map(str,fields))+'\n')
out=Path(__file__).with_name('reference-vectors.txt');out.write_text(''.join(lines));print(len(lines),hashlib.sha256(out.read_bytes()).hexdigest())
