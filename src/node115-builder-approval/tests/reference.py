#!/usr/bin/env python3
"""Independent list-based mutation reference; no captured code execution."""
from pathlib import Path
import random,hashlib
r=random.Random(0x3c1a510);out=[];count={};total_steps=0
# IDs map to 20-byte addresses whose last eight bytes contain the ID big-endian.
for case in range(142):
    initial=case%71
    # Keep list ownership/insertion order here; Rust uses sorted keyed maps.
    users={1:[(i+10,100+i) for i in range(initial)]}
    out.append(f'I\t{initial}')
    for step in range(40):
        user=r.choice([1,1,1,2,3]);builder=r.choice([10,11,19,20,80,100,r.randrange(10,100)])
        fee=0 if step%3==0 or r.randrange(4)==0 else r.choice([1,(1<<64)-1,r.getrandbits(64)])
        rows=users.setdefault(user,[]);status=0x1a2
        index=next((i for i,(k,_) in enumerate(rows) if k==builder),None)
        if fee==0:
            if index is not None:rows.pop(index)
        elif len(rows)>10:status=0x13c
        elif index is None:rows.append((builder,fee))
        else:rows[index]=(builder,fee)
        def encode():
            return ';'.join(str(u)+':'+(','.join(f'{k}={v}' for k,v in sorted(x)) or '-') for u,x in sorted(users.items()))
        out.append('\t'.join(map(str,['A',user,builder,fee,status,encode()])))
        total_steps+=1;count[status]=count.get(status,0)+1
raw=('\n'.join(out)+'\n').encode();Path(__file__).with_name('reference.tsv').write_bytes(raw)
print({'scenarios':142,'actions':total_steps,'outcomes':count,'sha256':hashlib.sha256(raw).hexdigest()})
