#!/usr/bin/env python3
"""Arbitrary-precision reference; no target execution or emulation."""
from pathlib import Path
import random,hashlib
r=random.Random(0x44831a0)
U=(1<<64)-1;I=(1<<63)-1
rows=[];counts={};branches={'base':0,'adjusted':0}
for case in range(12000):
    user=int(case%13!=0);asset=int(case%11!=0)
    aggregate=r.choice([0,1,U,U-1]) if case%3==0 else r.randrange(1<<50)
    size=r.choice([-(1<<63),I,0,1,-1]) if case%5==0 else r.randrange(-1000,1001)
    price=r.choice([0,1,I,I-1,U]) if case%5==0 else r.randrange(1000)
    if case%5==0:
        values=[r.choice([0,1,I,I-1,U,U-1]) for _ in range(2)]
        qtys=[r.choice([0,1,I,I-1,U,U-1]) for _ in range(2)]
    else:
        values=[r.randrange(100000000) for _ in range(2)]
        qtys=[r.randrange(100000) for _ in range(2)]
    old=r.choice([0,1,2,3,5,10,20,(1<<32)-1]);new=r.choice([0,1,2,3,5,10,20,(1<<32)-1])
    status='ok';out=aggregate;lev=old
    if user and asset and old!=new:
        side=0 if size>0 else 1;base=values[side];n=values[1-side];q=qtys[1-side]
        selected=base;notional=abs(size)*price
        if q and q<=n and notional<=I-1:
            dq=q-min(U,2*abs(size));dn=n-2*notional
            candidate=(n//q)*dq
            if dq>=0 and dn>=0 and candidate<=I-1:
                selected=max(base,min(dn,candidate))
        branches['adjusted' if selected>base else 'base']+=1
        if old==0:status='oldzero'
        else:
            before=selected//old;lev=new
            if new==0:status='newzero'
            else:out=min(U,max(0,aggregate-before)+selected//new)
    counts[status]=counts.get(status,0)+1
    rows.append('\t'.join(map(str,[user,asset,aggregate,price,*values,*qtys,size,old,new,status,out,lev])))
raw=('\n'.join(rows)+'\n').encode();Path(__file__).with_name('reference.tsv').write_bytes(raw)
print({'cases':len(rows),'outcomes':counts,'selection':branches,'sha256':hashlib.sha256(raw).hexdigest()})
