#!/usr/bin/env python3
"""Independent arbitrary-integer/binary64 reference; never executes captured code."""
import hashlib, math, random, struct
from pathlib import Path
r=random.Random(0x4205370)
LO=-(1<<63); HI=(1<<63)-1
sat=lambda x:max(LO,min(HI,x))
bits=lambda x:struct.pack('>d',x).hex()
f64=lambda x:struct.unpack('>d',bytes.fromhex(x))[0]
rate_values=[0.,-0.,.0001,-.0001,.125,-.125,1.,-1.,1e300,-1e300,float('inf'),-float('inf'),float('nan')]
rate_bits=[bits(x) for x in rate_values]+['7ff0000000000001','fff800000000beef']
def encode_positions(p):
    return ';'.join(','.join(map(str,[k]+v)) for k,v in sorted(p.items())) or '-'
def run(p,rates,prices,cross,time):
    records=[];error='ok'
    for key,v in sorted(p.items()):
        rate=rates.get(key)
        if rate is None or f64(rate)==0:continue
        idx=key%10000
        if idx>=len(prices):error=f'index:{key}';break
        if v[2]==0:continue
        price=prices[idx];notional=price*v[2]
        if price>HI or not LO<=notional<=HI:error=f'range:{key}';break
        if not time:continue
        product=float(notional)*f64(rate)
        converted=sat(math.trunc(product)) if math.isfinite(product) else 0
        payment=sat(-converted);charge=-payment
        if v[0]:v[1]=sat(v[1]-charge)
        else:cross=sat(cross-charge)
        v[3:]=[sat(x+charge) for x in v[3:]]
        records.append((key,payment,v[2],rate,notional))
    total=0;largest=None
    if error=='ok':
        for i,record in enumerate(records):
            key,payment,_,_,notional=record
            total=payment if i==0 else sat(total+payment)
            if largest is None or abs(notional)>largest[1]:largest=(key,abs(notional))
    else:records=[]
    return error,cross,records,total,largest
rows=[];counts={};record_count=0
for case in range(7000):
    keys=sorted(r.sample([0,1,2,3,4,10000,10001,20002,30003,(1<<64)-1],r.randrange(8)))
    prices=[r.choice([0,1,2,10,100,100000,HI,1<<63,(1<<64)-1]) if case%5==0 else r.randrange(1,10000000) for _ in range(r.randrange(9))]
    edges=[LO,LO+1,HI,0,1,-1]
    p={k:[r.choice([0,0,1,255]),r.choice(edges) if case%3==0 else r.randrange(-100000000,100000000),r.choice([0,LO,HI,-1,1]) if case%5==0 else r.randrange(-10000,10000),*[r.choice(edges) if case%3==0 else r.randrange(-100000000,100000000) for _ in range(3)]] for k in keys}
    rates={k:r.choice(rate_bits) if case%2==0 else bits(r.uniform(-.1,.1)) for k in keys if r.randrange(5)}
    cross=r.choice(edges) if case%3==0 else r.randrange(-100000000,100000000)
    time=int(case%4!=0);original=encode_positions(p)
    error,out,records,total,largest=run(p,rates,prices,cross,time)
    counts[error.split(':')[0]]=counts.get(error.split(':')[0],0)+1;record_count+=len(records)
    rows.append('\t'.join([str(time),str(cross),','.join(map(str,prices)) or '-', ';'.join(f'{k},{v}' for k,v in sorted(rates.items())) or '-',original,error,str(out),encode_positions(p),';'.join(','.join(map(str,x)) for x in records) or '-',str(total),','.join(map(str,largest)) if largest else '-']))
raw=('\n'.join(rows)+'\n').encode();Path(__file__).with_name('reference.tsv').write_bytes(raw)
print({'cases':len(rows),'outcomes':counts,'records':record_count,'sha256':hashlib.sha256(raw).hexdigest()})
