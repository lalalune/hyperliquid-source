#!/usr/bin/env python3
"""Independent Gregorian/native-integer and keyed-state reference, never target execution."""
from pathlib import Path
import hashlib,random
r=random.Random(0x3c17590);rows=[];counts={};successful=0
for case in range(8000):
    year=r.choice([-262143,-400,-100,-1,0,1,4,100,400,1969,1970,2000,262142]) if case%3==0 else r.randrange(-262143,262143)
    leap=year%4==0 and (year%100!=0 or year%400==0)
    ordinal=r.randrange(1,367 if leap else 366);y=year-1
    days=365*y+y//4-y//100+y//400+ordinal
    seconds=r.choice([0,1,86399,r.randrange(86400)]);nanos=r.choice([0,999999,1000000,999999999,r.randrange(1000000000)])
    # Transcribe the native inline calendar arithmetic independently of CE-days.
    prior=year-1;cycle=0
    if year<=0:
        cycles=((1-year)*0x51eb851f>>39)+1
        prior+=400*cycles;cycle=-146097*cycles
    century=prior//100
    native_day=(ordinal+cycle-century+(prior*1461>>2)+(century>>2)-719163)
    assert native_day==days-719163
    millis=max(0,(native_day*86400+seconds)*1000+nanos//1000000)
    ue=int(r.randrange(4)!=0);us=int(r.randrange(4)==0);ce=int(r.randrange(10)!=0);same=int(r.randrange(10)==0);re=int(r.randrange(8)!=0)
    period=r.choice([0,1,1000,86400000,(1<<64)-1,r.getrandbits(64)])
    bucket=millis//period if period and case%2==0 else r.getrandbits(64)
    rem=r.choice([0,1,2,999,(1<<64)-1,r.getrandbits(64)]);quota=r.choice([0,1,999,1000,1001,(1<<64)-1,r.getrandbits(64)])
    history=int(r.randrange(2));oute=ue;outs=1 if ue and us else 0;outb=bucket;outr=rem;hn=0
    if not ce:status=0xa6
    elif same:status=0xa2
    else:
        oute=1
        if ue and us:status=0xa3
        elif not re:status=0x1a2
        elif not period:status=0xa5
        else:
            b=millis//period
            if b==bucket and rem==0:status=0xa5
            else:
                if b!=bucket:outb=b;outr=max(1000,quota)
                outr-=1;hn=1;outs=2;status=0x1a2;successful+=1
    counts[status]=counts.get(status,0)+1
    rows.append('\t'.join(map(str,[ue,us,ce,same,re,period,bucket,rem,quota,days,seconds,nanos,history,status,oute,outs,outb,outr,hn])))
raw=('\n'.join(rows)+'\n').encode();Path(__file__).with_name('reference.tsv').write_bytes(raw)
print({'cases':len(rows),'statuses':counts,'assignments':successful,'sha256':hashlib.sha256(raw).hexdigest()})
