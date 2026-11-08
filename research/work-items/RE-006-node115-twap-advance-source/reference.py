#!/usr/bin/env python3
"""Independent synthetic calendar and binary64 reference, no native execution."""
import datetime, hashlib, math, random, struct, sys
from pathlib import Path
out=Path(__file__).resolve().parents[3]/'src/node115-twap-advance/tests/reference-vectors.txt'
r=random.Random(1154264);rows=['# due_day due_s due_ns now_day now_s now_ns total filled counter duration_bits result_day result_s result_ns result_counter finish']
durations=[0.,60.,120.,300.,float('nan'),float('inf'),-1.,1e300]
for i in range(6000):
    d=r.randrange(1,3_000_000); datetime.date.fromordinal(d)
    sec=r.randrange(86400); ns=r.randrange(1_000_000_000)
    nd=max(1,min(3_500_000,d+r.randrange(-150000,150001))); datetime.date.fromordinal(nd)
    nsec=r.randrange(86400); nns=r.randrange(1_000_000_000)
    total=r.randrange(1,100000);filled=total if i%11==0 else r.randrange(total)
    counter=(2**64-1 if i%37==0 else r.randrange(12));duration=durations[i%len(durations)]
    current=(d*86400+sec)*1_000_000_000+ns+30_000_000_000
    now=(nd*86400+nsec)*1_000_000_000+nns
    if current<now:
        delta=now-current;whole=delta//1_000_000_000;part=delta%1_000_000_000
        delay=math.ceil((float(whole)+float(part)/1e9)/30.0)*30
        current+=min(delay*1_000_000_000,2**63-1)
    seconds,nano=divmod(current,1_000_000_000);day,seconds=divmod(seconds,86400)
    counter=min(counter+1,2**64-1)
    x=duration/60.0
    n=0 if not math.isfinite(x) or x<0 else min(int(x),2**64-1)
    count=min(2*n+1,2**64-1)
    finish=int(filled>=total or counter>count)
    bits=int.from_bytes(struct.pack('>d',duration),'big')
    rows.append(f'{d} {sec} {ns} {nd} {nsec} {nns} {total} {filled} {counter if counter==2**64-1 else counter-1} {bits:016x} {day} {seconds} {nano} {counter} {finish}')
data=('\n'.join(rows)+'\n').encode()
if '--write' in sys.argv:out.write_bytes(data)
else:
 assert out.read_bytes()==data
 print('6000 synthetic calendar and binary64 cases; sha256',hashlib.sha256(data).hexdigest())
