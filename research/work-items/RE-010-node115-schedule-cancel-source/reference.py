#!/usr/bin/env python3
"""Arbitrary-precision timer/state reference; no captured target execution."""
from pathlib import Path
import hashlib,json,random,struct,sys
U=(1<<64)-1
Y=262142-1
MAXDAY=365*Y+Y//4-Y//100+Y//400+365
MAXMS=(MAXDAY-719163)*86400000+86399999
MAXNS=MAXMS*1000000+999999

def bits(v):return struct.unpack('<Q',struct.pack('<d',v))[0]
def calc(x,wrong_inclusive=False,wrong_gate=False,wrong_reset=False):
    now,extra,requested,exists,count,old,p0,q0,p1,q1,ps,qs,mask,poll,reset=x
    scaled=min(U,sum(v for n,v in enumerate((p0,p1,ps)) if mask>>n&1))
    raw=min(U,sum(v for n,v in enumerate((q0,q1,qs)) if mask>>n&1))
    tag=0x1a2;report=0
    deadline=old if exists else -1;count=count if exists else 0
    if scaled<100000000 and not (wrong_gate and requested<0):tag=0x11d;report=bits(scaled/100.0)
    elif requested<0:deadline=-1
    elif requested>MAXMS:tag=0x89
    elif requested*1000000 < min(MAXNS,now*1000000+extra+5000000000)+(0 if wrong_inclusive else 1):tag=0x11b
    elif count>9:tag=0x11c
    else:exists=1;deadline=requested
    admitted=(exists,count,deadline)
    due=int(exists and deadline>=0 and deadline<=poll)
    if due:count=min(U,count+1);deadline=-1
    if reset:
        count=0
        if deadline<0 and not wrong_reset:exists=0
    return (scaled,raw,tag,report,*admitted,due,exists,count if exists else 0,deadline if exists else -1)

def main():
    rng=random.Random(11521384128);rows=["# now_ms extra_nanos requested_ms(-1=None) exists count old_ms p0 q0 p1 q1 spot raw mask poll_ms reset | sum0 sum1 tag report_bits request_exists request_count request_deadline due final_exists final_count final_deadline"]
    statuses={};controls={'deadline_equality_allowed':0,'clearing_bypasses_volume':0,'reset_retains_inactive':0}
    for i in range(14000):
        now=rng.choice([0,86399999,946684799999,951868799999,MAXMS-6000,MAXMS-4999,MAXMS,rng.randrange(MAXMS+1)])
        extra=rng.choice([0,1,999999]);requested=rng.choice([-1,0,min(MAXMS,now+4999),min(MAXMS,now+5000),min(MAXMS,now+5001),min(MAXMS,now+30000),MAXMS,MAXMS+1,U])
        exists=int(i%4!=0);count=rng.choice([0,1,8,9,10,U]);old=rng.choice([-1,max(0,now-1),now,min(MAXMS,now+30000)])
        p0,p1,ps=[rng.choice([0,1,49999999,50000000,99999999,100000000,U]) for _ in range(3)]
        q0,q1,qs=[rng.choice([0,1,U,rng.randrange(U+1)]) for _ in range(3)]
        mask=rng.randrange(8);poll=min(MAXMS,now+rng.choice([0,5000,30000,60000]));reset=i%3==0
        x=(now,extra,requested,exists,count,old,p0,q0,p1,q1,ps,qs,mask,poll,int(reset));y=calc(x)
        statuses[hex(y[2])]=statuses.get(hex(y[2]),0)+1
        for k,kw in [('deadline_equality_allowed',{'wrong_inclusive':True}),('clearing_bypasses_volume',{'wrong_gate':True}),('reset_retains_inactive',{'wrong_reset':True})]:controls[k]+=calc(x,**kw)!=y
        rows.append(' '.join(map(str,x))+' | '+' '.join(map(str,y)))
    data=('\n'.join(rows)+'\n').encode();out=Path(__file__).resolve().parents[3]/'src/node115-schedule-cancel/tests/reference-vectors.txt'
    if '--write' in sys.argv:out.write_bytes(data)
    else:assert out.read_bytes()==data
    assert all(controls.values()),controls
    print(json.dumps({'cases':14000,'request_tags':statuses,'controls_differing':controls,'fixture_sha256':hashlib.sha256(data).hexdigest(),'method':'Synthetic arbitrary-precision calendar/integer state model, not native execution'},indent=2))
if __name__=='__main__':main()
