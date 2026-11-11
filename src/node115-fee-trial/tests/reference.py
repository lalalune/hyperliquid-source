#!/usr/bin/env python3
"""Independent decimal/list-state model; does not load captured code."""
from pathlib import Path
from decimal import Decimal
import random, struct, hashlib, math
r=random.Random(0x3c18390)
def bits(v):return struct.pack('>d',v).hex()
def unbits(v):return struct.unpack('>d',bytes.fromhex(v))[0]
def decimal_value(s):
    d=Decimal(s);sign,digits,exp=d.as_tuple();n=int(''.join(map(str,digits)));scale=max(0,-exp)
    den=10**scale;q,rem=divmod(n,den)
    if rem:
        z=(float(q)+float(rem)/float(den))*float(den)
        i=int(z);v=float(i+(z-i>=0.5))/float(den)
    else:v=float(q)
    return -v if sign and n else v
def floats(xs):return ','.join(bits(x) for x in xs)
def rows(xs):return ';'.join(floats(x) for x in xs) or '~'
def usertext(users):
    out=[]
    for k,u in sorted(users.items()):
        last='n' if u['last'] is None else str(u['last'])
        t=u['custom']
        text='n' if t is None else floats(t['active']+[t['volume']]+t['requested']+t['original'])+','+('n' if t['end'] is None else str(t['end']))+','+bits(t['tail'])
        out.append(f'{k}:{last}:{text}')
    return ';'.join(out) or '~'
def jan1(y):return 365*(y-1)+(y-1)//4-(y-1)//100+(y-1)//400+1
low,high=jan1(-262143),jan1(262143)-1
values=['0','-0','0.001','-0.0001','0.0005','0.002','0.01','+0.02','3.','0.000000000000001','-4.5']
lines=[];counts={}
for case in range(4500):
    fees=[r.choice(values) for _ in range(4)]
    if case%5==0:fees[3]=fees[1]
    requested=[decimal_value(x) for x in fees]
    now=r.choice([719163,730179,1,low,high-14,high-13,high,r.randrange(low+100,high-100)])
    user=r.choice([1,2,3,4,250,251])
    disabled=r.choices([0,1,2,255],[15,1,1,1])[0]
    defaults=[r.choice([-0.001,0.0,0.01,0.1,4.0]) for _ in range(4)]
    templates=[] if case%11==0 else [requested.copy()]
    alternatives=[]
    if case%4==0 and templates:
        templates[0][1]+=1;templates[0][3]+=1
        alternatives=[[r.random(),requested[1]]]
    if case%13==0:templates.append([requested[0],999,requested[2],999])
    discounts=r.choice([[],[[0,0],[100,0.25],[1000,0.5]],[[500,0.9],[0,-0.5]],[[0,1.0]],[[0,-0.25]]])
    users={}
    for k in [1,2,3,4,250,251]:
        if r.randrange(3):
            custom=None
            if r.randrange(2):
                custom=dict(active=[r.choice([-0.01,0.0,0.01,0.1,10.0]) for _ in range(4)],volume=r.choice([0.,100.,300.,1000.]),requested=[7.]*4,original=[8.]*4,end=719163 if case%9==0 else None,tail=2.5)
            users[k]=dict(last=r.choice([None,max(low,min(high,now-90)),max(low,min(high,now-89)),high]),custom=custom)
    affiliate=[r.choice([1,2,3,4,5,user]) for _ in range(r.randrange(5))]
    initial=usertext(users)
    special=user in [250,251]
    old=users.get(user,{}).get('custom') if not special else None
    original=([0.]*4 if special else defaults.copy()) if old is None else old['active'].copy()
    volume=0. if old is None else old['volume'];tail=(0. if special else 1.) if old is None else old['tail']
    active=old is not None and old['end'] is not None
    status=None
    if disabled or active:status=str(0x149+4*disabled)
    else:
        exact=any(t==requested for t in templates)
        prefix=any(t[0]==requested[0] and t[2]==requested[2] for t in templates)
        if not exact and not (prefix and any(t[1]==requested[1]==requested[3] for t in alternatives)):status=str(0x14a)
        last=users.get(user,{}).get('last')
        if status is None and last is not None:
            if not low<=last+90<=high:status='overflow'
            elif last+90>now:status=str(0x14c)
        if status is None and not low<=now+14<=high:status='overflow'
        if status is None:
            eligible=[]
            for row in discounts:
                if row[0]>volume:break
                eligible.append(row[1])
            discount=eligible[-1] if eligible else 0.
            adjusted=[v*(1.-discount) if v>0 else v for v in requested]
            if not any(a>b for a,b in zip(original,adjusted)):status=str(0x14b)
            else:
                trial=dict(active=[a if a<b else b for a,b in zip(original,adjusted)],volume=volume,requested=requested.copy(),original=original,end=now+14,tail=tail)
                for k in affiliate+[user]:
                    users.setdefault(k,dict(last=None,custom=None))['custom']=trial.copy()
                status=str(0x1a2)
    counts[status]=counts.get(status,0)+1
    lines.append('\t'.join([str(now),str(user),str(disabled),floats(defaults),rows(templates),rows(alternatives),rows(discounts),initial,','.join(fees),','.join(map(str,affiliate)) or '~',status,usertext(users)]))
state_data=('\n'.join(lines)+'\n').encode();Path(__file__).with_name('states.tsv').write_bytes(state_data)
decimals=[]
for s in ['0','-0','-0.00','1.','+2.5','99999999999999999','-9999999999999999','0.000000000000001']:
    decimals.append(s)
while len(decimals)<16000:
    n=str(r.randrange(10**r.randrange(1,17)));scale=r.randrange(len(n)+1)
    s=(n[:-scale] or '0')+'.'+n[-scale:] if scale else n
    s=r.choice(['','+','-'])+s
    if len(s)<=17:decimals.append(s)
decimal_data=('\n'.join(s+'\t'+bits(decimal_value(s)) for s in decimals)+'\n').encode()
Path(__file__).with_name('decimals.tsv').write_bytes(decimal_data)
print({'date_range':[low,high],'state_cases':len(lines),'outcomes':counts,'state_sha256':hashlib.sha256(state_data).hexdigest(),'decimal_cases':len(decimals),'decimal_sha256':hashlib.sha256(decimal_data).hexdigest()})
