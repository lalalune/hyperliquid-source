#!/usr/bin/env python3
"""Independent flat-relation oracle and fixed input-only frames, never target code."""
from __future__ import annotations
import copy
import gzip
import hashlib
import itertools
import json
import random
import struct

MIN=-(1<<63);MAX=(1<<63)-1;UMAX=(1<<64)-1


def bound(x):
    return max(MIN,min(MAX,x))


def address(n):
    return n.to_bytes(20,'big').hex()


def row(seed,sentinel=1):
    raw=bytearray(hashlib.sha256(str(seed).encode()).digest()*3)[:72]
    raw[60:64]=sentinel.to_bytes(4,'little')
    return raw.hex()


def position(asset=7,mode=0,size=1,margin=19,leverage=3):
    return dict(asset=asset,mode=mode,size=size,margin=margin,leverage=leverage)


def user(key=1,balance=30,count=1,positions=None):
    return dict(address=address(key),balance=balance,count=count,positions=positions if positions is not None else [position()])


def summary(key=1,total=1,selection=(7,1),records=None):
    return dict(address=address(key),total=total,selection=list(selection) if selection is not None else None,
                records=records if records is not None else [row(key)])


def state(users=None,aru=None,aux=None,with_positions=None):
    return dict(users=users if users is not None else [user()],aru=aru if aru is not None else [],
                aux=aux if aux is not None else [],with_positions=with_positions if with_positions is not None else [address(1)])


def canon_state(value):
    result=copy.deepcopy(value);result['users'].sort(key=lambda x:x['address'])
    for u in result['users']:u['positions'].sort(key=lambda x:x['asset'])
    result['aru'].sort();result['aux'].sort(key=lambda x:x[0]);result['with_positions'].sort()
    return result


def counts_ok(summaries,records):
    # Native provenance, not Rust element layout/capacity equivalence.
    return 0<=summaries<=MAX//104 and summaries<=MAX//80 and 0<=records<=MAX//72


def oracle(case):
    if case['kind']=='counts':
        return dict(accepted=counts_ok(case['summary_count'],case['record_count']))
    original=canon_state(case['state']);rows=sorted(case['summaries'],key=lambda x:x['address'])
    def reject(tag):return dict(status=tag,state=original)
    if len({x['address'] for x in rows})!=len(rows):return reject('duplicate_summary')
    if not counts_ok(len(rows),sum(len(x['records']) for x in rows)):return reject('span')
    total=0
    for s in rows:total=bound(total+s['total'])
    selected=[s for s in rows if s['selection'] is not None]
    # Flat stable ordering formulation, deliberately not native paired scan.
    winner=sorted(selected,key=lambda s:(-s['selection'][1],s['address']))[:1]
    winner=(dict(address=winner[0]['address'],asset=winner[0]['selection'][0],magnitude=winner[0]['selection'][1]) if winner else None)
    flattened=[]
    for s in rows:
        sentinels=[i for i,r in enumerate(s['records']) if int.from_bytes(bytes.fromhex(r)[60:64],'little')==0]
        flattened.extend(s['records'][:min(sentinels)] if sentinels else s['records'])
    result=copy.deepcopy(original)
    if total and winner:
        users=[u for u in result['users'] if u['address']==winner['address']]
        if not users:return reject('missing_user')
        u=users[0];positions=[p for p in u['positions'] if p['asset']==winner['asset']]
        if not positions:return reject('missing_position')
        p=positions[0]
        if p['size']==MIN:return reject('size_magnitude')
        result['aru']=sorted(set(result['aru'])|{winner['address']})
        if p['mode']==1:p['margin']=bound(p['margin']-total)
        else:u['balance']=bound(u['balance']-total)
        # Closed algebraic relation, not the two-step source/native implementation.
        old=[v for a,v in result['aux'] if a==winner['asset']]
        value=max(old[0] if old else 0,MIN+abs(p['size']))
        result['aux']=[x for x in result['aux'] if x[0]!=winner['asset']]+[[winner['asset'],value]]
    return dict(status='ok',total=total,winner=winner,records=flattened,state=canon_state(result))


class Frame:
    def __init__(self):self.data=bytearray()
    def n(self,fmt,value):self.data.extend(struct.pack('<'+fmt,value))
    def raw(self,value):self.data.extend(bytes.fromhex(value))


def encode_state(f,s):
    s=canon_state(s);f.n('I',len(s['users']))
    for u in s['users']:
        f.raw(u['address']);f.n('q',u['balance']);f.n('Q',u['count']);f.n('I',len(u['positions']))
        for p in u['positions']:
            for fmt,k in [('Q','asset'),('I','mode'),('I','leverage'),('q','margin'),('q','size')]:f.n(fmt,p[k])
    for key in ['aru','aux','with_positions']:
        f.n('I',len(s[key]))
        for x in s[key]:
            if key=='aux':f.n('Q',x[0]);f.n('q',x[1])
            else:f.raw(x)


def input_frame(case):
    f=Frame();f.n('B',1)
    if case['kind']=='counts':
        f.n('B',1);f.n('Q',case['summary_count']);f.n('Q',case['record_count']);return bytes(f.data)
    f.n('B',0);f.n('I',len(case['summaries']))
    for s in case['summaries']:
        f.raw(s['address']);f.n('q',s['total']);f.n('B',int(s['selection'] is not None))
        if s['selection'] is not None:f.n('Q',s['selection'][0]);f.n('Q',s['selection'][1])
        f.n('I',len(s['records']))
        for r in s['records']:f.raw(r)
    encode_state(f,case['state']);return bytes(f.data)


def expected_frame(case):
    out=oracle(case);f=Frame();f.n('B',1)
    if case['kind']=='counts':f.n('B',1);f.n('B',int(out['accepted']));return bytes(f.data)
    f.n('B',0);tag=['ok','duplicate_summary','span','missing_user','missing_position','size_magnitude'].index(out['status']);f.n('B',tag)
    if tag==0:
        f.n('q',out['total']);w=out['winner'];f.n('B',int(w is not None))
        if w is not None:f.raw(w['address']);f.n('Q',w['asset']);f.n('Q',w['magnitude'])
        f.n('I',len(out['records']))
        for r in out['records']:f.raw(r)
    encode_state(f,out['state']);return bytes(f.data)


def cases():
    out=[]
    def add(name,summaries=None,st=None,domain='native_corresponding'):
        out.append(dict(name=name,kind='apply',domain=domain,summaries=summaries if summaries is not None else [summary()],state=st if st is not None else state()))
    add('empty',[],state(users=[],with_positions=[]))
    for mode in [0,1,2,3,255,256,0x80000000,0xffffffff]:
        for total in [MIN,MIN+1,-1,0,1,MAX-1,MAX]:
            for value in [MIN,MIN+1,-1,0,1,MAX-1,MAX]:
                add(f'debit-{mode}-{total}-{value}',[summary(total=total)],state(users=[user(balance=value,positions=[position(mode=mode,margin=value)])]))
    for size in [0,1,-1,2,-2,1<<31,-(1<<31),MAX,-MAX]:
        a=abs(size)
        values=sorted(set([MIN,MIN+1,MIN+a-1,MIN+a,MIN+a+1,-1,0,1,MAX]))
        for x in [None]+[x for x in values if MIN<=x<=MAX]:
            add(f'aux-{size}-{x}',st=state(users=[user(positions=[position(size=size)])],aux=[] if x is None else [[7,x]]))
    for n in [1,2,3,4,5,6,10,11,12,13,23,24,25,143,144,145]:
        for pattern in ['none','tie','increasing','decreasing','alternating']:
            ss=[];uu=[]
            for i in range(n):
                key=i+1;mag={'none':None,'tie':0,'increasing':i,'decreasing':UMAX-i,'alternating':UMAX if i%2 else 0}[pattern]
                ss.append(summary(key,total=(i%3)-1,selection=None if mag is None else (key,mag),records=[row((n,i)),row((i,'zero'),0),row((i,'suffix'))] if i%3==0 else []))
                uu.append(user(key,positions=[position(asset=key,size=i)]))
            add(f'outer-{n}-{pattern}',list(reversed(ss)),state(users=list(reversed(uu)),aru=[address(999)],aux=[[999,MIN]],with_positions=[address(999)]))
    for sums in itertools.permutations([MAX,1,-1]):
        add(f'ordered-sum-{sums}',[summary(i+1,total=x,selection=None,records=[]) for i,x in enumerate(sums)],state(users=[]))
    for sums in itertools.permutations([MIN,-1,1]):
        add(f'ordered-sum-negative-{sums}',list(reversed([summary(i+1,total=x,selection=None,records=[]) for i,x in enumerate(sums)])),state(users=[]))
    for a,b in [(0,1),(0x7f,0x80),(0xff,0x100),((1<<152)-1,1<<152),((1<<159)-1,1<<159),((1<<160)-2,(1<<160)-1)]:
        add(f'unsigned-address-{a}-{b}',[summary(b,selection=(2,UMAX)),summary(a,selection=(1,UMAX))],state(users=[user(a,positions=[position(1)]),user(b,positions=[position(2)])]))
    for sentinel in [0,1,255,256,0x80000000,0xffffffff]:
        for index in range(5):
            rr=[row(i+800,sentinel if i==index else 1) for i in range(5)]
            add(f'inner-{sentinel}-{index}',[summary(records=rr),summary(2,total=0,selection=None,records=[row('later')])])
    for zero in [False,True]:
        for no_selection in [False,True]:
            if not zero and not no_selection:continue
            for st in [state(users=[]),state(users=[user(positions=[])]),state(users=[user(positions=[position(size=MIN)])])]:
                add(f'lazy-{zero}-{no_selection}-{len(st["users"])}',[summary(total=0 if zero else 1,selection=None if no_selection else (7,1))],st)
    for count in [0,1,UMAX]:
        for prior in [[],[address(1)]]:
            add(f'count-aru-{count}-{bool(prior)}',st=state(users=[user(count=count)],aru=prior,with_positions=[address(2)]))
    for mode in [0,1,0xffffffff]:
        add(f'separate-missing-user-{mode}',st=state(users=[user(2)]),domain='safe_policy')
        add(f'separate-missing-position-{mode}',st=state(users=[user(positions=[position(8,mode,size=MIN)])]),domain='safe_policy')
        add(f'separate-size-MIN-{mode}',st=state(users=[user(positions=[position(mode=mode,size=MIN)])]),domain='safe_policy')
    for total in [0,1]:
        add(f'duplicate-priority-{total}',[summary(total=total),summary(total=-total)],state(users=[]),domain='safe_policy')
    rng=random.Random(0x3703f20)
    for i in range(240):
        n=rng.randrange(0,20);keys=rng.sample(range(1,70),n);ss=[];uu=[]
        for key in keys:
            asset=rng.choice([0,7,UMAX]);size=rng.choice([0,1,-1,MAX,-MAX,rng.randrange(MIN+1,MAX)])
            ss.append(summary(key,rng.choice([MIN,MAX,0,1,-1,rng.randrange(MIN,MAX)]),None if rng.randrange(4)==0 else (asset,rng.choice([0,UMAX,rng.getrandbits(64)])),[row((i,key,j),rng.choice([0,1,256,0xffffffff])) for j in range(rng.randrange(5))]))
            uu.append(user(key,rng.randrange(MIN,MAX),rng.getrandbits(64),[position(asset,rng.choice([0,1,2,0xffffffff]),size,rng.randrange(MIN,MAX),rng.getrandbits(32)),position(9,0,MIN,18,4)]))
        add(f'random-{i}',ss,state(users=uu,aru=[address(90)],aux=[[0,MIN],[7,-1],[UMAX,MAX]],with_positions=[address(90)]))
    for s in sorted(set([0,1,MAX//104-1,MAX//104,MAX//104+1,MAX//80,MAX//80+1,UMAX])):
        for r in sorted(set([0,1,MAX//72-1,MAX//72,MAX//72+1,UMAX])):
            out.append(dict(name=f'counts-{s}-{r}',kind='counts',domain='safe_policy',summary_count=s,record_count=r))
    for c in out:
        if c['kind']=='counts':continue
        st=c['state']
        for k in ('users','aru','aux','with_positions'):
            values=[x['address'] for x in st[k]] if k=='users' else [x[0] for x in st[k]] if k=='aux' else st[k]
            if len(values)!=len(set(values)):raise ValueError('duplicate state keys')
        for u in st['users']:
            if len({p['asset'] for p in u['positions']})!=len(u['positions']):raise ValueError('duplicate positions')
        for x in c['summaries']:
            if len(bytes.fromhex(x['address']))!=20 or any(len(bytes.fromhex(r))!=72 for r in x['records']):raise ValueError('fixed byte widths')
        if c['domain']=='native_corresponding' and oracle(c)['status']!='ok':raise ValueError('native-domain case fails safe admission')
    return out


def generate():
    all_cases=cases();inputs=[];expected=[]
    for i,c in enumerate(all_cases):
        label=f'C{i:06d}';inputs.append(label+'\t'+input_frame(c).hex());expected.append(label+'\t'+expected_frame(c).hex())
    compress=lambda x:gzip.compress(x.encode(),mtime=0)
    meta=dict(cases=len(all_cases),native_corresponding=sum(c['domain']=='native_corresponding' for c in all_cases),safe_policy=sum(c['domain']=='safe_policy' for c in all_cases),oracle='Flat sorted relations, arbitrary-precision clamp, stable rank and closed auxiliary formula; no native evaluator. Input IDs contain no semantics or expected values.')
    return {'cases.jsonl.gz':compress(''.join(json.dumps(c,separators=(',',':'))+'\n' for c in all_cases)),
            'vectors.tsv.gz':compress('\n'.join(inputs)+'\n'),'expected.tsv.gz':compress('\n'.join(expected)+'\n'),
            'summary.json':(json.dumps(meta,indent=2)+'\n').encode()}
