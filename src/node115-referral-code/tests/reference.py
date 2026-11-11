#!/usr/bin/env python3
"""Independent list/dictionary state reference using arbitrary-width volume sums."""
from pathlib import Path
import random,hashlib
r=random.Random(0x3c193d0);U=(1<<64)-1;lines=[];counts={};actions=0
hx=lambda s:s.encode().hex() or '-'
def records_text(records):
    return ';'.join(','.join(map(str,[u,hx(v['code']),v['remaining'],v['bucket'],v['quota'],v['history']])) for u,v in sorted(records.items())) or '-'
def codes_text(codes):return ';'.join(f'{hx(c)},{u}' for c,u in sorted(codes.items())) or '-'
for case in range(200):
    volumes={u:r.choice([[0],[999999],[1000000],[999999,1],[U,1],[100000,200000,700000]]) for u in range(1,5) if r.randrange(5)}
    records={u:dict(code=f'old{u}',remaining=r.choice([0,1,U]),bucket=r.getrandbits(64),quota=r.getrandbits(64),history=1) for u in range(1,4) if r.randrange(2)}
    codes={v['code']:u for u,v in records.items()};codes['occupied']=9
    # A code may exist without a referrer record; the two core modes differ.
    if case%3==0:codes['alias']=1
    vol=';'.join(f'{u}:'+','.join(map(str,v)) for u,v in sorted(volumes.items())) or '-'
    lines.append('\t'.join(['I',vol,records_text(records),codes_text(codes)]))
    for step in range(20):
        mode=r.randrange(3);user=r.randrange(1,6);code=r.choice(['', 'a', 'Old1','old1','old2','old3','occupied','alias','new'+str(r.randrange(5)),'é'*50,'é'*51,'nul\x00code','x'*100,'x'*101]);quota=r.choice([0,1,999,1000,U,r.getrandbits(64)])
        tag=0
        if mode==2 and len(code.encode())>100:status=0x158
        elif mode!=1 and min(U,sum(volumes.get(user,[])))<1000000:status=0xa9
        elif len(code.encode())>100:status=0xa4
        elif mode!=1 and user in records:status=0xa8
        elif user in records:
            if code in codes and codes[code]!=user:status=0xa7
            else:
                record=records[user];codes.pop(record['code'],None);codes[code]=user;record.update(code=code,quota=quota,bucket=0);status=0x1a2
        elif code in codes:status=0xa7
        else:
            records[user]=dict(code=code,remaining=0,bucket=0,quota=0 if mode==2 else quota,history=0);codes[code]=user;status=0x1a2
        if mode==2:tag=14 if status==0x1a2 else 15
        counts[f'{mode}:{status}']=counts.get(f'{mode}:{status}',0)+1;actions+=1
        lines.append('\t'.join(map(str,['A',mode,user,hx(code),quota,tag,status,records_text(records),codes_text(codes)])))
raw=('\n'.join(lines)+'\n').encode();Path(__file__).with_name('reference.tsv').write_bytes(raw)
print({'scenarios':200,'actions':actions,'outcomes':counts,'sha256':hashlib.sha256(raw).hexdigest()})
