#!/usr/bin/env python3
"""Independent scalar relations from node115 probe instructions, not an emulator."""
from pathlib import Path
import hashlib,json,itertools
P=Path(__file__).resolve().parent
R=P.parents[2]
MASK64=(1<<64)-1

def relation(kind,pattern,n,pos,origin,old):
    width=4 if kind=='s' else 8
    # Adapter requires native outer loop's current <= end-12 precondition.
    if n<12 or pos>n-12:
        return '-,-,-,precondition'
    if origin+pos>MASK64:
        return '-,-,-,absolute-overflow'
    data=lambda i: pattern[i%len(pattern)]
    word=sum(data(pos+i)<<(8*i) for i in range(width))
    bits=32 if kind=='s' else 64
    mult=0x9e3779b1 if kind=='s' else 0xcf1bbcdcbb000000
    bucket=((word*mult)%(1<<bits))>>(bits-12)
    current=origin+pos
    stored=current% (1<<(16 if kind=='s' else 32))
    if old>current: result='candidate-ahead'
    elif old<origin: result='before-origin'
    elif current-old>=65536: result='too-far'
    elif any(data(old-origin+i)!=data(pos+i) for i in range(4)):result='different'
    else:result=f'match:{old-origin}:{current-old}'
    return f'{bucket},{old},{stored},{result}'

def cases():
    seen=set()
    patterns=[bytes.fromhex(x) for x in ('0000000000000000','0102030405060708','0102030401020304','ffffffffffffffff','0001020300000000','ffffffff00000000','00000000ffffffff','0102030405aabbcc')]
    for kind,pat,n,pos,origin in itertools.product('sl',patterns,[12,13,32,96],[0,1,2,4,7,8,12,20,64,84],[0,1,7,65530,65536,(1<<32)-5,(1<<64)-9]):
        cellmask=(1<<(16 if kind=='s' else 32))-1
        current=origin+pos
        for old in (0,1,7,cellmask,origin-1,origin,origin+1,current-1,current,current+1,current-65535,current-65536):
            if not 0<=old<=cellmask:continue
            row=(kind,pat.hex(),n,pos,origin,old)
            if row not in seen:seen.add(row);yield row
    # Real distance threshold requires a long source and a representable old cell.
    for kind,pat,pos,origin,old in itertools.product('sl',patterns,[65534,65535,65536,65537],[0,1],[0,1,2]):
        row=(kind,pat.hex(),pos+12,pos,origin,old)
        if row not in seen:seen.add(row);yield row

def render():
    rows=[]
    for k,h,n,p,o,v in cases():rows.append(f'{k}\t{h}\t{n}\t{p}\t{o}\t{v}\t{relation(k,bytes.fromhex(h),n,p,o,v)}\n')
    return ''.join(rows).encode()
if __name__=='__main__':
    data=render();(P/'cases.tsv').write_bytes(data)
    f={'cases':len(data.splitlines()),'sha256':hashlib.sha256(data).hexdigest(),'new_rust_exists_at_freeze':(R/'src/node115-lz4-dictionary-kernel').exists(),'oracle_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'basis':'ELF-VA probe branch math; no captured execution/emulation','target_sha256':'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'}
    (P/'freeze.json').write_text(json.dumps(f,indent=2)+'\n');print(json.dumps(f))
