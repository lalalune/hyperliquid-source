#!/usr/bin/env python3
"""Independent flat-relation value/ownership oracle, authored before Rust.

No captured code, native tree walker, callbacks, allocator or source module is
evaluated. Object IDs denote shared byte-vector identity, not pointer addresses.
"""
from __future__ import annotations
import gzip
import hashlib
import itertools
import json
from pathlib import Path
import struct

LIMIT=((1<<63)-1)//40


def u32(n):return struct.pack('<I',n)
def u64(n):return struct.pack('<Q',n)
def blob(b):return u32(len(b))+b
def key(n):return n.to_bytes(32,'big')
def hashes(xs):return u64(len(xs))+b''.join(xs)
def mapping(xs):return u64(len(xs))+b''.join(k+u32(v) for k,v in xs)


class ViewError(ValueError):pass


def hash_view(raw):
    if len(raw)<8:raise ViewError('short count')
    n=struct.unpack_from('<Q',raw)[0]
    if len(raw)!=8+32*n:raise ViewError('hash span')
    return [raw[8+32*i:40+32*i] for i in range(n)]


def map_view(raw,pool):
    if len(raw)<8:raise ViewError('short count')
    n=struct.unpack_from('<Q',raw)[0]
    if len(raw)!=8+36*n:raise ViewError('map span')
    out=[(raw[8+36*i:40+36*i],struct.unpack_from('<I',raw,40+36*i)[0]) for i in range(n)]
    if any(v>=len(pool) for _,v in out):raise ViewError('value object ID')
    if any(a[0]>=b[0] for a,b in zip(out,out[1:])):raise ViewError('strict sorted uniqueness')
    return out


def input_frame(c):
    if c['kind']=='length':return b'\x02'+u64(c['count'])
    raw=b'\x01'+blob(c['block'])+c['time']+u32(len(c['pool']))
    raw+=b''.join(blob(x) for x in c['pool'])+blob(c['hash_view'])+blob(c['map_view'])
    supplied=c['supplied'];raw+=bytes([supplied is not None])
    if supplied is not None:raw+=u32(len(supplied))+b''.join(k+u32(v) for k,v in supplied)
    return raw


def decode_frame(raw):
    """Outer typed fixture parser; the two views remain uninterpreted raw blobs."""
    pos=0
    def take(n):
        nonlocal pos
        if n<0 or pos+n>len(raw):raise ValueError('truncated input')
        out=raw[pos:pos+n];pos+=n;return out
    def number():return struct.unpack('<I',take(4))[0]
    def take_blob():return take(number())
    kind=take(1)[0]
    if kind==2:c=dict(kind='length',count=struct.unpack('<Q',take(8))[0])
    elif kind==1:
        block=take_blob();time=take(12);pool=[take_blob() for _ in range(number())]
        hs,mp=take_blob(),take_blob();flag=take(1)[0]
        if flag not in (0,1):raise ValueError('invalid option')
        supplied=None if not flag else [(take(32),number()) for _ in range(number())]
        if supplied is not None and any(v>=len(pool) for _,v in supplied):raise ValueError('supplied object ID')
        c=dict(kind='join',block=block,time=time,pool=pool,hash_view=hs,map_view=mp,supplied=supplied)
    else:raise ValueError('unknown frame kind')
    if pos!=len(raw):raise ValueError('trailing input')
    return c


def expected(c):
    if c['kind']=='length':
        n=c['count'];valid=n<=LIMIT
        return b'\x02'+bytes([valid])+(u64(40*n) if valid else b'')
    pool=c['pool'];supplied=c['supplied'];h_used=m_used=0;status=0;missing=b'';rows=[]
    try:mp=map_view(c['map_view'],pool)
    except ViewError:mp=None
    if supplied is not None:rows=list(supplied)
    else:
        h_used=1
        try:hs=hash_view(c['hash_view'])
        except ViewError:status=2;hs=[]
        if status==0 and len(hs)>LIMIT:status=4
        if status==0 and hs:
            m_used=1
            if mp is None:status=3
            else:
                # Mathematical relation: first index without an equal key;
                # successful prefixes are discarded as a whole on failure.
                matches=[[v for k,v in mp if k==h] for h in hs]
                absent=[i for i,x in enumerate(matches) if not x]
                if absent:status=1;missing=hs[min(absent)]
                else:rows=[(h,vs[0]) for h,vs in zip(hs,matches)]
    ok=status==0
    # The driver retains one pool owner, every valid map entry, and one keeper
    # of a supplied outer rows Arc. That keeper shares inner values once.
    base=[1+sum(v==i for _,v in (mp or []))+sum(v==i for _,v in (supplied or [])) for i in range(len(pool))]
    live=[x+(sum(v==i for _,v in rows) if ok and supplied is None else 0) for i,x in enumerate(base)]
    identity=1 if ok and supplied is not None else 2 if ok else 0
    raw=b'\x01'+bytes([status,h_used,m_used,ok,identity])
    if ok:
        raw+=blob(c['block'])+c['time']+u32(len(rows))
        raw+=b''.join(h+u32(v)+blob(pool[v]) for h,v in rows)
    elif status==1:raw+=missing
    raw+=u32(len(pool))+b''.join(u64(a)+u64(b) for a,b in zip(live,base))
    raw+=bytes([0])+u32((2 if supplied is not None else 1) if ok else (1 if supplied is not None else 0))
    raw+=u32(1 if supplied is not None else 0)
    # An invalid map view has no constructed source map. The validity bit is an
    # observed parser result, not input to the recovered operation.
    raw+=bytes([mp is not None])
    if mp is not None:raw+=u32(len(mp))+b''.join(k+u32(v)+blob(pool[v]) for k,v in mp)
    return raw


def cases():
    out=[]
    pool=[b'',b'\x00',b'\xff\x80\x00',b'equal bytes',b'equal bytes',bytes(range(256))]
    def add(name,hs=(),mp=(),supplied=None,category='native ordinary projection',**kw):
        c=dict(kind='join',name=name,category=category,block=b'opaque block\x00proof\xff',time=bytes(range(12)),
               pool=list(pool),hash_view=hashes(hs),map_view=mapping(mp),supplied=supplied)
        c.update(kw);out.append(c)
    add('absent empty')
    add('provided empty',supplied=[])
    add('provided unrelated order',hs=[key(999)],mp=[(key(999),0)],supplied=[(key(8),4),(key(7),3),(key(8),4)])
    add('duplicate requested keys',hs=[key(2),key(1),key(2),key(1)],mp=[(key(1),3),(key(2),4)])
    add('different keys same object',hs=[key(1),key(2),key(1)],mp=[(key(1),5),(key(2),5)])
    for n in (1,2,3,10,11,12,23,64,257):
        mp=[(key(2*i),i%len(pool)) for i in range(n)]
        requested=[k for k,_ in mp]
        add(f'all present {n}',requested,mp)
        add(f'reverse repeats {n}',list(reversed(requested))+requested[:3],mp)
        for at in sorted({0,n//2,n}):
            hs=requested[:at]+[key(2*n+1)]+requested[at:]+[key(2*n+3)]
            add(f'first miss prefix {n} {at}',hs,mp)
    for order in itertools.permutations([1,2,3,4]):
        add('permutation '+''.join(map(str,order)),[key(i) for i in order],[(key(i),i) for i in range(1,5)])
    # First differing byte, unsigned sign extremes and every exact hash byte.
    for pos in range(32):
        for a,b in ((0,1),(0x7f,0x80),(0x80,0xff)):
            lo=bytearray(b'\x55'*32);hi=bytearray(lo);lo[pos]=a;hi[pos]=b
            lo,hi=bytes(lo),bytes(hi)
            add(f'byte order {pos} {a} {b}',[hi,lo,hi],[(lo,3),(hi,4)])
            add(f'exact miss byte {pos} {a} {b}',[lo,hi,lo],[(lo,2)])
    for k in range(33):
        mp=[(key(i),i%6) for i in range(33)]
        hs=[key(i) for i in range(k)]+[key(1000+k),key(2000+k)]
        add(f'cleanup every prefix {k}',hs,mp)
    for n in (0,1,7,31):
        supplied=[(key((i*7)%13),i%6) for i in range(n)]
        for hb,mb,label in [(b'',b'','both'),(hashes([key(5)]),b'','map'),(b'',mapping([(key(1),2)]),'hash')]:
            add(f'provided ignores invalid {label} {n}',supplied=supplied,hash_view=hb,map_view=mb,
                category='safe view admission; provided path projection')
    invalid_hash=[b'',u64(1),hashes([key(1)])+b'\x00',u64((1<<64)-1)]
    invalid_maps=[b'',u64(1),mapping([(key(1),99)]),mapping([(key(2),1),(key(1),2)]),
                  mapping([(key(1),1),(key(1),2)]),mapping([])+b'\x00',u64((1<<64)-1)]
    for i,h in enumerate(invalid_hash):
        add(f'invalid hash {i}',hash_view=h,map_view=b'',category='safe view refusal')
    for i,m in enumerate(invalid_maps):
        add(f'empty ignores invalid map {i}',map_view=m,category='safe view admission; empty path projection')
        add(f'nonempty invalid map {i}',hs=[key(1)],map_view=m,category='safe view refusal')
    for i in range(12):
        t=bytearray(12);t[i]=255
        for supplied in (None,[(key(9),2)]):
            add(f'raw time byte {i} {supplied is None}',hs=[key(9)],mp=[(key(9),2)],supplied=supplied,
                time=bytes(t),block=bytes(range(i))+b'\x00\xffproof')
    for n in (0,1,39,40,LIMIT-1,LIMIT,LIMIT+1,1<<63,(1<<64)-1):
        out.append(dict(kind='length',name=f'span boundary {n}',category='safe count admission arithmetic',count=n))
    return out


def generate():
    inputs=[];outputs=[];metadata=[]
    for i,c in enumerate(cases()):
        ident=f'C{i:06d}';raw=input_frame(c);decoded=decode_frame(raw)
        result=expected(c)
        if result!=expected(decoded):raise ValueError('frame roundtrip semantic difference')
        inputs.append(ident+'\t'+raw.hex()+'\n');outputs.append(ident+'\t'+result.hex()+'\n')
        metadata.append(json.dumps(dict(id=ident,name=c['name'],category=c['category'],
                                       input_sha256=hashlib.sha256(raw).hexdigest(),
                                       output_sha256=hashlib.sha256(result).hexdigest()),separators=(',',':'))+'\n')
    compress=lambda s:gzip.compress(''.join(s).encode(),mtime=0)
    return {'vectors.tsv.gz':compress(inputs),'expected.tsv.gz':compress(outputs),'cases.jsonl.gz':compress(metadata)}


if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    a.out.mkdir(parents=True,exist_ok=False)
    for name,raw in generate().items():(a.out/name).write_bytes(raw)
    print(json.dumps({'cases':len(cases()),'files':3}))
