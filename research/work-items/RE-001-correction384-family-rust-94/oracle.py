#!/usr/bin/env python3
"""Pre-Rust whole-integer, ordered-image oracle for single-correction addition."""
import argparse
from collections import Counter
from datetime import datetime,timezone
import gzip,hashlib,json,random
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
TARGET='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
B=1<<64
Q=1<<384

def sha(x):return hashlib.sha256(x).hexdigest()
def words(x):return tuple((x//B**i)%B for i in range(6))
def relation(a,b,c):
    total=a+b;wrapped=total%Q
    output=(total-(c if total>=c else 0))%Q
    carry=total//Q;borrow=int(wrapped<c)
    s=words(wrapped);v=words(output)
    # Exact final SBB result, distinct from the selection condition.
    rdx=(-carry-borrow)%B
    core=(s[2],rdx,s[5],s[3],s[4],s[0],s[1])+v
    return output,core

def image_relation(mode,image,base,dst,left,right,corr,initial):
    original=bytes(image)
    if base+len(image)>B:return None,original,'image-wrap'
    width=96 if mode=='P' else 48
    roles=[(dst,width),(right,width),(corr,48)]
    if mode!='A':roles.append((left,width))
    for addr,size in roles:
        if addr<base or addr+size>B or addr-base+size>len(image):return None,original,'range-refusal'
    state=bytearray(image)
    def value(addr):return int.from_bytes(state[addr-base:addr-base+48],'little')
    for offset in ((48,0) if mode=='P' else (0,)):
        a=initial if mode=='A' else value(left+offset)
        b=value(right+offset);c=value(corr)
        output,regs=relation(a,b,c)
        at=dst-base+offset;state[at:at+48]=output.to_bytes(48,'little')
    if mode in ('S','P'):regs=(regs[0],regs[1],regs[2],corr,dst)+regs[7:11]
    alias=any(dst<a+n and a<dst+width for a,n in roles[1:])
    return regs,bytes(state),'alias' if alias else 'disjoint'

def corpus():
    edge=(0,1,2,B-1,B,1<<191,1<<383,Q-2,Q-1)
    for a in edge:
        for b in edge:
            for c in edge:yield ('C',a,b,c)
    for bit in range(384):
        p=1<<bit
        for a,b,c in ((p-1,1,p),(Q-1,p,Q-1),(p,p,Q-1),(Q-1,Q-1,p)):
            yield ('C',a,b,c)
    rng=random.Random(0x5656980)
    def case(mode,a,b,c,dst=0,left=96,right=192,corr=272,base=0x1000,length=320,initial=None):
        image=bytearray((i*41+23)%256 for i in range(length))
        for offset,value,width in ((left,a,96 if mode=='P' else 48),(right,b,96 if mode=='P' else 48),(corr,c,48)):
            if 0<=offset and offset+width<=length:
                raw=(value.to_bytes(48,'little')*((width+47)//48))[:width];image[offset:offset+width]=raw
        return mode,bytes(image),base,(base+dst)%B,(base+left)%B,(base+right)%B,(base+corr)%B,a if initial is None else initial
    for mode in ('F','S','P','A'):
        for a in (0,1,Q-1):
            for b in edge:
                for c in edge:yield case(mode,a,b,c)
    for delta in range(-95,96):
        # Every byte displacement; high stores can alter each later read role.
        yield case('P',Q-1,Q-2,Q-3,96+delta,96,0,272)
        yield case('P',Q-2,Q-1,Q-3,96+delta,0,96,272)
        yield case('P',Q-1,Q-1,Q-2,96+delta,0,192,96)
    for mode in ('F','S','A'):
        for delta in range(-47,48):yield case(mode,Q-1,Q-2,Q-3,96+delta,96,0,272)
    # Invalid/short/overflow layouts are refused without any earlier high store.
    for mode in ('F','S','P','A'):
        for base in (0,0x1000,B-320,B-319,B-1):
            for length in (0,47,48,95,96,319,320):
                for dst,left,right,corr in ((0,96,192,272),(0,-1,0,0),(0,0,0,0),(225,96,192,272)):
                    yield case(mode,0,0,0,dst,left,right,corr,base,length)
    for i in range(1024):
        a=rng.getrandbits(384);b=rng.getrandbits(384);c=rng.getrandbits(384)
        yield ('C',a,b,c)
        mode=rng.choice(('F','S','P','A'));limit=225 if mode=='P' else 273
        yield case(mode,a,b,c,rng.randrange(limit),rng.randrange(limit),rng.randrange(limit),rng.randrange(273),initial=rng.getrandbits(384))

def render():
    inputs=[];outputs=[];coverage=Counter()
    for i,case in enumerate(corpus()):
        mode=case[0];label=f'case-{i:05d}';coverage[mode]+=1
        if mode=='C':
            _,a,b,c=case;out,regs=relation(a,b,c);image='-'
            fields=(label,mode,f'{a:096x}',f'{b:096x}',f'{c:096x}','-','-','-','-')
            coverage['carry'+str((a+b)//Q)+'-borrow'+str(int((a+b)%Q<c))]+=1
        else:
            _,data,base,dst,left,right,corr,initial=case
            regs,new,kind=image_relation(mode,data,base,dst,left,right,corr,initial);coverage[kind]+=1
            fields=(label,mode,f'{base:016x}',f'{dst:016x}',f'{left:016x}' if mode!='A' else '-',f'{right:016x}',f'{corr:016x}',f'{initial:096x}' if mode=='A' else '-',data.hex() or '-')
            image=new.hex() or '-'
        inputs.append('\t'.join(fields)+'\n')
        outputs.append(label+'\t'+('E' if regs is None else 'V:'+':'.join(f'{x:016x}' for x in regs))+'\t'+image+'\n')
    return ''.join(inputs).encode(),''.join(outputs).encode(),dict(sorted(coverage.items()))

def check():
    frozen=json.loads((HERE/'fixtures/freeze.json').read_text());inp,out,cov=render()
    if frozen['cases']!=len(inp.splitlines()) or frozen['coverage']!=cov or frozen['target_sha256']!=TARGET:raise ValueError('freeze identity')
    for name,raw in [('inputs.tsv',inp),('expected.tsv',out)]:
        packed=(HERE/'fixtures'/(name+'.gz')).read_bytes()
        if gzip.decompress(packed)!=raw or sha(raw)!=frozen['sha256'][name] or sha(packed)!=frozen['sha256'][name+'.gz']:raise ValueError('fixture drift')
    if sha(Path(__file__).read_bytes())!=frozen['sha256']['oracle.py']:raise ValueError('oracle drift')
    return frozen
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--freeze',action='store_true');args=p.parse_args()
    if args.freeze:
        if (ROOT/'src/node94-correction384-family').exists() or (HERE/'fixtures/freeze.json').exists():raise ValueError('freeze must precede Rust')
        inp,out,cov=render();files={'inputs.tsv':inp,'expected.tsv':out}
        for name,raw in list(files.items()):
            packed=gzip.compress(raw,mtime=0);(HERE/'fixtures'/(name+'.gz')).write_bytes(packed);files[name+'.gz']=packed
        files['oracle.py']=Path(__file__).read_bytes()
        f={'target_sha256':TARGET,'cases':len(inp.splitlines()),'coverage':cov,'frozen_at_utc':datetime.now(timezone.utc).isoformat(),'rust_source_absent':True,'sha256':{k:sha(v) for k,v in files.items()}}
        (HERE/'fixtures/freeze.json').write_text(json.dumps(f,sort_keys=True,indent=2)+'\n');print(json.dumps(f,indent=2))
    else:print('PASS frozen oracle',check()['cases'])
