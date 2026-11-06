#!/usr/bin/env python3
"""Pure integer branch relation from authenticated sender operands; no target execution."""
import hashlib,json,random
from pathlib import Path
P=Path(__file__).resolve().parent
R=P.parents[2]
MAX=2**64-1

def expected(n,c,tag,k):
    # Extracted threshold / modular-word predicate differs intentionally from Rust set form.
    enabled=n>=1025 and ((c-4000)%65536)<65534
    if not enabled:
        if n>2**32-1:return 'E:WireLength'
        return f'R:{n}:{n.to_bytes(4,"big").hex()}00'
    if 110*n>MAX:return 'E:MultiplyOverflow'
    q=(110*n)//100
    a=q+24
    lead=f'C:{a}:{q+20}:{8192 if n<65535 else 16384}:{(n%2**32).to_bytes(4,"little").hex()}'
    if tag==1:return lead+'|E:CodecFailure'
    if k>MAX-4:return lead+'|E:PrefixOverflow'
    chosen=min(k+4,a)
    if chosen>2**32-1:return lead+'|E:WireLength'
    return lead+f'|F:{chosen}:{chosen.to_bytes(4,"big").hex()}01'

def rows():
    seen=set()
    def emit(v):
        if v not in seen:
            seen.add(v);return ' '.join(map(str,v))+'\t'+expected(*v)+'\n'
    for low in range(65536):
        v=(1025,low|(([0,1,32768,65535][low%4])<<16),0,low%1160)
        yield emit(v)
    lengths=[0,1,1023,1024,1025,1026,65534,65535,65536,2**32-1,2**32,2**32+1,MAX//110-1,MAX//110,MAX//110+1,MAX]
    for n in lengths:
      for c in [0,3997,3998,3999,4000,0xffff0f9e,0xffff0f9f,2**32-1]:
       a=110*n//100+24
       for tag in [0,1,2,MAX]:
        for k in sorted(set([0,1,n,max(0,a-5),max(0,a-4),a,MAX-4,MAX-3,MAX])):
         row=emit((n,c,tag,k))
         if row:yield row
    rng=random.Random(1152768)
    for _ in range(12000):
      n=rng.choice([rng.randrange(1000000),rng.getrandbits(64),rng.randrange(2**32)])
      row=emit((n,rng.getrandbits(32),rng.choice([0,1,2,MAX]),rng.getrandbits(64)))
      if row:yield row

def corpus():return ''.join(rows()).encode()
if __name__=='__main__':
    data=corpus();(P/'cases.tsv').write_bytes(data)
    freeze={'target_sha256':'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301','cases':data.count(b'\n'),'cases_sha256':hashlib.sha256(data).hexdigest(),'oracle_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'new_rust_exists':(R/'src/node115-tcp-compression-plan').exists(),'relation':'hand-authored arithmetic consequences of pinned sender operands; not emulator'}
    assert not freeze['new_rust_exists'],'freeze must precede Rust'
    (P/'freeze.json').write_text(json.dumps(freeze,indent=2)+'\n')
    print(freeze)
