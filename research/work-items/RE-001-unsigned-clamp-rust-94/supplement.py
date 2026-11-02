#!/usr/bin/env python3
"""Explicit post-Rust witnesses for the surviving low8-one-tag control."""
import argparse,gzip,hashlib,json
from datetime import datetime,timezone
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
def sha(raw):return hashlib.sha256(raw).hexdigest()
def require(ok,message):
    if not ok:raise ValueError(message)
def render():
    inputs=[];expected=[]
    for bit in range(8,32):
        for prefix in (0,1<<32,1<<63):
            tag=prefix+(1<<bit)+1;cap=(1<<63)+bit
            # The tag is nonzero and its low32 is >1, so the target theorem
            # gives RAX=0 independently of both arithmetic fields. RCX=cap.
            require(tag!=0 and tag%(1<<32)>1,'direct tag-class premise')
            name=f'supplement-{bit}-{prefix:x}'
            inputs.append(f'{name}\t{tag:016x}\tfffffffffffffffe\t0000000000000004\t{cap:016x}\n')
            expected.append(f'{name}\tV:0000000000000000:{cap:016x}\n')
    return ''.join(inputs).encode(),''.join(expected).encode()
def check():
    record=json.loads((HERE/'fixtures/supplement.json').read_text());inputs,expected=render()
    require(record['cases']==72 and record['post_rust'] is True,'supplement identity')
    for name,raw in [('supplement-inputs.tsv',inputs),('supplement-expected.tsv',expected)]:
        compressed=(HERE/'fixtures'/(name+'.gz')).read_bytes()
        require(gzip.decompress(compressed)==raw and sha(raw)==record['sha256'][name] and sha(compressed)==record['sha256'][name+'.gz'],'supplement fixture integrity')
    for name,path in [('oracle.py',HERE/'oracle.py'),('lib.rs',ROOT/'src/node94-unsigned-clamp/lib.rs'),('original-freeze.json',HERE/'fixtures/freeze.json'),('supplement.py',Path(__file__))]:
        require(sha(path.read_bytes())==record['sha256'][name],f'unchanged bound {name}')
    return record
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--freeze',action='store_true');args=parser.parse_args()
    if args.freeze:
        require(not(HERE/'fixtures/supplement.json').exists(),'already frozen')
        inputs,expected=render();files={'supplement-inputs.tsv':inputs,'supplement-expected.tsv':expected}
        for name,raw in list(files.items()):
            packed=gzip.compress(raw,compresslevel=9,mtime=0);(HERE/'fixtures'/(name+'.gz')).write_bytes(packed);files[name+'.gz']=packed
        files.update({'oracle.py':(HERE/'oracle.py').read_bytes(),'lib.rs':(ROOT/'src/node94-unsigned-clamp/lib.rs').read_bytes(),'original-freeze.json':(HERE/'fixtures/freeze.json').read_bytes(),'supplement.py':Path(__file__).read_bytes()})
        record={'cases':72,'post_rust':True,'reason':'Original frozen corpus did not distinguish the surviving low8-one-tag mutant; original source/oracle/corpus remain unchanged.','frozen_at_utc':datetime.now(timezone.utc).isoformat(),'sha256':{name:sha(raw) for name,raw in files.items()}}
        (HERE/'fixtures/supplement.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(check(),indent=2))
