"""Pre-Rust piecewise interval relation for the closed global/tail state."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import random
import struct

PACKET=Path(__file__).resolve().parent
ROOT=PACKET.parents[2]
MOD=1<<64
MASK=MOD-1
CAP=1<<22


def require(ok,message):
    if not ok:raise ValueError(message)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def expected(row):
    bits,*_=row
    signed=bits if bits<MOD//2 else bits-MOD
    if signed<0:return (0,0,0,0)
    original=1 if signed==0 else signed
    if signed<128:scaled=1
    elif signed>=CAP*64:scaled=CAP
    else:scaled=signed//64
    return (0,scaled,0,original)


def corpus():
    values=set(range(-4096,4096))
    for center in (0,64,128,CAP*64,1<<32,(1<<63)-1,-(1<<63)):
        values.update(value for value in range(center-129,center+130) if -(1<<63)<=value<(1<<63))
    for bit in range(63):
        for sign in (-1,1):
            for delta in (-1,0,1):
                value=sign*(1<<bit)+delta
                if -(1<<63)<=value<(1<<63):values.add(value)
    rng=random.Random(0x55539e0)
    rows=[(value%MOD,*[rng.getrandbits(64) for _ in range(3)]) for value in sorted(values)]
    rows.extend((rng.getrandbits(64),*[rng.getrandbits(64) for _ in range(3)]) for _ in range(10000))
    return rows


def fixtures():
    rows=corpus();answers=[expected(row) for row in rows]
    inputs=b''.join(struct.pack('<4Q',*row) for row in rows)
    outputs=b''.join(struct.pack('<4Q',*answer) for answer in answers)
    record={'cases':len(rows),'inputs_sha256':sha(inputs),'expected_sha256':sha(outputs),
            'negative_inputs':sum(row[0]>=MOD//2 for row in rows),'zero_inputs':sum(row[0]==0 for row in rows),
            'capped_outputs':sum(answer[1]==CAP for answer in answers),
            'oracle_sha256_at_freeze':sha(Path(__file__).read_bytes()),'static_sha256_at_freeze':sha((PACKET/'static.json').read_bytes()),
            'source_directory_existed_at_freeze':False,'captured_code_executed':False}
    return inputs,outputs,record


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--freeze',action='store_true');args=parser.parse_args()
    inputs,outputs,record=fixtures()
    if args.freeze:
        require(not (ROOT/'src/node94-global-clamp').exists(),'Rust exists before freeze')
        for name,raw in [('inputs',inputs),('expected',outputs)]:
            with (PACKET/(name+'.bin.gz')).open('xb') as f:f.write(gzip.compress(raw,mtime=0))
        with (PACKET/'frozen.json').open('x') as f:f.write(json.dumps(record,indent=2,sort_keys=True)+'\n')
    else:
        require(json.loads((PACKET/'frozen.json').read_text())==record,'frozen metadata')
        for name,raw in [('inputs',inputs),('expected',outputs)]:require(gzip.decompress((PACKET/(name+'.bin.gz')).read_bytes())==raw,'frozen stream')
    print(json.dumps(record,indent=2))


if __name__=='__main__':main()
