"""Pre-Rust immutable final-byte relation for the tagged 40-byte output."""
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
SIZE=128
INPUT='<QQQH128s'
OUTPUT='<BQ128s'
TAG=bytes.fromhex('1400000000000080')


def require(ok,message):
    if not ok:raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def expected(row):
    base,source,destination,length,initial=row
    if length and base+length>MOD:return (1,0,initial)
    a,b=source-base,destination-base
    if not (0<=a and a+32<=length):return (2,0,initial)
    if not (0<=b and b+40<=length):return (3,0,initial)
    # Each final output byte refers directly to the immutable entry image.
    def final(j):
        if b<=j<b+8:return TAG[j-b]
        if b+8<=j<b+40:return initial[a+j-b-8]
        return initial[j]
    return (0,destination,bytes(final(j) for j in range(SIZE)))


def corpus():
    rows=[]
    def add(source,destination,base=0,length=SIZE,seed=17,contents=None):
        initial=bytes((seed+37*j)%256 for j in range(SIZE)) if contents is None else contents
        require(len(initial)==SIZE,'fixture image')
        rows.append((base,(base+source)%MOD,(base+destination)%MOD,length,initial))
    for phase in range(8):
        source=48+phase
        for displacement in range(-39,32):
            for seed in (0,17,128,255):add(source,source+displacement,seed=seed)
    for bit in range(256):
        initial=bytearray(SIZE);initial[48+bit//8]=1<<(bit%8)
        for displacement in (-39,-16,-8,-1,0,1,16,31):
            add(48,48+displacement,contents=bytes(initial))
    for base in (0,0x1000,MOD-SIZE):
        for source in (0,1,31,48,88,96,97):
            for destination in (0,1,31,48,80,88,89):
                for length in (0,31,32,39,40,79,80,119,120,127,128):add(source,destination,base,length)
    for base in (MASK,MASK-7,MOD-SIZE+1):
        for length in (0,1,7,8,127,128):add(0,0,base,length)
    rng=random.Random(0x22155a0)
    for _ in range(2048):
        base=rng.choice((0,0x1000,MOD-SIZE))
        add(rng.randrange(100),rng.randrange(93),base,rng.choice((SIZE,SIZE,rng.randrange(SIZE+1))),contents=rng.randbytes(SIZE))
    return rows


def fixtures():
    rows=corpus();results=[expected(row) for row in rows]
    inputs=b''.join(struct.pack(INPUT,*row) for row in rows)
    expected_bytes=b''.join(struct.pack(OUTPUT,*result) for result in results)
    valid=[row for row,result in zip(rows,results) if result[0]==0]
    record={'cases':len(rows),'input_record_bytes':struct.calcsize(INPUT),'output_record_bytes':struct.calcsize(OUTPUT),
            'inputs_sha256':sha(inputs),'expected_sha256':sha(expected_bytes),
            'outcomes':{str(tag):sum(result[0]==tag for result in results) for tag in range(4)},
            'overlapping_admitted_cases':sum(row[1]<row[2]+40 and row[2]<row[1]+32 for row in valid),
            'same_address_admitted_cases':sum(row[1]==row[2] for row in valid),
            'oracle_sha256_at_freeze':sha(Path(__file__).read_bytes()),
            'static_sha256_at_freeze':sha((PACKET/'static.json').read_bytes()),
            'source_directory_existed_at_freeze':False,'captured_code_executed':False}
    return inputs,expected_bytes,record


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--freeze',action='store_true');args=parser.parse_args()
    inputs,outputs,record=fixtures()
    if args.freeze:
        require(not (ROOT/'src/node94-tagged-copy').exists(),'Rust exists before freeze')
        for name,raw in [('inputs',inputs),('expected',outputs)]:
            with (PACKET/(name+'.bin.gz')).open('xb') as f:f.write(gzip.compress(raw,mtime=0))
        with (PACKET/'frozen.json').open('x') as f:f.write(json.dumps(record,indent=2,sort_keys=True)+'\n')
    else:
        require(json.loads((PACKET/'frozen.json').read_text())==record,'frozen metadata')
        for name,raw in [('inputs',inputs),('expected',outputs)]:
            require(gzip.decompress((PACKET/(name+'.bin.gz')).read_bytes())==raw,'frozen stream')
    print(json.dumps(record,indent=2))


if __name__=='__main__':main()
