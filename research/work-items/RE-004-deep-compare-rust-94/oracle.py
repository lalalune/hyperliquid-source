"""Pre-Rust exact read obligations and partial-register replacement relation."""
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
SIZE=256
INPUT='<QQQH256s'
OUTPUT='<BQQ'


def require(ok,message):
    if not ok:raise ValueError(message)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def expected(row):
    base,first,second,length,image=row
    if length and base+length>MOD:return (1,0,0)
    def read(address):
        offset=address-base
        if not (0<=offset and offset+8<=length):return None
        return sum(image[offset+j]*256**j for j in range(8))
    a=read((first+8)%MOD)
    if a is None:return (2,0,0)
    b=read((second+8)%MOD)
    if b is None:return (3,0,0)
    x=read((a+120)%MOD)
    if x is None:return (4,0,0)
    y=read((b+120)%MOD)
    if y is None:return (5,0,0)
    # SETB replaces only the lowest byte of the first loaded value.
    return (0,256*(x//256)+int(y<x),b)


def corpus():
    rows=[]
    def make(x,y,base=0,first=16,second=32,at_x=128,at_y=152,length=SIZE,seed=11):
        image=bytearray((seed+37*j)%256 for j in range(SIZE))
        def put(at,value):
            if 0<=at and at+8<=SIZE:image[at:at+8]=(value%MOD).to_bytes(8,'little')
        put(first+8,base+at_x-120);put(second+8,base+at_y-120)
        put(at_x,x);put(at_y,y)
        rows.append((base,(base+first)%MOD,(base+second)%MOD,length,bytes(image)))
    edges=(0,1,127,128,255,256,257,(1<<32)-1,1<<32,(1<<63)-1,1<<63,MASK)
    for x in edges:
        for y in edges:
            for base in (0,0x1000,MOD-SIZE):make(x,y,base)
    for low_byte in range(256):
        x=0x8123456789abcd00+low_byte
        for y in (0,x-1,x,x+1,MASK):make(x,y)
    for bit in range(64):
        x=1<<bit
        for y in (0,x-1,x,(x+1)%MOD,MASK):make(x,y)
    for x in edges:
        make(x,x,second=16,at_y=128)
        for base in (0,MOD-SIZE):
            for location in (0,1,7,8,16,24,32,40,127,128,129,152,153,248):
                make(x,x^MASK,base,at_x=location,at_y=152)
                make(x,x^MASK,base,at_x=128,at_y=location)
    for length in (0,7,8,23,24,31,32,39,40,135,136,159,160,255,256):
        for first,second in ((0,8),(16,32),(-8,0),(248,16)):
            make(0x8877665544332211,0x1020304050607080,first=first,second=second,length=length)
    for base in (MOD-SIZE+1,MASK-7,MASK):make(1,0,base)
    rng=random.Random(0x51c0c00)
    for _ in range(2048):
        make(rng.getrandbits(64),rng.getrandbits(64),rng.choice((0,0x1000,MOD-SIZE)),
             first=rng.choice((16,32,-8,rng.randrange(256))),second=rng.choice((32,16,rng.randrange(256))),
             at_x=rng.randrange(249),at_y=rng.randrange(249),length=rng.choice((SIZE,SIZE,rng.randrange(257))),seed=rng.randrange(256))
    return rows


def fixtures():
    rows=corpus();results=[expected(row) for row in rows]
    inputs=b''.join(struct.pack(INPUT,*row) for row in rows)
    outputs=b''.join(struct.pack(OUTPUT,*result) for result in results)
    record={'cases':len(rows),'input_record_bytes':struct.calcsize(INPUT),'output_record_bytes':struct.calcsize(OUTPUT),
            'inputs_sha256':sha(inputs),'expected_sha256':sha(outputs),
            'outcomes':{str(tag):sum(r[0]==tag for r in results) for tag in range(6)},
            'non_boolean_RAX_results':sum(r[0]==0 and r[1]>1 for r in results),
            'oracle_sha256_at_freeze':sha(Path(__file__).read_bytes()),'static_sha256_at_freeze':sha((PACKET/'static.json').read_bytes()),
            'source_directory_existed_at_freeze':False,'captured_code_executed':False}
    return inputs,outputs,record


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--freeze',action='store_true');args=parser.parse_args()
    inputs,outputs,record=fixtures()
    if args.freeze:
        require(not (ROOT/'src/node94-deep-compare').exists(),'Rust exists before freeze')
        for name,raw in [('inputs',inputs),('expected',outputs)]:
            with (PACKET/(name+'.bin.gz')).open('xb') as f:f.write(gzip.compress(raw,mtime=0))
        with (PACKET/'frozen.json').open('x') as f:f.write(json.dumps(record,indent=2,sort_keys=True)+'\n')
    else:
        require(json.loads((PACKET/'frozen.json').read_text())==record,'frozen metadata')
        for name,raw in [('inputs',inputs),('expected',outputs)]:require(gzip.decompress((PACKET/(name+'.bin.gz')).read_bytes())==raw,'frozen stream')
    print(json.dumps(record,indent=2))


if __name__=='__main__':main()
