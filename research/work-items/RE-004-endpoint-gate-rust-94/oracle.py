"""Frozen finite-image expectations, independently classified before Rust exists."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import random
import struct

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
SOURCE = ROOT / 'src/node94-endpoint-gate'
MODULUS = 1 << 64
MASK = MODULUS - 1
INPUT = '<QQQQQB8s'
OUTPUT = '<BQQ'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def expected(row):
    image_base, base, start, end, limit, length, contents = row
    span = (end - start) % MODULUS
    if length and image_base + length > MODULUS:
        return (1, 0, 0)
    if end < start or start > limit:
        return (0, 0, span)
    # These ordered obligations encode the observed short-circuit read paths.
    for index, missing_tag in ((start, 2), (end, 3)):
        if index > limit:
            return (0, 0, span)
        if index == limit:
            continue
        address = (base + index) % MODULUS
        if address not in range(image_base, image_base + length):
            return (missing_tag, 0, 0)
        value = contents[address - image_base]
        signed = value if value < 128 else value - 256
        if signed <= -65:
            return (0, 0, span)
    return (0, (base + start) % MODULUS, span)


def corpus():
    rows = []
    def add(ib, base, start, end, limit, content=b'', length=None):
        require(len(content) <= 8, 'fixture capacity')
        n = len(content) if length is None else length
        require(0 <= n <= len(content), 'fixture length')
        rows.append((ib, base, start, end, limit, n, content.ljust(8, b'\0')))
    for first in range(256):
        for last in range(256):
            add(0x1000, 0x1000, 0, 1, 2, bytes((first, last)))
    for byte in range(256):
        for start, end, limit in ((0,0,1),(0,1,1),(1,1,1)):
            add(0, 0, start, end, limit, bytes((byte,)))
    edges = (0,1,2,7,8,1<<63,MASK)
    for ib, base, data in ((0,0,b'\x7f\x80\xbf\xc0\xffabc'),
                            (0x1000,0x1000,b'\xc0\xbf\x80\x7f\xffabc'),
                            (MASK-7,MASK-7,b'\xff\xc0\x7f\x80\xbfabc'),
                            (0,MASK,b'\xc0\x7f\x00\xff\xbfabc')):
        for start in edges:
            for end in edges:
                for limit in edges:
                    add(ib,base,start,end,limit,data)
    # Unmapped start must win over a later invalid end; a failed start gate
    # must skip an unmapped end; a wrapped success can have RAX == zero.
    for ib, base in ((0,0),(0x1000,0),(MASK,MASK),(MASK-7,MASK-7)):
        for length in range(9):
            for start,end,limit in ((0,1,2),(0,2,1),(1,1,1),(1,1,2),
                                    (2,1,0),(0,MASK,1),(MASK,MASK,MASK)):
                add(ib,base,start,end,limit,b'\x80\xc0abcdef',length)
    for index in edges:
        add(0,(-index)%MODULUS,index,index,index)
    rng = random.Random(0x3cd2460)
    for _ in range(10000):
        ib = rng.choice((0,0x1000,MASK-7,MASK-3,MASK,rng.getrandbits(64)))
        base = rng.choice((ib,(ib-1)%MODULUS,(ib+1)%MODULUS,rng.getrandbits(64)))
        start,end,limit = [rng.choice((*edges,rng.randrange(10),rng.getrandbits(64))) for _ in range(3)]
        add(ib,base,start,end,limit,rng.randbytes(8),rng.randrange(9))
    return rows


def fixtures():
    rows=corpus(); results=[expected(row) for row in rows]
    inputs=b''.join(struct.pack(INPUT,*row) for row in rows)
    outputs=b''.join(struct.pack(OUTPUT,*row) for row in results)
    record={'cases':len(rows),'input_bytes':len(inputs),'output_bytes':len(outputs),
            'input_sha256':sha(inputs),'expected_sha256':sha(outputs),
            'tags':{str(tag):sum(r[0]==tag for r in results) for tag in range(4)},
            'all_byte_pairs':65536,'same_index_and_skipped_endpoint_byte_cases':768,
            'oracle_sha256_at_freeze':sha(Path(__file__).read_bytes()),
            'source_directory_existed_at_freeze':False,'captured_code_executed':False}
    return inputs,outputs,record


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--freeze',action='store_true');args=parser.parse_args()
    inputs,outputs,record=fixtures()
    if args.freeze:
        require(not SOURCE.exists(),'Rust exists before independent freeze')
        for name,data in (('inputs',inputs),('expected',outputs)):
            with (PACKET/(name+'.bin.gz')).open('xb') as f:f.write(gzip.compress(data,mtime=0))
        with (PACKET/'frozen.json').open('x') as f:f.write(json.dumps(record,indent=2,sort_keys=True)+'\n')
    else:
        require(json.loads((PACKET/'frozen.json').read_text())==record,'frozen metadata')
        for name,data in (('inputs',inputs),('expected',outputs)):
            require(gzip.decompress((PACKET/(name+'.bin.gz')).read_bytes())==data,'frozen stream')
    print(json.dumps(record,indent=2))


if __name__=='__main__':main()
