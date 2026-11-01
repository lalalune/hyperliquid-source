"""Independent byte-overlay expectations, frozen before Rust source creation."""
from pathlib import Path
import gzip
import hashlib
import json
import struct

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
MASK = 2**64 - 1
IMAGE = 320
HEADER = struct.Struct('<QQQQQQH')  # image base, object, returned base, index, out, table base, length
OUTPUT = struct.Struct('<BQ')

def require(ok, message):
    if not ok:
        raise ValueError(message)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def expected(row):
    image_base, obj, base, raw_index, out, table, length, image = row
    def result(code, value=0, changed=None):
        return OUTPUT.pack(code, value) + (image if changed is None else changed)
    if length and image_base + length - 1 > MASK:
        return result(1)
    def span(address, width):
        offset = address - image_base
        return offset if 0 <= address <= MASK and 0 <= offset and offset + width <= length else None
    index = raw_index % 2**32
    selector = 0
    if obj:
        presence = span(obj + 144, 8)
        if presence is None:
            return result(2)
        if any(image[presence:presence+8]):
            selected = span(obj + 161 + index, 1)
            if selected is None:
                return result(2)
            selector = image[selected]
    output = None if out == 0 else span(out, 4)
    if out and output is None:
        return result(3)
    cell = span(table + 4*index, 4)
    if cell is None:
        return result(4)
    # Algebraic overlay: each post-store byte independently selects its old
    # value or one digit of the zero-extended selector. No instruction model.
    digit = lambda i: selector if i == 0 else 0
    final = bytes(digit(i-output) if output is not None and output <= i < output+4
                  else image[i] for i in range(IMAGE))
    entry = sum(final[cell+i] * 256**i for i in range(4))
    return result(0, (base + entry + 224*selector) % 2**64, final)

def corpus():
    rows = set()
    def make(selector=7, present=1, index=0, bias=4096, relative_out=256,
             base=MASK-10, length=IMAGE, null=False, raw_high=0):
        image = bytearray((13*i+selector) % 256 for i in range(IMAGE))
        image[160:168] = present.to_bytes(8,'little')
        if 177+index < IMAGE:
            image[177+index] = selector
        if 256+4*index+4 <= IMAGE:
            image[256+4*index:260+4*index] = (0xfedcba98 ^ (selector*0x01010101)).to_bytes(4,'little')
        out = 0 if relative_out is None else (bias+relative_out) % 2**64
        rows.add((bias,0 if null else (bias+16) % 2**64,base,
                  (raw_high*2**32+index) % 2**64,out,(bias+256) % 2**64,length,bytes(image)))
    for selector in range(256):
        index=selector % 8
        for present in (0,1):
            for displacement in range(-3,4):
                make(selector,present,index,relative_out=256+4*index+displacement)
            make(selector,present,index,relative_out=None)
    for index in range(16):
        for selector in (0,1,127,128,255):
            for bias in (0,4096,MASK-319):
                for out in (None,160,177+index,316):
                    make(selector,MASK,index,bias,out,raw_high=0x87654321)
    for length in (0,1,16,144,160,167,168,177,178,255,256,259,260,319,320):
        for out in (None,0,160,256,316,318):
            for null in (False,True):
                make(length=length,relative_out=out,null=null)
    for index in (16,31,255,2**31,2**32-1):
        for present in (0,1,MASK):
            for null in (False,True):
                make(index=index,present=present,null=null,relative_out=None)
    for bias in (MASK-318,MASK-16,MASK):
        make(bias=bias)
    for index in range(256):
        digest=hashlib.sha256(f'node94-table-offset:{index}'.encode()).digest()
        make(selector=digest[0],present=int.from_bytes(digest[1:9],'little'),index=digest[9]%16,
             base=int.from_bytes(digest[10:18],'little'),relative_out=256+4*(digest[9]%16)+digest[18]%7-3)
    return sorted(rows)

def fixtures():
    rows=corpus()
    inputs=b''.join(HEADER.pack(*row[:7])+row[7] for row in rows)
    outputs=b''.join(expected(row) for row in rows)
    outcomes=[expected(row)[0] for row in rows]
    record={'cases':len(rows),'input_bytes_per_case':HEADER.size+IMAGE,
            'output_bytes_per_case':OUTPUT.size+IMAGE,'image_bytes':IMAGE,
            'outcome_counts':{str(code):outcomes.count(code) for code in range(5)},
            'inputs_sha256':sha(inputs),'expected_sha256':sha(outputs),
            'domain':'bounded nonwrapping mutable byte image with explicit runtime table base',
            'method':'per-byte immutable output-store overlay followed by base256 table digit sum',
            'refusals':'new safe API preflight policy; not native fault observations'}
    return inputs,outputs,record

if __name__=='__main__':
    import sys
    require(sys.argv[1:]==['--freeze'],'only --freeze is supported')
    require(not (ROOT/'src/node94-table-offset-alias').exists(),'freeze must precede Rust')
    inputs,outputs,record=fixtures()
    record['oracle_sha256_at_freeze']=sha(Path(__file__).read_bytes())
    record['rust_source_existed_at_freeze']=False
    for name,raw in [('inputs',inputs),('expected',outputs)]:
        with (PACKET/(name+'.bin.gz')).open('xb') as f:f.write(gzip.compress(raw,mtime=0))
    with (PACKET/'frozen.json').open('x') as f:
        json.dump(record,f,indent=2,sort_keys=True);f.write('\n')
    print(json.dumps(record,indent=2))
