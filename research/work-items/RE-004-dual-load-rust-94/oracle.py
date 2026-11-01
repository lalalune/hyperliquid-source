"""Pre-Rust byte-image relocation oracle for the complete u8 reachable window."""
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


def require(ok,message):
    if not ok:raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def corpus():
    static=json.loads((PACKET/'static.json').read_text())
    biases=sorted({0,1,4096,0x100000000,0x100000001,MASK,*[1<<bit for bit in range(64)],*[MASK^(1<<bit) for bit in range(64)]})
    rows=[(index,bias) for bias in biases for index in range(256)]
    for relocation in static['data_relocations']:
        for offset in (-1,0,1,2):rows.append((relocation['index'],(-relocation['addend']+offset)%MOD))
    rng=random.Random(0x4e48600)
    rows.extend((rng.randrange(256),rng.getrandbits(64)) for _ in range(4096))
    return rows


def fixtures():
    static=json.loads((PACKET/'static.json').read_text())
    a=bytes.fromhex(static['tables']['A']['hex']);b=bytes.fromhex(static['tables']['B']['hex'])
    rows=corpus();output=[];previous_bias=None;loaded=None
    for index,bias in rows:
        if bias!=previous_bias:
            # Materialize the whole relocated byte image, independent of the
            # later Rust per-entry mask selection and u64 wrapping addition.
            loaded=bytearray(b)
            for relocation in static['data_relocations']:
                offset=relocation['index']*8
                value=(bias+relocation['addend'])%MOD
                loaded[offset:offset+8]=bytes((value//256**j)%256 for j in range(8))
            previous_bias=bias
        at=index*8
        output.append(bytes(loaded[at:at+8])+a[at:at+8])
    inputs=b''.join(struct.pack('<BQ',*row) for row in rows);expected=b''.join(output)
    relocated={r['index'] for r in static['data_relocations']}
    record={'cases':len(rows),'inputs_sha256':sha(inputs),'expected_sha256':sha(expected),
            'input_record_bytes':9,'output_record_bytes':16,'reachable_words_per_window':256,
            'relocated_entries':len(relocated),'raw_entries':256-len(relocated),
            'relocated_cases':sum(i in relocated for i,_ in rows),
            'raw_cases':sum(i not in relocated for i,_ in rows),
            'biases':len({b for _,b in rows}),'oracle_sha256_at_freeze':sha(Path(__file__).read_bytes()),
            'static_sha256_at_freeze':sha((PACKET/'static.json').read_bytes()),
            'source_directory_existed_at_freeze':False,'captured_code_executed':False}
    return inputs,expected,record


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--freeze',action='store_true');args=parser.parse_args()
    inputs,expected,record=fixtures()
    if args.freeze:
        require(not (ROOT/'src/node94-dual-load').exists(),'Rust exists before freeze')
        for name,raw in [('inputs',inputs),('expected',expected)]:
            with (PACKET/(name+'.bin.gz')).open('xb') as f:f.write(gzip.compress(raw,mtime=0))
        with (PACKET/'frozen.json').open('x') as f:f.write(json.dumps(record,indent=2,sort_keys=True)+'\n')
    else:
        require(json.loads((PACKET/'frozen.json').read_text())==record,'frozen metadata')
        for name,raw in [('inputs',inputs),('expected',expected)]:
            require(gzip.decompress((PACKET/(name+'.bin.gz')).read_bytes())==raw,'frozen stream')
    print(json.dumps(record,indent=2))


if __name__=='__main__':main()
