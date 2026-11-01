"""Pre-Rust quotient equation oracle, independent of the native modular multiply."""
import argparse
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path
import random
import struct

PACKET=Path(__file__).resolve().parent
ROOT=PACKET.parents[2]
MOD=1<<64
INPUT=struct.Struct('<QQQ')
OUTPUT=struct.Struct('<QQ')


def require(condition,message):
    if not condition:raise ValueError(message)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def scaled(count):
    # 2**64 == 5 mod11; the inverse of 5 mod11 is 9. Choose the unique k
    # in0..10 making count+k*2**64 divisible by11. The quotient is in0..2**64.
    k=(-9*count)%11
    numerator=count+k*MOD
    require(numerator%11==0,'exact integer quotient')
    value=numerator//11
    require(0<=value<MOD,'unique modular solution')
    return value


def expected(row):
    cursor,end,request=row
    count=((end-cursor)%MOD)//8
    taken=min(request,scaled(count))
    return (cursor+88*taken)%MOD,request-taken


def corpus():
    rng=random.Random(0x4ea41e0)
    rows=set()
    maximum=(1<<61)-1
    counts=set(range(128))|{maximum-i for i in range(32)}
    for bit in range(61):
        for delta in (-1,0,1):counts.add(max(0,min(maximum,(1<<bit)+delta)))
    for count in counts:
        threshold=scaled(count)
        requests={0,1,threshold,max(threshold-1,0),min(threshold+1,MOD-1),MOD-1}
        for low in range(8):
            span=count*8+low
            for cursor in (0,1234,MOD-2049,MOD-1):
                for request in requests:rows.add((cursor,(cursor+span)%MOD,request))
    # Explicit normalized spans and ordinary element-count expectations.
    for elements in [*range(256),(MOD-1)//88,((MOD-1)//88)-1]:
        for cursor in (0,1,12345):
            if cursor+88*elements>=MOD:continue
            for request in (0,1,max(elements-1,0),elements,min(elements+1,MOD-1),MOD-1):
                rows.add((cursor,cursor+88*elements,request))
    for _ in range(4096):rows.add(tuple(rng.randrange(MOD) for _ in range(3)))
    return sorted(rows)


def fixtures():
    rows=corpus();results=[expected(row) for row in rows]
    inputs=b''.join(INPUT.pack(*row) for row in rows)
    outputs=b''.join(OUTPUT.pack(*row) for row in results)
    canonical=[row for row in rows if row[1]>=row[0] and (row[1]-row[0])%88==0]
    for row in canonical:
        cursor,end,request=row;taken=min(request,(end-cursor)//88)
        require(expected(row)==(cursor+88*taken,request-taken),'canonical exact division')
    meta={'cases':len(rows),'canonical_spans':len(canonical),
          'input_record_bytes':INPUT.size,'output_record_bytes':OUTPUT.size,
          'inputs_sha256':sha(inputs),'expected_sha256':sha(outputs),
          'count_residues_mod11':dict(sorted(Counter(str((((end-cursor)%MOD)//8)%11) for cursor,end,request in rows).items())),
          'low_span_bits':dict(sorted(Counter(str((end-cursor)%8) for cursor,end,request in rows).items()))}
    return inputs,outputs,meta


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--freeze',action='store_true');args=parser.parse_args()
    inputs,outputs,meta=fixtures();meta['oracle_sha256_at_freeze']=sha(Path(__file__).read_bytes())
    if args.freeze:
        require(not (ROOT/'src/node94-scaled-advance').exists(),'freeze before Rust')
        for name,raw in [('inputs',inputs),('expected',outputs)]:
            with (PACKET/(name+'.bin.gz')).open('xb') as f:f.write(gzip.compress(raw,mtime=0))
        with (PACKET/'frozen.json').open('x') as f:json.dump(meta,f,indent=2,sort_keys=True);f.write('\n')
    else:
        require(json.loads((PACKET/'frozen.json').read_text())==meta,'oracle freeze drift')
        for name,raw in [('inputs',inputs),('expected',outputs)]:
            require(gzip.decompress((PACKET/(name+'.bin.gz')).read_bytes())==raw,'fixture drift')
    print(json.dumps(meta,indent=2,sort_keys=True))


if __name__=='__main__':main()
