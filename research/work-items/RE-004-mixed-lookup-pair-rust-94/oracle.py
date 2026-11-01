"""Pre-Rust expectations from raw numeric bytes and unbounded integer math."""
import gzip
import struct
from verify_static import ROOT,PACKET,TARGET,encoded,sha,require
MOD=1<<64
MASK=MOD-1
BASES=[0x3f7ba0,0x402728]
INPUT=struct.Struct('<BQQ')
OUTPUT=struct.Struct('<QQ')


def corpus():
    rows=set()
    uppers=[0,1<<8,1<<32,1<<63,MASK^255]
    for member in [0,1]:
        raw=(PACKET/f'data{member}.bin').read_bytes()
        for byte in range(256):
            for upper in uppers:
                for bias in [0,1,0x100000,1<<63,MASK]:rows.add((member,upper|byte,bias))
            # Deliberately cross both sides of the returned-address wrap.
            bits=int.from_bytes(raw[0x288+byte*4:0x28c+byte*4],'little')
            signed=bits-(1<<32) if bits>=1<<31 else bits
            for target in [0,1,MASK]:rows.add((member,byte,(target-BASES[member]-signed)%MOD))
        for bit in range(64):
            for low in [0,1,5,127,128,255]:
                for tag in [(1<<bit)|low,MASK^(1<<bit)]:rows.add((member,tag,1<<bit))
    return sorted(rows)


def fixtures():
    raw_tables=[(PACKET/f'data{n}.bin').read_bytes() for n in [0,1]]
    rows=corpus();inputs=bytearray();expected=bytearray();negative=positive=0
    for member,tag,bias in rows:
        byte=tag%256;raw=raw_tables[member]
        qword=sum(raw[8*byte+k]*256**k for k in range(8))
        bits=sum(raw[0x288+4*byte+k]*256**k for k in range(4))
        offset=bits-(1<<32) if bits>=1<<31 else bits
        negative+=offset<0;positive+=offset>=0
        address=(bias+BASES[member]+offset)%MOD
        inputs.extend(INPUT.pack(member,tag,bias));expected.extend(OUTPUT.pack(address,qword))
    return bytes(inputs),bytes(expected),{'target_sha256':TARGET,'cases':len(rows),'members':2,'all_byte_indices_per_member':256,
        'negative_offset_cases':negative,'nonnegative_offset_cases':positive,'input_record_bytes':17,'output_record_bytes':16,
        'inputs_sha256':sha(inputs),'expected_sha256':sha(expected),'data_sha256':[sha(x) for x in raw_tables],
        'oracle':'raw little-endian byte polynomials, explicit two-complement subtraction, single unbounded base+bias+offset modulo64',
        'fixture_compression':{'format':'gzip','level':1,'mtime':0}}


def main():
    import sys
    require(sys.argv[1:]==['--freeze'],'only --freeze supported')
    require(not (ROOT/'src/node94-mixed-lookup-pair').exists(),'freeze before Rust')
    inputs,expected,record=fixtures();record.update(oracle_sha256_at_freeze=sha((PACKET/'oracle.py').read_bytes()),static_sha256_at_freeze=sha((PACKET/'static.json').read_bytes()),rust_source_existed_at_freeze=False)
    for name,raw in [('inputs',inputs),('expected',expected)]:
        with (PACKET/(name+'.bin.gz')).open('xb') as f:f.write(gzip.compress(raw,compresslevel=1,mtime=0))
    with (PACKET/'frozen.json').open('xb') as f:f.write(encoded(record))
    print(encoded(record).decode(),end='')


if __name__=='__main__':main()
