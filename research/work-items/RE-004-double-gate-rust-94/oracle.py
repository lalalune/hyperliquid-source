"""Pre-Rust image oracle with exact integer-significand IEEE754 comparison."""
import gzip
import struct
from verify_static import ROOT,PACKET,TARGET,encoded,require,sha
MOD=1<<64
MASK=MOD-1
SIZE=128
HEADER=struct.Struct('<QQBH')
OUTPUT=struct.Struct('<BQ')


def expected(row):
    base,obj,mode,length,image=row
    if base+length>MOD:return (1,0)
    memory=dict(zip(range(base,base+length),image[:length]))
    def word(address):
        if not all(address+k in memory for k in range(8)):return None
        return sum(memory[address+k]*256**k for k in range(8))
    pointer=word((obj+0xf38)%MOD)
    if pointer is None:return (2,0)
    bits=word(pointer)
    if bits is None:return (3,0)
    sign=bits//(1<<63);exponent=(bits>>52)%2048;fraction=bits%(1<<52)
    nan=exponent==2047 and fraction!=0
    denormal=exponent==0 and fraction!=0
    if nan and mode%2==0:return (4,0)
    if denormal and mode//4==0 and (mode//2)%2==0:return (5,0)
    if nan or sign:meets=False
    elif exponent==2047:meets=True
    else:
        significand=fraction+(1<<52 if exponent else 0)
        if exponent==0 and mode//4:significand=0
        shift=(exponent if exponent else 1)-1023-52
        meets=(significand<<shift)>=1 if shift>=0 else significand>=1<<(-shift)
    return (0,(pointer//256)*256+int(meets))


def corpus():
    rows=set()
    def add(bits=0x3ff0000000000000,mode=3,base=4096,field=16,payload=80,length=SIZE,seed=19,raw_pointer=None):
        image=bytearray((seed+37*j+17*(j//8))%256 for j in range(SIZE))
        def put(at,value):
            if 0<=at<=SIZE-8:image[at:at+8]=value.to_bytes(8,'little')
        # Overlap cases form one final immutable image. Pointer bytes are last,
        # so aliased payload bits are subsequently read from that final image.
        put(payload,bits)
        if payload!=96:put(96,0 if bits==0x3ff0000000000000 else 0x3ff0000000000000)
        put(field+8,(base+96)%MOD)
        put(field,(base+payload)%MOD if raw_pointer is None else raw_pointer)
        rows.add((base,(base+field-0xf38)%MOD,mode,length,bytes(image)))
    fractions=[0,1,(1<<52)-1]
    bases=[0,4096,1<<32,1<<63,MOD-SIZE]
    for exponent in range(2048):
        for sign in [0,1]:
            for fraction in fractions:
                add((sign<<63)+(exponent<<52)+fraction,base=bases[exponent%5])
    special_fractions=[0,1,2,(1<<51)-1,1<<51,(1<<51)+1,(1<<52)-1]
    for exponent in [0,1,1022,1023,1024,2046,2047]:
        for sign in [0,1]:
            for fraction in special_fractions:
                for mode in range(8):add((sign<<63)+(exponent<<52)+fraction,mode)
    bit_patterns=[0,1,(1<<52)-1,1<<52,0x3fefffffffffffff,0x3ff0000000000000,0x3ff0000000000001,0x7fefffffffffffff,0x7ff0000000000000,0x7ff0000000000001,0x7ff8000000000000,0x8000000000000000,0xfff0000000000000,MASK]
    for low in range(256):
        for bits in [0,0x3fefffffffffffff,0x3ff0000000000000,0x7ff8000000000000]:add(bits,base=4096+low)
    for bits in bit_patterns:
        for mode in range(8):
            for base in bases:add(bits,mode,base)
            for payload in [0,1,8,9,15,16,17,23,24,25,31,32,79,80,120,121,127]:add(bits,mode,payload=payload)
    for field in [-8,-7,-1,0,1,16,120,121,127]:
        for length in [0,1,7,8,15,16,23,24,79,80,87,88,127,128]:
            for mode in [0,3,4,7]:add(mode=mode,field=field,length=length)
    for pointer in [0,1,7,8,16,80,120,121,127,128,255,1<<32,1<<63,MASK]:
        for mode in range(8):add(mode=mode,base=0,raw_pointer=pointer)
    for base in [MOD-SIZE+1,MOD-8,MASK]:
        for length in [0,1,7,8,SIZE]:add(base=base,length=length)
    for bit in range(64):
        for mode in range(8):
            add(1<<bit,mode,base=1<<bit)
            add(MASK^(1<<bit),mode,base=(1<<bit)-1)
    for i in range(1024):
        digest=bytes.fromhex(sha(f'double-gate94:{i}'.encode()));bits,base=struct.unpack('<QQ',digest[:16])
        add(bits,digest[16]%8,base,payload=digest[17]%(SIZE-7),length=SIZE if i%2 else digest[18]%(SIZE+1),seed=digest[19])
    return sorted(rows)


def fixtures():
    rows=corpus();answers=[expected(row) for row in rows]
    inputs=b''.join(HEADER.pack(*row[:4])+row[4] for row in rows);outputs=b''.join(OUTPUT.pack(*out) for out in answers)
    counts={str(tag):sum(out[0]==tag for out in answers) for tag in range(6)};require(all(counts.values()),'all outcomes represented')
    return inputs,outputs,{'target_sha256':TARGET,'cases':len(rows),'input_record_bytes':HEADER.size+SIZE,'output_record_bytes':9,'image_bytes':SIZE,'outcome_counts':counts,
        'exponent_sign_fraction_grid':2048*2*3,'inputs_sha256':sha(inputs),'expected_sha256':sha(outputs),
        'oracle':'numeric-address map, exact integer significand/exponent comparison, decimal byte-bucket return reconstruction',
        'mode_descriptor':'bit0 invalid masked, bit1 denormal masked, bit2 DAZ; this is not raw MXCSR',
        'fixture_compression':{'format':'gzip','level':1,'mtime':0}}


def main():
    import sys
    require(sys.argv[1:]==['--freeze'],'only --freeze supported');require(not (ROOT/'src/node94-double-gate').exists(),'freeze before Rust')
    inputs,outputs,record=fixtures();record.update(oracle_sha256_at_freeze=sha((PACKET/'oracle.py').read_bytes()),static_sha256_at_freeze=sha((PACKET/'static.json').read_bytes()),rust_source_existed_at_freeze=False)
    for name,raw in [('inputs',inputs),('expected',outputs)]:
        with (PACKET/(name+'.bin.gz')).open('xb') as f:f.write(gzip.compress(raw,compresslevel=1,mtime=0))
    with (PACKET/'frozen.json').open('xb') as f:f.write(encoded(record))
    print(encoded(record).decode(),end='')


if __name__=='__main__':main()
