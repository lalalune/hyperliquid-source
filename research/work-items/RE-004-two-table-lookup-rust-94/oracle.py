"""Pre-Rust oracle: categorical gate, unbounded affine address, byte-address map."""
import gzip
import struct
from verify_static import ROOT, PACKET, TARGET, encoded, require, sha

MOD = 1 << 64
MASK = MOD - 1
SIZE = 512
HEADER = struct.Struct('<QQQQQH')
OUTPUT = struct.Struct('<BQ')
A, B = 0x576d9e0, 0x576db20


def address(bias, first, mode, row):
    x = first % (1 << 32)
    y = struct.unpack('<i', (row % (1 << 32)).to_bytes(4, 'little'))[0]
    # The oracle uses literal membership, not the implementation's wrapped
    # subtraction/unsigned gate, and one unbounded affine byte expression.
    if x in (3, 4, 5) and mode % (1 << 32) == 1:
        return (bias + B + {3: 0, 4: 8, 5: 16}[x] + 24*y) % MOD
    signed_x = struct.unpack('<i', x.to_bytes(4, 'little'))[0]
    return (bias + A + 8*signed_x + 80*y) % MOD


def expected(row):
    base, bias, first, mode, index, length, image = row
    if length and base + length > MOD:
        return (1, 0)
    selected = address(bias, first, mode, index)
    memory = dict(zip(range(base, base + length), image[:length]))
    if not all(selected+k in memory for k in range(8)):
        return (2, 0)
    return (0, sum(memory[selected+k] * 256**k for k in range(8)))


def corpus():
    rows = set()
    def add(first=3, mode=1, index=0, bias=0, base=None, position=128, length=SIZE, seed=19, words=()):
        selected = address(bias, first, mode, index)
        if base is None:base=(selected-position)%MOD
        image=bytearray((seed+37*j+17*(j//8))%256 for j in range(SIZE))
        for at,value in words:
            if 0<=at<=SIZE-8:image[at:at+8]=value.to_bytes(8,'little')
        rows.add((base,bias,first,mode,index,length,bytes(image)))
    # Dense same-image ranges exercise overlapping reachable addresses in the
    # two addressing formulae without assigning any logical table extent.
    for first in range(16):
        for mode in [0,1,2,0xffffffff,0x100000001]:
            for index in range(-8,9):add(first,mode,index%MOD,base=A-128,seed=first+mode%256)
    edges=[0,1,2,3,4,5,6,7,255,0x7fffffff,0x80000000,0xfffffffd,0xfffffffe,0xffffffff]
    uppers=[0,0x100000000,0xffffffff00000000]
    modes=[0,1,2,0x100000000,0x100000001,0x8000000000000001,MASK]
    for first in edges:
        for index in edges:
            for upper in uppers:
                for mode in modes:
                    for position in [64,384]:
                        add(first+upper,mode,index+upper,position=position,seed=(first+index)%256)
    # Each low32 bit plus independently varied high halves in all inputs.
    for bit in range(64):
        for x,m,y in [(1<<bit,1,0),(3,1<<bit,0),(4,1,1<<bit),(5,1,(MASK^(1<<bit)))]:
            add(x,m,y,position=64);add(x,m,y,position=384)
    # Runtime base addition can wrap even though signed affine products fit i64.
    for first,mode,index in [(0,0,0),(3,1,0),(4,1,0xffffffff),(5,1,0x80000000),(0x80000000,0,0xffffffff),(MASK,0,MASK)]:
        for bias in [0,1,0x100000,2**63,MOD-A,MOD-B,MASK]:
            for position in [0,1,7,8,63,64,384,504,505,511]:
                add(first,mode,index,bias,position=position)
        unbased=address(0,first,mode,index)
        for selected in [0,1,7,8,64,504,505,511,MOD-512,MOD-8,MOD-7,MASK]:
            bias=(selected-unbased)%MOD
            for base in [0,MOD-SIZE]:
                for length in [0,1,7,8,64,511,512]:add(first,mode,index,bias,base=base,length=length)
    for position in [0,1,7,8,63,64,384,504,505,511]:
        for length in sorted({0,1,7,8,position,max(0,position+7),min(SIZE,position+8),SIZE}):
            if length<=SIZE:
                for first,mode in [(0,0),(3,1),(4,1),(5,1),(6,1)]:add(first,mode,position=position,length=length)
    for base in [MOD-SIZE+1,MOD-8,MASK]:
        for length in [0,1,7,8,SIZE]:add(base=base,length=length)
    # Original relocated base qwords are exact numeric samples, not extents.
    for bias in [0,0x100000,2**63,MASK]:
        add(0,0,0,bias,position=64,words=[(64,(bias+0x5585670)%MOD)])
        add(3,1,0,bias,position=64,words=[(64,(bias+0x55af100)%MOD)])
    for value in [0,1,255,256,2**32-1,2**32,2**63-1,2**63,MASK]:
        for first,mode in [(0,0),(3,1),(4,1),(5,1)]:add(first,mode,words=[(128,value)])
    for i in range(1024):
        digest=bytes.fromhex(sha(f'two-table-lookup94:{i}'.encode()))
        first,mode,index,bias=struct.unpack('<QQQQ',digest)
        if i%3==0:first=3+i%3;mode=(mode&0xffffffff00000000)+1
        add(first,mode,index,bias,position=digest[0]*2,length=SIZE if i%2 else int.from_bytes(digest[1:3],'little')%(SIZE+1),seed=digest[3])
    return sorted(rows)


def fixtures():
    rows=corpus();answers=[expected(row) for row in rows]
    inputs=b''.join(HEADER.pack(*r[:6])+r[6] for r in rows)
    outputs=b''.join(OUTPUT.pack(*r) for r in answers)
    counts={str(tag):sum(r[0]==tag for r in answers) for tag in range(3)}
    require(all(counts.values()),'all outcomes represented')
    return inputs,outputs,{'target_sha256':TARGET,'cases':len(rows),'input_record_bytes':HEADER.size+SIZE,
        'output_record_bytes':OUTPUT.size,'image_bytes':SIZE,'outcome_counts':counts,
        'inputs_sha256':sha(inputs),'expected_sha256':sha(outputs),
        'oracle':'literal low32 category membership, unbounded affine byte address, immutable numeric byte-address map',
        'refusals':'new nonwrapping image / selected qword range refusals, not original faults',
        'fixture_archive':{'compression':'gzip','level':1,'mtime':0}}


def main():
    import sys
    require(sys.argv[1:]==['--freeze'],'only --freeze supported')
    require(not (ROOT/'src/node94-two-table-lookup').exists(),'freeze before Rust')
    inputs,outputs,record=fixtures()
    record.update(oracle_sha256_at_freeze=sha((PACKET/'oracle.py').read_bytes()),static_sha256_at_freeze=sha((PACKET/'static.json').read_bytes()),rust_source_existed_at_freeze=False)
    for name,raw in [('inputs',inputs),('expected',outputs)]:
        with (PACKET/(name+'.bin.gz')).open('xb') as file:file.write(gzip.compress(raw,compresslevel=1,mtime=0))
    with (PACKET/'frozen.json').open('xb') as file:file.write(encoded(record))
    print(encoded(record).decode(),end='')


if __name__=='__main__':main()
