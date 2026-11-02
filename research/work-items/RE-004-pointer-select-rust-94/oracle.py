"""Pre-Rust closed-address and positional-byte relation for the low32 selector."""
from pathlib import Path
import gzip
import hashlib
import json
import random
import struct

PACKET=Path(__file__).resolve().parent
ROOT=PACKET.parents[2]
N=1<<64
SIZE=2048


def sha(raw):return hashlib.sha256(raw).hexdigest()
def require(ok,why):
    if not ok:raise ValueError(why)


def corpus():
    rows=set()
    def add(base,alternative,selector,value,length=SIZE,salt=0):
        data=bytearray((i*41+(i>>3)+salt)%256 for i in range(SIZE))
        for at,v in [(alternative,value),(alternative+1784,value^0x89abcdef01234567)]:
            if 0<=at<=SIZE-8:data[at:at+8]=v.to_bytes(8,'little')
        obj=(base+alternative-0xe590)%N
        for member,adjustment in enumerate([0,24,0x29b0]):
            rows.add((member,base,(obj-adjustment)%N,selector,length,bytes(data)))
    bases=[0,1,1<<32,1<<63,N-SIZE]
    placements=[-1784,-1776,-8,0,1,7,8,128,255,256,257,2040,2041,2048]
    selectors=[0,1,2,255,256,257,0x10001,0xffffffff,1<<32,(1<<32)+1,(1<<32)+2,1<<63,(1<<63)+1,N-1,N-(1<<32)+1]
    values=[0,1,N-1,0x81234567fedcba98]
    for base in bases:
        for at in placements:
            for selector in selectors:
                for i,v in enumerate(values):add(base,at,selector,v,salt=i)
        for bit in range(64):
            for delta in [-1,0,1]:
                selector=((1<<bit)+delta)%N
                add(base,8,selector,(1<<bit),salt=bit)
                add(base,8,(((1<<bit)<<32)|1)%N,N-1-(1<<bit),salt=bit)
    for length in [0,1,7,8,9,15,16,127,128,135,136,255,256,263,264,1783,1784,1791,1792,1799,1800,2040,2047,2048]:
        for at in placements:
            for selector in [1,2,(1<<32)+1]:add(0,at,selector,0x8877665544332211,length)
    for selector in selectors:add(0xe588,8,selector,0xfedcba9876543210) # object zero
    # Exercise zero objects and each intermediate wrapper-addition carry.
    for adjustment in [24,0x29b0]:
        for delta in [0,1,8,23,24,0x2997,0x2998,0x29af]:
            for selector in [1,2,(1<<32)+1]:
                add((0xe590+adjustment-delta-8)%N,8,selector,0x12345678fedcba98)
    # Invalid whole image, but the selected qword remains below 2^64.
    add(N-1024,8,1,0x1122334455667788)
    add(N-1024,-1776,2,0x1122334455667788)
    rng=random.Random(0x552cac0)
    for i in range(1200):
        add(rng.choice(bases),rng.choice(placements),rng.choice(selectors+[rng.getrandbits(64)]),rng.getrandbits(64),rng.choice([SIZE,SIZE,1800,264,16]),i)
    return sorted(rows)


def relation(row):
    member,base,obj,selector,length,data=row
    if base+length>N:return (0,0,0,0),'image',{}
    # Collapse both address additions into a single mathematical field address;
    # derive RDI backwards from it, rather than mirroring the library sequence.
    alternative=selector%(1<<32)==1
    adjustment=[0,24,0x29b0][member]
    address=(obj+adjustment+(0xe590 if alternative else 0xec88))%N
    offset=address-base
    if offset<0 or offset+8>length:return (0,0,0,0),'missing',{}
    value=sum(data[offset+i]*256**i for i in range(8))
    selected=(address-120)%N
    other=(obj+adjustment+(0xec88 if alternative else 0xe590))%N
    return (1,value,selected,selector),'alternative' if alternative else 'default',{
        'address':address,'base_unmapped':not(base<=selected<base+length),
        'unused_absent':not(base<=other and other+8<=base+length),
        'field_addition_wrap':selected+120>=N,'exact_end':offset+8==length}


def fixtures():
    inputs=bytearray();expected=bytearray()
    counts={'cases':0,'outcomes':{},'admitted_by_member':[0,0,0],'refused_by_member':[0,0,0],'unused_field_absent':{'alternative':0,'default':0},
            'preserved_nonzero_selector_high32':0,'alternative_with_nonzero_high32':0,
            'selected_base_unmapped':0,'field_addition_wrap':0,'exact_end':0,'zero_object_admitted':0}
    for row in corpus():
        result,outcome,info=relation(row);member,base,obj,selector,length,data=row
        inputs.extend(struct.pack('<5Q',member,base,obj,selector,length)+data)
        expected.extend(struct.pack('<4Q',*result));counts['cases']+=1
        counts['outcomes'][outcome]=counts['outcomes'].get(outcome,0)+1
        counts['admitted_by_member' if result[0] else 'refused_by_member'][member]+=1
        if result[0]:
            counts['unused_field_absent'][outcome]+=info['unused_absent']
            counts['preserved_nonzero_selector_high32']+=selector>>32!=0
            counts['alternative_with_nonzero_high32']+=selector>>32!=0 and outcome=='alternative'
            counts['selected_base_unmapped']+=info['base_unmapped'];counts['field_addition_wrap']+=info['field_addition_wrap']
            counts['exact_end']+=info['exact_end'];counts['zero_object_admitted']+=obj==0
    return bytes(inputs),bytes(expected),{**counts,'input_record_bytes':2088,'output_record_bytes':32,
        'inputs_sha256':sha(inputs),'expected_sha256':sha(expected),
        'oracle_sha256_at_freeze':sha(Path(__file__).read_bytes()),'static_sha256_at_freeze':sha((PACKET/'static.json').read_bytes()),
        'target_sha256':'3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f',
        'captured_execution':False,'instruction_emulation':False}


if __name__=='__main__':
    require(not(ROOT/'src/node94-pointer-select').exists(),'freeze before Rust')
    inputs,expected,record=fixtures();record['rust_source_existed_at_freeze']=False
    for name,raw in [('inputs',inputs),('expected',expected)]:
        with(PACKET/(name+'.bin.gz')).open('xb')as f:f.write(gzip.compress(raw,compresslevel=1,mtime=0))
    with(PACKET/'frozen.json').open('xb')as f:f.write((json.dumps(record,indent=2,sort_keys=True)+'\n').encode())
    print(json.dumps(record,sort_keys=True))
