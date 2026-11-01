"""Pre-Rust acyclic byte-origin equations for six bounded SIMD selection leaves."""
from pathlib import Path
import hashlib,gzip,json,random,struct
PACKET=Path(__file__).resolve().parent
ROOT=PACKET.parents[2]
N=1<<64
WIDTH=640
SIZES=[32,48,96,192,144,288]
def require(ok,message):
    if not ok:raise ValueError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def corpus():
    rows=set();bases=[0,1,0x1000,N-WIDTH]
    controls=[0,1,2,0x7fffffff,0x80000000,0xffffffff,1<<32,(1<<32)+1,1<<63,N-1]
    def add(member,base,a,b,d,control,length=WIDTH,salt=0,rax=0xfedcba9876543210):
        image=bytes(((i*73)^((i//7)*31)^salt)%256 for i in range(WIDTH))
        rows.add((member,base,(base+a)%N,(base+b)%N,(base+d)%N,control,rax,length,image))
    for member,width in enumerate(SIZES):
        for destination in range(353):
            for control in [0,1]:add(member,0,64,160,destination,control,salt=destination)
        for base in bases:
            for a,b,d in [(0,288,128),(64,160,96),(64,160,191),(64,160,192),(64,160,193),(0,0,0),(32,16,0),(352,0,336)]:
                for control in controls:add(member,base,a,b,d,control,salt=control%256)
        for bit in range(64):
            for delta in [-1,0,1]:
                control=((1<<bit)+delta)%N;add(member,0,64,160,96,control,salt=bit,rax=control)
        for length in [0,1,15,16,31,32,47,48,63,64,95,96,127,128,143,144,191,192,255,256,287,288,319,320,351,352,383,384,415,416,447,448,495,496,543,544,639,640]:
            for a,b,d in [(0,width,0),(-32,0,0),(64,160,96),(0,0,width)]:
                for control in [0,1]:add(member,0,a,b,d,control,length)
        # Each original source is required even when its mask is zero.
        for control in [0,1]:
            add(member,0,0,width,0,control,width)
            add(member,0,width,0,0,control,width)
        # Reached spans fit below N, but the supplied interval itself wraps.
        add(member,N-320,0,0,0,1,WIDTH)
    rng=random.Random(0x5657540)
    for _ in range(800):
        member=rng.randrange(6);base=rng.choice(bases);a,b,d=[rng.randrange(400) for _ in range(3)];control=rng.choice([0,1<<32,rng.getrandbits(64)])
        add(member,base,a,b,d,control,rng.choice([640,640,639,320]),rng.randrange(256),rng.getrandbits(64))
    return sorted(rows)
def relation(row):
    member,base,a,b,d,control,rax,length,raw=row;width=SIZES[member]
    refused=((0,)*6,raw,False)
    if base+length>N:return refused
    offsets=[address-base for address in [a,b,d]]
    if any(offset<0 or offset+width>length for offset in offsets):return refused
    aa,bb,dd=offsets;selected=aa if control%(1<<32) else bb
    # Byte k is loaded before stores of block floor(k/16)-1 and later.
    # Only earlier destination blocks can supply a value; their byte results
    # have strictly smaller indices, so this origin relation is acyclic.
    output=[]
    for k in range(width):
        previous=selected+k-dd
        if 0<=previous<width and previous//16<=k//16-2:output.append(output[previous])
        else:output.append(raw[selected+k])
    final=raw[:dd]+bytes(output)+raw[dd+width:]
    registers=(1,rax,control,(d+width//2)%N,(a+width//2)%N,(b+width//2)%N)
    return registers,final,bytes(output)!=raw[selected:selected+width]
def fixtures():
    inputs=bytearray();expected=bytearray();counts={'cases':0,'refusals':0,'admitted_per_member':[0]*6,'staged_alias_differences_per_member':[0]*6}
    for row in corpus():
        registers,updated,staged=relation(row);inputs.extend(struct.pack('<8Q',*row[:-1])+row[-1]);expected.extend(struct.pack('<6Q',*registers)+updated);counts['cases']+=1;counts['refusals']+=registers[0]==0
        if registers[0]:counts['admitted_per_member'][row[0]]+=1
        counts['staged_alias_differences_per_member'][row[0]]+=staged
    return bytes(inputs),bytes(expected),{**counts,'inputs_sha256':sha(inputs),'expected_sha256':sha(expected),'oracle_sha256_at_freeze':sha(Path(__file__).read_bytes()),'static_sha256_at_freeze':sha((PACKET/'static.json').read_bytes()),'captured_code_executed':False}
if __name__=='__main__':
    require(not (ROOT/'src/node94-simd-selection-family').exists(),'freeze before Rust')
    inputs,expected,record=fixtures()
    for name,raw in [('inputs',inputs),('expected',expected)]:
        with (PACKET/(name+'.bin.gz')).open('xb') as f:f.write(gzip.compress(raw,compresslevel=1,mtime=0))
    record['source_directory_existed_at_freeze']=False
    with (PACKET/'frozen.json').open('x') as f:f.write(json.dumps(record,indent=2,sort_keys=True)+'\n')
    print(json.dumps(record,indent=2))
