"""Pre-Rust integer-domain partitions and immutable byte-map reads; no instruction stepping."""
from pathlib import Path
import hashlib,gzip,json,random,struct
PACKET=Path(__file__).resolve().parent
ROOT=PACKET.parents[2]
N=1<<64
WIDTH=128
def require(ok,message):
    if not ok:raise ValueError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def corpus():
    cases=set();bases=[0,1,0x1000,N-WIDTH]
    layouts=[(0,48),(-16,48),(-8,48),(8,64),(32,0),(64,64),(104,-16),(0,-16),(0,96),(0,104)]
    def add(member,base,oi,pi,flag,count,compared,target,length=128,salt=0):
        image=bytearray((i*37+salt)%256 for i in range(WIDTH))
        for off,size,value in [(oi+4,4,compared),(oi+8,8,(base+pi)%N),(oi+16,4,count),(oi+21,1,flag),(pi+16,8,target)]:
            if 0<=off and off+size<=WIDTH:image[off:off+size]=(value%(1<<(size*8))).to_bytes(size,'little')
        cases.add((member,base,(base+oi)%N,length,bytes(image)))
    counts=[0,1,2,0x7fffffff,0x80000000,0xffffffff]
    for member in range(2):
        for flag in range(256):
            for count in counts:
                signed=count if count<1<<31 else count-(1<<32)
                for delta in [-1,0,1]:
                    for target in [signed%N,(signed+1)%N]:add(member,0,0,48,flag,count,count+delta,target,salt=flag)
        for bit in range(32):
            for delta in [-1,0,1]:
                count=((1<<bit)+delta)%(1<<32);signed=count if count<1<<31 else count-(1<<32)
                for base in bases:
                    for flag in [0,1,255]:add(member,base,0,48,flag,count,count,signed%N,salt=bit)
        for length in [0,1,3,4,5,6,7,8,15,16,19,20,21,22,23,24,31,32,63,64,71,72,119,120,127,128]:
            for oi,pi in layouts:
                for flag,count,target in [(0,0,0),(255,1,0),(255,0xffffffff,N-1),(1,0x80000000,0x80000000)]:add(member,0,oi,pi,flag,count,0,target,length)
        for base in bases:
            for oi,pi in layouts:
                for c in counts:add(member,base,oi,pi,128,c,0,c if c<1<<31 else (c-(1<<32))%N)
    rng=random.Random(0x5172c90)
    for _ in range(1500):
        member=rng.randrange(2);base=rng.choice(bases);oi,pi=rng.choice(layouts);count=rng.getrandbits(32);target=count if count<1<<31 else (count-(1<<32))%N
        add(member,base,oi,pi,rng.randrange(256),count,rng.getrandbits(32),rng.choice([target,target,rng.getrandbits(64)]),rng.choice([128,128,22,20,72]),rng.randrange(256))
    for member in range(2):add(member,N-64,0,48,1,1,0,0)
    return sorted(cases)
def relation(row):
    member,base,obj,length,raw=row
    if base+length>N:return (0,0,0)
    memory={base+i:b for i,b in enumerate(raw[:length])}
    def unsigned(address,width):
        if any(address+i>=N or address+i not in memory for i in range(width)):raise KeyError
        return sum(memory[address+i]*256**i for i in range(width))
    try:
        if member==1:
            pointer=unsigned((obj+8)%N,8);count=unsigned((obj+16)%N,4)
            signed=count if count<1<<31 else count-(1<<32)
            if unsigned((pointer+16)%N,8)!=signed%N:return (1,1,signed%N)
        flag=unsigned((obj+21)%N,1);count=unsigned((obj+16)%N,4)
        if flag and 0<count<1<<31:return (1,flag,count)
        compared=unsigned((obj+4)%N,4)
        return (1,int((compared^(1<<31))<=(count^(1<<31))),count)
    except KeyError:return (0,0,0)
def fixtures():
    inputs=bytearray();expected=bytearray();counts={'cases':0,'refusals':0,'admitted_per_member':[0,0]}
    for row in corpus():
        output=relation(row);inputs.extend(struct.pack('<4Q',*row[:-1])+row[-1]);expected.extend(struct.pack('<3Q',*output));counts['cases']+=1;counts['refusals']+=output[0]==0
        if output[0]:counts['admitted_per_member'][row[0]]+=1
    return bytes(inputs),bytes(expected),{**counts,'inputs_sha256':sha(inputs),'expected_sha256':sha(expected),'oracle_sha256_at_freeze':sha(Path(__file__).read_bytes()),'static_sha256_at_freeze':sha((PACKET/'static.json').read_bytes()),'captured_code_executed':False}
if __name__=='__main__':
    require(not (ROOT/'src/node94-byte-dword-gate-pair').exists(),'freeze before Rust')
    inputs,expected,record=fixtures()
    for name,raw in [('inputs',inputs),('expected',expected)]:
        with (PACKET/(name+'.bin.gz')).open('xb') as f:f.write(gzip.compress(raw,compresslevel=1,mtime=0))
    record['source_directory_existed_at_freeze']=False
    with (PACKET/'frozen.json').open('x') as f:f.write(json.dumps(record,indent=2,sort_keys=True)+'\n')
    print(json.dumps(record,indent=2))
