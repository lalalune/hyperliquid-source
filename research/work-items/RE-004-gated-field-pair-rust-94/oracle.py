"""Pre-Rust immutable byte-map equations for the complete same-flag copy pair."""
from pathlib import Path
import hashlib,gzip,json,random,struct
PACKET=Path(__file__).resolve().parent
ROOT=PACKET.parents[2]
N=1<<64
WIDTH=800
def require(ok,message):
    if not ok:raise ValueError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def corpus():
    cases=set()
    def add(member,base,objoff,poff,extoff,gate,length=WIDTH,salt=0,null=False,rax=0x0123456789abcdef,rdx=0xfedcba9876543210):
        image=bytearray((i*71+salt)%256 for i in range(WIDTH))
        if 0<=objoff+728<=WIDTH-8:image[objoff+728:objoff+736]=(0 if null else (base+poff)%N).to_bytes(8,'little')
        if 0<=objoff+184<WIDTH:image[objoff+184]=gate
        cases.add((member,base,(base+objoff)%N,(base+extoff)%N,rax,rdx,length,bytes(image)))
    bases=[0,1,0x1000,N-WIDTH]
    layouts=[(0,32,-16),(0,32,16),(0,32,80),(0,32,168),(0,32,680),(0,32,712),(-184,32,0),(-728,32,0),(8,33,17),(64,64,720),(0,696,712),(0,704,768)]
    for member in range(2):
        for gate in range(256):
            for base in [0,N-WIDTH]:
                add(member,base,0,32,16,gate,salt=gate)
                add(member,base,-184,32,0,gate,salt=gate)
        for base in bases:
            for oi,pi,ei in layouts:
                for gate in [0,1,2,128,255]:
                    add(member,base,oi,pi,ei,gate)
                    add(member,base,oi,pi,ei,gate,null=True)
        for length in [0,1,7,8,31,32,39,40,63,64,71,72,95,96,103,104,183,184,185,199,200,695,696,703,704,711,712,719,720,727,728,735,736,743,744,791,792,799,800]:
            for oi,pi,ei in layouts[:8]:
                for gate in [0,1]:add(member,0,oi,pi,ei,gate,length)
        for bit in range(64):
            for delta in [-1,0,1]:
                v=((1<<bit)+delta)%N;add(member,0,0,32,16,1,salt=bit,rax=v,rdx=v)
    rng=random.Random(0x53b1120)
    for _ in range(1200):
        member=rng.randrange(2);base=rng.choice(bases);oi,pi,ei=rng.choice(layouts)
        add(member,base,oi,pi,ei,rng.randrange(256),rng.choice([800,800,736,728,200]),rng.randrange(256),rng.randrange(5)==0,rng.getrandbits(64),rng.getrandbits(64))
    # Dense byte-shift aliases bind both loads before the first/only store.
    for member in range(2):
        for displacement in range(-17,18):
            add(member,0,0,32,32+displacement,1,salt=displacement)
            add(member,0,0,32,96+displacement,1,salt=displacement)
            add(member,0,0,32,696+displacement,1,salt=displacement)
    for member in range(2):
        for null in [False,True]:add(member,N-400,0,32,0,0,WIDTH,null=null)
    return sorted(cases)
def relation(row):
    member,base,obj,ext,rax,rdx,length,raw=row
    if length and base+length>N:return (0,0,0),raw
    memory={base+i:b for i,b in enumerate(raw[:length])}
    def read(address,size):
        keys=range(address,address+size)
        if any(k>=N or k not in memory for k in keys):raise KeyError
        return bytes(memory[k] for k in keys)
    def word(address):return int.from_bytes(read(address,8),'little')
    try:
        if member==0:
            pointer=word((obj+728)%N)
            if pointer==0:return (1,0,rdx),raw
            if read((obj+184)%N,1)==b'\0':return (1,pointer,rdx),raw
            first=read((pointer+32)%N,8);last=read((pointer+96)%N,8)
            writes=[((ext+16)%N,first),((ext+24)%N,last)]
            registers=(1,int.from_bytes(last,'little'),int.from_bytes(first,'little'))
        else:
            if read((obj+184)%N,1)==b'\0':return (1,rax,rdx),raw
            writes=[((obj+696)%N,read((ext+16)%N,8)+read((ext+24)%N,8))]
            registers=(1,rax,rdx)
        for address,value in writes:read(address,len(value))
        updated=dict(memory)
        for address,value in writes:updated.update({address+i:b for i,b in enumerate(value)})
        return registers,bytes(updated[base+i] for i in range(length))+raw[length:]
    except KeyError:return (0,0,0),raw
def fixtures():
    inputs=bytearray();expected=bytearray();counts={'cases':0,'refusals':0,'changed_images':0,'admitted_per_member':[0,0]}
    for row in corpus():
        registers,updated=relation(row);inputs.extend(struct.pack('<7Q',*row[:-1])+row[-1]);expected.extend(struct.pack('<3Q',*registers)+updated)
        counts['cases']+=1;counts['refusals']+=registers[0]==0;counts['changed_images']+=updated!=row[-1]
        if registers[0]:counts['admitted_per_member'][row[0]]+=1
    return bytes(inputs),bytes(expected),{**counts,'inputs_sha256':sha(inputs),'expected_sha256':sha(expected),'oracle_sha256_at_freeze':sha(Path(__file__).read_bytes()),'static_sha256_at_freeze':sha((PACKET/'static.json').read_bytes()),'captured_code_executed':False}
if __name__=='__main__':
    require(not (ROOT/'src/node94-gated-field-pair').exists(),'freeze before Rust')
    inputs,expected,record=fixtures()
    for name,raw in [('inputs',inputs),('expected',expected)]:
        with (PACKET/(name+'.bin.gz')).open('xb') as f:f.write(gzip.compress(raw,compresslevel=1,mtime=0))
    record['source_directory_existed_at_freeze']=False
    with (PACKET/'frozen.json').open('x') as f:f.write(json.dumps(record,indent=2,sort_keys=True)+'\n')
    print(json.dumps(record,indent=2))
