"""Pre-Rust immutable-image equations, using centered residues and exact floor."""
from pathlib import Path
import gzip,hashlib,json,random,struct
PACKET=Path(__file__).resolve().parent
ROOT=PACKET.parents[2]
N=1<<64
WIDTH=128
def sha(raw):return hashlib.sha256(raw).hexdigest()
def require(ok,message):
    if not ok:raise ValueError(message)
def corpus():
    cases=set()
    def add(member,base,layout,a,b,dest,length=128,incoming=0xfedcba9876543210,salt=0):
        oi,pi,qi=layout;image=bytearray((i*73+salt)%256 for i in range(WIDTH))
        def put(at,value,width):
            if 0<=at<=WIDTH-width:image[at:at+width]=(value%(1<<(8*width))).to_bytes(width,'little')
        if member==0:
            obj=(base+oi-0x788)%N;p=(base+pi-0x30)%N;q=(base+qi-0xb18)%N
            put(qi,b,8);put(qi+8,a,8);put(pi,q,8);put(oi,p,8)
        else:
            obj=(base+oi-0x788)%N;incoming=(base+qi-0x1438)%N;put(qi,a,4)
        cases.add((member,base,obj,incoming,(base+dest)%N,length,bytes(image)))
    values=[0,1,7,8,15,16,17,31,32,33,(1<<31)-1,1<<31,(1<<32)-1,1<<32,(1<<63)-17,(1<<63)-1,1<<63,(1<<63)+1,N-33,N-17,N-16,N-15,N-1]
    bases=[0,0x1000,1<<63,N-128]
    layouts=[(0,16,64),(16,0,64),(0,8,16),(0,16,24),(0,0,64),(0,16,0),(0,16,8),(32,24,32),(40,48,56),(88,96,104),(120,104,0)]
    for base in bases:
        for layout in layouts:
            for i,a in enumerate(values):
                for b in [values[(i*7+3)%len(values)],0,N-1]:
                    for dest in [0,7,16,layout[2],layout[2]+5,layout[2]+8,112,120]:add(0,base,layout,a,b,dest,salt=i)
        for dest in range(121):
            for a,b in [(0,1),(1,0),(N-1,0),(1<<63,0),(0,1<<63)]:add(0,base,(0,16,64),a,b,dest)
        for bit in range(64):
            for delta in [-1,0,1]:
                for residue in range(16):add(0,base,(0,16,64),(1<<bit)+delta+residue,1,residue*7,salt=bit)
    # Signed input grid and every byte-offset destination around each source.
    signed=[0,1,127,128,255,256,(1<<31)-1,1<<31,(1<<31)+1,(1<<32)-1]
    for base in bases:
        for pos in [0,1,7,8,16,64,120,124]:
            for dest in [0,1,7,8,16,63,64,65,120]:
                for a in signed:add(1,base,(0,0,pos),a,0,dest)
        for bit in range(32):
            for delta in [-1,0,1]:
                for dest in range(56,73):add(1,base,(0,0,64),(1<<bit)+delta,0,dest,salt=bit)
    # Exactly fitting/missing reads and stores; otherwise ignored fields absent.
    for member in range(2):
        for length in [0,1,3,4,7,8,15,16,19,20,23,24,63,64,67,68,71,72,75,76,79,80,119,120,123,124,127,128]:
            for layout in [(0,16,64),(120,16,0),(0,16,124)]:
                for dest in [0,1,64,120,121,128,-8]:add(member,0,layout,N-1,1,dest,length)
        add(member,N-64,(0,16,64),N-1,1,0,128)
    rng=random.Random(0x514ab20)
    for _ in range(1800):
        member=rng.randrange(2);base=rng.choice(bases);layout=rng.choice(layouts);a=rng.getrandbits(64);b=rng.getrandbits(64)
        add(member,base,layout,a,b,rng.randrange(129),rng.choice([128,128,80,64,32]),rng.getrandbits(64),rng.randrange(256))
    return sorted(cases)
def relation(row):
    member,base,obj,incoming,dest,length,raw=row;memory={base+i:v for i,v in enumerate(raw[:length])}
    if base+length>N:return (0,0,0),raw
    def read(address,width):
        values=[memory[address+i] for i in range(width)]
        return sum(v*256**i for i,v in enumerate(values))
    try:
        if member==0:
            p=read((obj+0x788)%N,8);q=read((p+0x30)%N,8)
            a=read((q+0xb20)%N,8);b=read((q+0xb18)%N,8)
            # Center the mathematical residue, then floor divide (not SAR).
            value=(((a-b+N//2)%N-N//2)//16)%N;rdx=q
        else:
            address=(incoming+0x1438)%N
            low=read(address,3);top=read(address+3,1)
            # Signed most-significant byte, independently of a whole-i32 cast.
            value=(low+((top+128)%256-128)*256**3)%N;rdx=incoming
        require(dest+8<=N,'output cannot cross numeric endpoint')
        for i in range(8):memory[dest+i]  # Require full destination before overlay.
        updated=bytes((value//256**(base+i-dest))%256 if dest<=base+i<dest+8 else v for i,v in enumerate(raw))
        return (1,1,rdx),updated
    except (KeyError,ValueError):return (0,0,0),raw

def fixtures():
    inputs=bytearray();expected=bytearray();counts={'cases':0,'admitted_per_member':[0,0],'refusals':0,'changed_images':0}
    for row in corpus():
        registers,updated=relation(row);inputs.extend(struct.pack('<6Q',*row[:-1])+row[-1]);expected.extend(struct.pack('<3Q',*registers)+updated)
        counts['cases']+=1;counts['refusals']+=registers[0]==0;counts['changed_images']+=updated!=row[-1]
        if registers[0]:counts['admitted_per_member'][row[0]]+=1
    return bytes(inputs),bytes(expected),{**counts,'input_record_bytes':176,'output_record_bytes':152,'inputs_sha256':sha(inputs),'expected_sha256':sha(expected),'oracle_sha256_at_freeze':sha(Path(__file__).read_bytes()),'static_sha256_at_freeze':sha((PACKET/'static.json').read_bytes()),'target_sha256':'3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f','captured_execution':False,'instruction_emulation':False}
if __name__=='__main__':
    require(not (ROOT/'src/node94-field-walk-pair').exists(),'freeze before Rust')
    inputs,expected,record=fixtures();record['rust_source_existed_at_freeze']=False
    for name,raw in [('inputs',inputs),('expected',expected)]:
        with (PACKET/(name+'.bin.gz')).open('xb') as f:f.write(gzip.compress(raw,compresslevel=1,mtime=0))
    with (PACKET/'frozen.json').open('xb') as f:f.write((json.dumps(record,indent=2,sort_keys=True)+'\n').encode())
    print(json.dumps(record,indent=2))
