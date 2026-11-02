"""Pre-Rust immutable numeric-memory relation for the self-guarded chain."""
from pathlib import Path
import gzip,hashlib,json,random,struct
PACKET=Path(__file__).resolve().parent
ROOT=PACKET.parents[2]
N=1<<64
WIDTH=128
def sha(b):return hashlib.sha256(b).hexdigest()
def require(ok,msg):
    if not ok:raise ValueError(msg)
def corpus():
    cases=set()
    def add(base,layout,guard,value,length=128,salt=0):
        oi,pi,qi,ri=layout;image=bytearray((i*61+salt)%256 for i in range(WIDTH))
        obj=(base+oi-8)%N;p=(base+pi)%N;q=(base+qi-16)%N;r=(base+ri-0xcb8)%N
        g={'self':p,'different':(p+1)%N,'high_only':p^(1<<32),'zero':0,'allones':N-1}.get(guard,guard)
        for offset,v in [(ri,value),(qi,r),(pi+8,q),(pi,g),(oi,p)]:
            if 0<=offset<=WIDTH-8:image[offset:offset+8]=(v%N).to_bytes(8,'little')
        cases.add((base,obj,length,bytes(image)))
    bases=[0,1,8,0x1000,N-128]
    layouts=[(0,16,64,96),(112,0,64,96),(104,16,0,96),(0,16,64,120),(0,120,64,96),(0,0,64,96),(16,16,64,96),(24,16,64,96),(0,16,16,96),(0,16,24,96),(0,16,64,64),(0,16,64,67),(0,17,65,97),(0,-8,64,96),(120,16,64,0)]
    values=[0,1,15,16,0xffffffff,1<<32,(1<<63)-1,1<<63,N-1,0xfedcba9876543210]
    for base in bases:
        for layout in layouts:
            for guard in ['self','different','high_only','zero','allones']:
                for i,v in enumerate(values):add(base,layout,guard,v,salt=i)
        for bit in range(64):
            for delta in [-1,0,1]:
                v=((1<<bit)+delta)%N
                add(base,(0,16,64,96),'different',v,salt=bit)
                add(base,(0,16,64,96),(base+16)^(1<<bit),v,salt=bit)
    for length in [0,1,7,8,15,16,23,24,31,32,63,64,71,72,95,96,103,104,119,120,127,128]:
        for layout in layouts:
            for guard in ['self','different','high_only']:add(0,layout,guard,0x8877665544332211,length)
    # Whole image overflows while every reached self/chain span fits below N.
    for guard in ['self','different']:add(N-64,(0,16,32,48),guard,0x89abcdef01234567,128)
    rng=random.Random(0x5172e50)
    for _ in range(1600):
        add(rng.choice(bases),rng.choice(layouts),rng.choice(['self','different','high_only',rng.getrandbits(64)]),rng.getrandbits(64),rng.choice([128,128,120,104,72,24]),rng.randrange(256))
    return sorted(cases)
def relation(row):
    base,obj,length,raw=row;memory={base+i:v for i,v in enumerate(raw[:length])};trace=[]
    if base+length>N:return (0,0,0),'image',trace
    def qword(address,label):
        trace.append((label,address))
        try:return sum(memory[address+i]*256**i for i in range(8))
        except KeyError:raise LookupError(label)
    try:
        pointer=qword((obj+8)%N,'entry')
        observed=qword(pointer,'self')
        if (observed-pointer)%N==0:return (1,N-1,N-1),'self',trace
        # Numeric function composition over immutable memory, not instruction steps.
        next_base=qword((pointer+8)%N,'next')
        field_base=qword((next_base+16)%N,'field-base')
        value=qword((field_base+0xcb8)%N,'value')
        return (1,value,value),'chain',trace
    except LookupError as error:return (0,0,0),'missing-'+str(error),trace

def fixtures():
    inputs=bytearray();expected=bytearray();counts={'cases':0,'outcomes':{},'self_with_absent_next_span':0,'zero_pointer_chain_cases':0,'high_only_guard_difference':0}
    for row in corpus():
        result,outcome,trace=relation(row);base,obj,length,raw=row
        inputs.extend(struct.pack('<3Q',base,obj,length)+raw);expected.extend(struct.pack('<3Q',*result));counts['cases']+=1;counts['outcomes'][outcome]=counts['outcomes'].get(outcome,0)+1
        if outcome=='self':
            p=trace[1][1];a=(p+8)%N;counts['self_with_absent_next_span']+=not(base<=a and a+8<=base+length)
        if outcome=='chain':
            p=trace[1][1];counts['zero_pointer_chain_cases']+=p==0
            offset=p-base;observed=int.from_bytes(raw[offset:offset+8],'little');counts['high_only_guard_difference']+=(observed-p)%N!=0 and observed%(1<<32)==p%(1<<32)
    return bytes(inputs),bytes(expected),{**counts,'input_record_bytes':152,'output_record_bytes':24,'inputs_sha256':sha(inputs),'expected_sha256':sha(expected),'oracle_sha256_at_freeze':sha(Path(__file__).read_bytes()),'static_sha256_at_freeze':sha((PACKET/'static.json').read_bytes()),'target_sha256':'3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f','captured_execution':False,'instruction_emulation':False}
if __name__=='__main__':
    require(not (ROOT/'src/node94-self-guarded-chain').exists(),'freeze before Rust')
    inputs,expected,record=fixtures();record['rust_source_existed_at_freeze']=False
    for name,raw in [('inputs',inputs),('expected',expected)]:
        with (PACKET/(name+'.bin.gz')).open('xb') as f:f.write(gzip.compress(raw,compresslevel=1,mtime=0))
    with (PACKET/'frozen.json').open('xb') as f:f.write((json.dumps(record,indent=2,sort_keys=True)+'\n').encode())
    print(json.dumps(record,indent=2))
