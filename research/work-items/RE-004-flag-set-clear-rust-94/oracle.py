"""Pre-Rust immutable-byte-map overlay oracle for the complete flag/clear leaf."""
import gzip,hashlib,json,random,struct
from pathlib import Path
PACKET=Path(__file__).resolve().parent
ROOT=PACKET.parents[2]
N=1<<64
SIZE=512
def require(ok,why):
    if not ok:raise ValueError(why)
def sha(b):return hashlib.sha256(b).hexdigest()
def resolve(row):
    base,obj,rdx,length,data=row
    if base+length>N:return None
    memory={base+i:b for i,b in enumerate(data[:length])}
    read=(obj+416)%N;flag=(obj+264)%N
    try:
        pointer=sum(memory[read+i]*256**i for i in range(8))
        if any(flag+i not in memory for i in range(4))or(pointer!=0 and pointer not in memory):return None
        patch={flag:1,flag+1:0,flag+2:0,flag+3:0}
        if pointer:patch[pointer]=0
        return bytes(patch.get(base+i,data[i])for i in range(SIZE)),pointer,(read,flag)
    except KeyError:return None

def corpus():
    rng=random.Random(0x53cf560);rows=[]
    def add(base,clear,length=SIZE,seed=1,object_offset=300,rdx=0xfedcba9876543210,pointer=None):
        data=bytearray(((i*29)^(i>>1)^seed)&255 for i in range(SIZE));obj=(base+object_offset-416)%N
        value=(base+clear)%N if pointer is None else pointer%N
        if 0<=object_offset<=SIZE-8:data[object_offset:object_offset+8]=value.to_bytes(8,'little')
        rows.append((base,obj,rdx%N,length,bytes(data)))
    for base in (0,0x123456780000,N-SIZE):
        for clear in range(SIZE):
            for seed in (1,171):add(base,clear,seed=seed,rdx=(base+clear)^0xfedcba9876543210)
        for length in (0,1,3,4,7,8,147,148,149,150,151,152,299,300,301,307,308,309,511,512):
            for clear in (0,1,147,148,149,150,151,152,299,300,307,308,511,512):add(base,clear,length=length)
            add(base,0,length=length,pointer=0)
        for value in (0,1,(1<<64)-1,1<<63,base-1,base+SIZE,base+SIZE-1):add(base,0,pointer=value)
        for object_offset in (152,153,300,504,505,511,512):
            for clear in (0,1,148,300,504,511):add(base,clear,object_offset=object_offset)
        for i in range(64):add(base,300+i%8,rdx=1<<i)
    # The numeric object may be zero; only its reached fields matter.
    for clear in (0,148,149,150,151,300,307,511):add(116,clear)
    for clear in (0,148,300,399):add(N-400,clear)
    for i in range(800):
        base=rng.choice([0,0x100000000,N-SIZE,N-400]);clear=rng.randrange(0,SIZE+8);length=rng.choice([SIZE,SIZE,400,308,152,0]);add(base,clear,length,seed=rng.randrange(256),rdx=rng.getrandbits(64),object_offset=rng.choice([152,300,301,504]))
    return rows

def fixtures():
    inputs=bytearray();expected=bytearray();stats={'cases':0,'admitted':0,'refusals':0,'null_pointer':0,'clear_aliases_pointer':0,'clear_aliases_flag':0,'zero_object':0,'wrapped_object_fields':0}
    for row in corpus():
        base,obj,rdx,length,data=row;inputs.extend(struct.pack('<4Q',base,obj,rdx,length)+data);stats['cases']+=1;r=resolve(row)
        if r is None:expected.extend(bytes(24)+data);stats['refusals']+=1
        else:
            updated,pointer,(read,flag)=r;expected.extend(struct.pack('<3Q',1,pointer,rdx)+updated);stats['admitted']+=1;stats['null_pointer']+=pointer==0;stats['clear_aliases_pointer']+=pointer!=0 and read<=pointer<read+8;stats['clear_aliases_flag']+=pointer!=0 and flag<=pointer<flag+4;stats['zero_object']+=obj==0;stats['wrapped_object_fields']+=obj+416>=N
    return bytes(inputs),bytes(expected),{**stats,'inputs_sha256':sha(inputs),'expected_sha256':sha(expected),'captured_code_executed':False}
if __name__=='__main__':
    require(not(ROOT/'src/node94-flag-set-clear').exists(),'Rust source predates freeze')
    inp,out,record=fixtures();record.update({'oracle_sha256_at_freeze':sha(Path(__file__).read_bytes()),'static_sha256_at_freeze':sha((PACKET/'static.json').read_bytes()),'source_directory_existed_at_freeze':False})
    for name,raw in [('inputs',inp),('expected',out)]:
        with(PACKET/(name+'.bin.gz')).open('xb')as f:f.write(gzip.compress(raw,compresslevel=1,mtime=0))
    with(PACKET/'frozen.json').open('x')as f:json.dump(record,f,indent=2,sort_keys=True);f.write('\n')
    print(json.dumps(record,sort_keys=True))
