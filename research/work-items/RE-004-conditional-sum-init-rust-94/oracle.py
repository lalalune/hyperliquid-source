"""Pre-Rust signed-low32 arithmetic and immutable four-field overlay oracle."""
import gzip,hashlib,json,random,struct
from pathlib import Path
PACKET=Path(__file__).resolve().parent
ROOT=PACKET.parents[2]
N=1<<64
SIZE=128
def require(ok,why):
    if not ok:raise ValueError(why)
def sha(b):return hashlib.sha256(b).hexdigest()
def resolve(row):
    base,dest,rsi,rdx,length,data=row
    if base+length>N:return None
    memory={base+i:x for i,x in enumerate(data[:length])}
    if any(dest+i not in memory for i in range(32)):return None
    low=rdx%(1<<32);signed=low if low<(1<<31)else low-(1<<32)
    total=(rsi+signed)%N;words=[0,total,0,signed%N]
    patch={dest+8*j+i:(v//256**i)%256 for j,v in enumerate(words)for i in range(8)}
    return bytes(patch.get(base+i,data[i])for i in range(SIZE)),total,signed
def corpus():
    rows=[];rng=random.Random(0x5475e80)
    def add(base,dest,rsi,rdx,length=SIZE,seed=0):
        data=bytes(((i*37)^(i>>2)^seed)&255 for i in range(SIZE));rows.append((base,(base+dest)%N,rsi%N,rdx%N,length,data))
    rsis=[0,1,(1<<31)-1,1<<32,1<<63,N-1]
    rdxs=[0,1,(1<<31)-1,1<<31,(1<<32)-1,1<<32,1<<63,N-1]+[1<<i for i in range(64)]+[N-1-(1<<i)for i in range(64)]
    for base in (0,0x123456780000,N-SIZE):
        for rdx in rdxs:
            for rsi in rsis:
                for dest in (0,1,96):add(base,dest,rsi,rdx,seed=(rdx+rsi)%256)
        for dest in range(-1,130):
            for rdx in (0,1,0x80000000,0xffffffff):add(base,dest,0x8123456789abcdef,rdx,seed=dest)
        for length in (0,1,7,8,15,16,23,24,31,32,33,63,64,127,128):
            for dest in (0,1,16,32,95,96):add(base,dest,N-1,0xffffffff,length)
    for offset in (0,1,16,32):add(N-64,offset,7,0x80000000)
    for i in range(500):add(rng.choice([0,0x100000000,N-SIZE,N-64]),rng.randrange(-8,136),rng.getrandbits(64),rng.getrandbits(64),rng.choice([SIZE,SIZE,96,64,32,0]),i)
    return rows
def fixtures():
    inputs=bytearray();expected=bytearray();stats={'cases':0,'admitted':0,'refusals':0,'negative_low32':0,'zero_low32_with_high_bits':0,'sum_wraps':0,'unaligned_destinations':0,'exact_end_spans':0}
    for row in corpus():
        base,dest,rsi,rdx,length,data=row;inputs.extend(struct.pack('<5Q',base,dest,rsi,rdx,length)+data);stats['cases']+=1;r=resolve(row)
        if r is None:expected.extend(bytes(32)+data);stats['refusals']+=1
        else:
            updated,total,signed=r;expected.extend(struct.pack('<4Q',1,1,total,rdx)+updated);stats['admitted']+=1;stats['negative_low32']+=signed<0;stats['zero_low32_with_high_bits']+=rdx!=0 and rdx%(1<<32)==0;stats['sum_wraps']+=not(0<=rsi+signed<N);stats['unaligned_destinations']+=dest%8!=0;stats['exact_end_spans']+=dest+32==base+length
    return bytes(inputs),bytes(expected),{**stats,'inputs_sha256':sha(inputs),'expected_sha256':sha(expected),'captured_code_executed':False}
if __name__=='__main__':
    require(not(ROOT/'src/node94-conditional-sum-init').exists(),'Rust source predates freeze')
    inp,out,record=fixtures();record.update({'oracle_sha256_at_freeze':sha(Path(__file__).read_bytes()),'static_sha256_at_freeze':sha((PACKET/'static.json').read_bytes()),'source_directory_existed_at_freeze':False})
    for name,raw in [('inputs',inp),('expected',out)]:
        with(PACKET/(name+'.bin.gz')).open('xb')as f:f.write(gzip.compress(raw,compresslevel=1,mtime=0))
    with(PACKET/'frozen.json').open('x')as f:json.dump(record,f,indent=2,sort_keys=True);f.write('\n')
    print(json.dumps(record,sort_keys=True))
