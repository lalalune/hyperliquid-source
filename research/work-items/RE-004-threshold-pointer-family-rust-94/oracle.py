"""Abstract unsigned interval and flag-class relation, frozen before Rust."""
from pathlib import Path
import gzip,hashlib,json,random,struct
PACKET=Path(__file__).resolve().parent
ROOT=PACKET.parents[2]
def require(condition,message):
    if not condition:raise ValueError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def corpus():
    N=1<<64;edges=[0,1,34,35,36,62,63,64,194,195,196,N//2-1,N//2,N-1]
    biases=[0,1,N-1,N-0x599fbd0,N-0x576a6c0,N-0x576c3a0,N-0x576c300,0x123456789abcdef0]
    rows=set()
    for member in range(3):
        for first in range(256):
            for second in range(256):
                x=edges[(first+second)%len(edges)];bias=biases[(first^second)%len(biases)]
                rows.add((member,x,bias,N-1-first,first,second))
        for first,second in [(256,256),(0,256),(1,256),(128,256),(256,1),(1,1),(2,1),(255,1),(1,2),(1,255),(0,1)]:
            for x in edges:
                for bias in biases:rows.add((member,x,bias,0xfedcba9876543210,first,second))
        for bit in range(64):
            for x in [(1<<bit)-1,1<<bit, min(N-1,(1<<bit)+1)]:
                for first,second in [(0,256),(1,1),(2,1),(1,255)]:rows.add((member,x,biases[bit%8],1<<bit,first,second))
    rng=random.Random(0x54d7700)
    for _ in range(6000):rows.add((rng.randrange(3),rng.getrandbits(64),rng.getrandbits(64),rng.getrandbits(64),rng.randrange(257),rng.choice([1,0,2,255,256])))
    return sorted(rows)
def relation(row):
    member,index,bias,rdx,first,second=row;N=1<<64
    if member==0:return (1,(bias+0x576a6c0)%N if index in range(64) else 0,0)
    if first==256 or (first in range(1,256) and second==256):return (0,0,0)
    if first==0:return (1,0,rdx)
    threshold,base=[(35,0x576c3a0),(195,0x576c300)][member-1]
    rax=(bias+base)%N if second==1 and index in range(threshold+1) else 0
    return (1,rax,(bias+0x599fbd0)%N)
def fixtures():
    inputs=bytearray();expected=bytearray();counts={'cases':0,'refusals':0,'preserved_rdx':0,'selected_nonzero':0,'all_flag_pairs_per_member':65536}
    for row in corpus():
        out=relation(row);inputs.extend(struct.pack('<6Q',*row));expected.extend(struct.pack('<3Q',*out));counts['cases']+=1;counts['refusals']+=out[0]==0;counts['preserved_rdx']+=row[0]!=0 and row[4]==0;counts['selected_nonzero']+=out[1]!=0
    return bytes(inputs),bytes(expected),{**counts,'inputs_sha256':sha(inputs),'expected_sha256':sha(expected),'oracle_sha256_at_freeze':sha(Path(__file__).read_bytes()),'static_sha256_at_freeze':sha((PACKET/'static.json').read_bytes()),'captured_code_executed':False}
if __name__=='__main__':
    require(not (ROOT/'src/node94-threshold-pointer-family').exists(),'freeze before Rust')
    inputs,expected,record=fixtures()
    for name,raw in [('inputs',inputs),('expected',expected)]:
        with (PACKET/(name+'.bin.gz')).open('xb') as f:f.write(gzip.compress(raw,compresslevel=1,mtime=0))
    record['source_directory_existed_at_freeze']=False
    with (PACKET/'frozen.json').open('x') as f:f.write(json.dumps(record,indent=2,sort_keys=True)+'\n')
    print(json.dumps(record,indent=2))
