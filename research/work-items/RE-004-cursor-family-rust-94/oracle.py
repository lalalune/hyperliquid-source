"""Immutable memory equations for four complete cursor leaves; freeze before Rust."""
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
    cases=set();values=[0,1,7,8,9,39,40,41,N//2-1,N//2,N-9,N-8,N-7,N-1]
    bases=[0,1,0x1000,N//2,N-128]
    layouts=[(-32,64),(-16,64),(0,16),(0,24),(0,32),(0,40),(0,64),(0,112),(0,120),(8,8),(16,48),(64,96),(80,96),(96,0)]
    def add(member,base,objoff,boundoff,first,last,cursor,length=128,salt=0,rdx=0xfedcba9876543210):
        image=bytearray((i*71+salt)%256 for i in range(128));object=(base+objoff)%N;pointer=(base+boundoff)%N
        writes=[(boundoff,first),(boundoff+8,last),(objoff+16,pointer),(objoff+32,cursor)]
        for offset,value in writes:
            if 0<=offset<=120:image[offset:offset+8]=(value%N).to_bytes(8,'little')
        cases.add((member,base,object,rdx,length,bytes(image)))
    for member in range(4):
        for base in bases:
            for oi,bo in layouts:
                for i,first in enumerate(values):
                    last=values[(i*5+3)%len(values)]
                    for cursor in [first,last,values[(i+1)%len(values)],(base+64)%N]:add(member,base,oi,bo,first,last,cursor,salt=i)
        for length in [0,1,7,8,15,16,23,24,31,32,39,40,47,48,63,64,71,72,119,120,127,128]:
            for oi,bo in layouts:
                for cursor in [0,8,64,N-1]:add(member,0,oi,bo,8,64,cursor,length)
        for bit in range(64):
            for delta in [-1,0,1]:
                v=((1<<bit)+delta)%N;add(member,0,0,64,v,v,v,rdx=v);add(member,0,0,64,0,N-1,v,rdx=v)
    rng=random.Random(0x52c6ea0)
    for _ in range(1800):
        member=rng.randrange(4);base=rng.choice(bases);oi,bo=rng.choice(layouts);v=rng.getrandbits(64);last=rng.getrandbits(64);cursor=rng.choice([v,last,rng.getrandbits(64),(base+rng.randrange(121))%N]);add(member,base,oi,bo,v,last,cursor,rng.choice([128,128,127,64,40]),rng.randrange(256),rng.getrandbits(64))
    # Invalid image wrapping is a new API refusal even if a particular read fits.
    for member in range(4):add(member,N-64,0,16,0,1,0,128)
    return sorted(cases)
def relation(row):
    member,base,object,rdx,length,raw=row;memory={base+i:b for i,b in enumerate(raw[:length])};out=bytearray(raw)
    if length and base+length>N:return (0,0,0),raw
    def word(address):
        addresses=[address+i for i in range(8)]
        if any(a not in memory or a>=N for a in addresses):raise KeyError
        return sum(memory[a]*256**i for i,a in enumerate(addresses))
    try:
        if member==1:
            cursor=word((object+32)%N);result=word(cursor);return (1,result,rdx),raw
        pointer=word((object+16)%N)
        if member==0:return (1,(word((pointer+8)%N)-word(pointer)+40)%N,pointer),raw
        cursor=word((object+32)%N)
        if member==2:
            terminal=word((pointer+8)%N);result=(cursor+8)%N if cursor!=terminal else cursor;store=cursor!=terminal
        else:
            first=word(pointer);result=word((pointer+8)%N) if cursor==first else (cursor-8)%N;store=True
        if store:
            offset=(object+32)%N-base;require(0<=offset and offset+8<=length,'read-implies-destination')
            out[offset:offset+8]=result.to_bytes(8,'little')
        return (1,result,pointer),bytes(out)
    except KeyError:return (0,0,0),raw

def fixtures():
    inputs=bytearray();expected=bytearray();counts={'cases':0,'refusals':0,'changed_images':0,'preserved_rdx':0,'admitted_per_member':[0]*4}
    for row in corpus():
        member,base,obj,rdx,length,raw=row;registers,updated=relation(row);inputs.extend(struct.pack('<5Q',member,base,obj,rdx,length)+raw);expected.extend(struct.pack('<3Q',*registers)+updated);counts['cases']+=1;counts['refusals']+=registers[0]==0;counts['changed_images']+=updated!=raw;counts['preserved_rdx']+=member==1 and registers[0]==1
        if registers[0]:counts['admitted_per_member'][member]+=1
    return bytes(inputs),bytes(expected),{**counts,'inputs_sha256':sha(inputs),'expected_sha256':sha(expected),'oracle_sha256_at_freeze':sha(Path(__file__).read_bytes()),'static_sha256_at_freeze':sha((PACKET/'static.json').read_bytes()),'captured_code_executed':False}
if __name__=='__main__':
    require(not (ROOT/'src/node94-cursor-family').exists(),'freeze before Rust')
    inputs,expected,record=fixtures()
    for name,raw in [('inputs',inputs),('expected',expected)]:
        with (PACKET/(name+'.bin.gz')).open('xb') as f:f.write(gzip.compress(raw,compresslevel=1,mtime=0))
    record['source_directory_existed_at_freeze']=False
    with (PACKET/'frozen.json').open('x') as f:f.write(json.dumps(record,indent=2,sort_keys=True)+'\n')
    print(json.dumps(record,indent=2))
