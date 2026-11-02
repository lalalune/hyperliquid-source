"""Independent ordered decision relations over an immutable byte-address map."""
import gzip,hashlib,json,random,struct
from pathlib import Path
PACKET=Path(__file__).resolve().parent
ROOT=PACKET.parents[2]
N=1<<64
MASK=N-1
SIZE=768
def require(ok,why):
    if not ok:raise ValueError(why)
def sha(b):return hashlib.sha256(b).hexdigest()
def observation(row):
    member,base,obj,rdx,length,data=row
    if base+length>N:return None
    memory={base+i:b for i,b in enumerate(data[:length])}
    def read(address,width):
        address%=N
        if any(address+i not in memory for i in range(width)):raise KeyError(address)
        return bytes(memory[address+i] for i in range(width))
    try:
        if member==0:
            flag=read(obj+0x28a,1)
            alternatives=[(flag!=b'\0',lambda:1),(True,lambda:2*int(read(obj+0x28c,4)==b'\1\0\0\0'))]
            rax=next(value()for yes,value in alternatives if yes)
        elif member==1:
            rdx=int.from_bytes(read(obj+0x50,8),'little')
            alternatives=[(rdx==0,lambda:0),(True,lambda:0 if read(rdx+0x20,1)==b'\0' else read(obj+0x289,1)[0])]
            rax=next(value()for yes,value in alternatives if yes)
        else:
            if read(obj+0x28a,1)!=b'\0':rax=0
            else:
                mode=read(obj+0x290,1)[0]
                if mode:rax=mode
                elif read(obj+0x289,1)==b'\0':rax=0
                else:
                    left=read(obj+0x98,4);right=read(obj+0x9c,4)
                    # Big-endian lexicographic order, retaining entry bytes1..3.
                    result=bytes([int(right[::-1]<left[::-1])])+left[1:]
                    rax=int.from_bytes(result,'little')
        return rax,rdx
    except KeyError:return None

def corpus():
    rows=[];rng=random.Random(0x5382d50)
    def add(member,base,obj,length,edits=(),rdx=0xfedcba9876543210,seed=0):
        data=bytearray(((i*73+seed*19)^(i>>2))&255 for i in range(SIZE))
        for address,raw in edits:
            off=(address%N)-base
            if 0<=off and off+len(raw)<=SIZE:data[off:off+len(raw)]=raw
        rows.append((member,base,obj%N,rdx%N,length,bytes(data)))
    def le(x,n):return (x% (1<<(8*n))).to_bytes(n,'little')
    words=[0,1,2,255,256,257,0x7fffffff,0x80000000,0xffffffff,0xffffff00,0x12345678]+[1<<i for i in range(32)]
    for base in [0,0x123456780000,N-SIZE]:
        obj=base
        for flag in range(256):
            for dword in [0,1,2,0x1000001,0xffffffff]:add(0,base,obj,SIZE,[(obj+0x28a,le(flag,1)),(obj+0x28c,le(dword,4))],seed=flag)
            for pointee_flag in [0,1,2,127,255]:
                ptr=base+192
                add(1,base,obj,SIZE,[(obj+0x50,le(ptr,8)),(ptr+0x20,le(pointee_flag,1)),(obj+0x289,le(flag,1))],seed=flag)
            add(2,base,obj,SIZE,[(obj+0x28a,b'\0'),(obj+0x290,le(flag,1)),(obj+0x289,b'\1'),(obj+0x98,le(0x1234abcd,4)),(obj+0x9c,le(0x1234abcc,4))],seed=flag)
        for a in words:
            for b in words:
                add(2,base,obj,SIZE,[(obj+0x28a,b'\0'),(obj+0x290,b'\0'),(obj+0x289,b'\xff'),(obj+0x98,le(a,4)),(obj+0x9c,le(b,4))],seed=(a^b)&255)
        for member in range(3):
            for length in [0,1,0x50,0x57,0x58,0x98,0x9b,0x9c,0x9f,0xa0,0x289,0x28a,0x28b,0x28c,0x28f,0x290,0x291,SIZE]:
                for flag,mode,enabled,ptr in [(0,0,1,base+192),(1,255,255,base+192),(0,255,1,base+192),(0,0,0,base+192),(0,0,1,0),(0,0,1,base+SIZE)]:
                    add(member,base,obj,length,[(obj+0x28a,le(flag,1)),(obj+0x290,le(mode,1)),(obj+0x289,le(enabled,1)),(obj+0x50,le(ptr,8)),(base+224,b'\1')])
        for offset in range(0,681):
            for pointee_flag in [0,255]:
                ptr=base+offset-32
                add(1,base,obj,SIZE,[(obj+0x50,le(ptr,8)),(obj+0x289,b'\x9d'),(ptr+32,le(pointee_flag,1))],seed=offset)
    # High numeric objects make separate field expressions wrap into the image;
    # packed intervals need not contain the object address itself.
    for member in range(3):
        for delta in [0x50,0x98,0x9c,0x289,0x28a,0x28c,0x290]:
            obj=N-delta
            for length in [1,4,8,32,128,SIZE]:
                add(member,0,obj,length,[(obj+0x50,le(32,8)),(64,b'\0'),(obj+0x28a,b'\1'),(obj+0x290,b'\xff')])
    # Explicit suppressed-field paths and global-overflow-only refusals.
    for flag in range(256):
        add(0,0,0,0x28b,[(0x28a,le(flag,1))])
        add(1,0,0,88,[(80,bytes(8))])
        add(2,0,N-0x28a,1,[(0,le(flag,1))])
    for member in range(3):
        base=N-700
        add(member,base,base,SIZE,[(base+0x50,bytes(8)),(base+0x28a,b'\1')])
    for i in range(1600):
        base=rng.choice([0,0x100000000,N-SIZE,N-500]);obj=(base+rng.choice([0,1,7,31,127,300,N-0x290]))%N
        member=rng.randrange(3);ptr=(base+rng.randrange(SIZE))%N
        add(member,base,obj,rng.choice([0,128,680,681,700,SIZE]),[(obj+0x50,le(ptr,8)),(obj+0x28a,le(rng.choice([0,0,1,255]),1)),(obj+0x289,le(rng.randrange(256),1)),(obj+0x290,le(rng.choice([0,0,1,255]),1)),(ptr+32,le(rng.choice([0,255]),1))],rdx=rng.getrandbits(64),seed=i)
    return rows

def fixtures():
    rows=corpus();inputs=bytearray();expected=bytearray();admitted=[0]*3;refusals=0;partial_upper=0;raw_flags=0
    for row in rows:
        member,base,obj,rdx,length,data=row;inputs.extend(struct.pack('<5Q',member,base,obj,rdx,length)+data);result=observation(row)
        if result is None:expected.extend(bytes(24));refusals+=1
        else:
            expected.extend(struct.pack('<3Q',1,*result));admitted[member]+=1
            partial_upper+=member==2 and result[0]>255
            raw_flags+=member in [1,2]and 1<result[0]<256
    return bytes(inputs),bytes(expected),{'cases':len(rows),'admitted_per_member':admitted,'refusals':refusals,'partial_upper_dword_cases':partial_upper,'raw_nonboolean_flag_cases':raw_flags,'inputs_sha256':sha(inputs),'expected_sha256':sha(expected),'captured_code_executed':False}
if __name__=='__main__':
    require(not (ROOT/'src/node94-object-status-gates').exists(),'Rust source predates freeze')
    inputs,expected,record=fixtures();record.update({'oracle_sha256_at_freeze':sha(Path(__file__).read_bytes()),'static_sha256_at_freeze':sha((PACKET/'static.json').read_bytes()),'source_directory_existed_at_freeze':False})
    for name,raw in [('inputs',inputs),('expected',expected)]:
        with (PACKET/(name+'.bin.gz')).open('xb')as f:f.write(gzip.compress(raw,compresslevel=1,mtime=0))
    with (PACKET/'frozen.json').open('x')as f:json.dump(record,f,indent=2,sort_keys=True);f.write('\n')
    print(json.dumps(record,sort_keys=True))
