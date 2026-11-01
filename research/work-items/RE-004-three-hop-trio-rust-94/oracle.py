"""Pre-Rust immutable-address composition and output-overlay oracle."""
import gzip,hashlib,json,random,struct
from pathlib import Path
PACKET=Path(__file__).resolve().parent
ROOT=PACKET.parents[2]
N=1<<64
MASK=N-1
SIZE=1280
FIELDS=(0xcd0,0xa70,0xa78)
def require(ok,why):
    if not ok:raise ValueError(why)
def sha(b):return hashlib.sha256(b).hexdigest()
def resolve(row):
    member,base,obj,dest,rdx,length,data=row
    if base+length>N:return None
    memory={base+i:b for i,b in enumerate(data[:length])};addresses=[]
    def word(address):
        address%=N;addresses.append(address)
        return sum(memory[address+i]*256**i for i in range(8))
    try:
        value=word(word(word(obj+0x788)+0x8e8)+FIELDS[member])
        if any(dest+i not in memory for i in range(8)):return None
        overlay={dest+i:(value>>(8*i))&255 for i in range(8)}
        result=bytes(overlay.get(base+i,data[i])for i in range(SIZE))
        return result,addresses,value
    except KeyError:return None

def corpus():
    rows=[];rng=random.Random(0x514acc0)
    def add(member,base,layout,dest,length=SIZE,value=0x81234567fedcba98,rdx=0xfedcba9876543210,seed=0,override=()):
        first,middle,last=layout;field=FIELDS[member]
        data=bytearray(((i*29+seed*53)^(i>>2))&255 for i in range(SIZE))
        obj=(base+first-0x788)%N;p=(base+middle-0x8e8)%N;q=(base+last-field)%N
        for offset,val in [(first,p),(middle,q),(last,value),*override]:
            if 0<=offset and offset+8<=SIZE:data[offset:offset+8]=(val%N).to_bytes(8,'little')
        rows.append((member,base,obj,(base+dest)%N,rdx%N,length,bytes(data)))
    values=[0,1,MASK,1<<63,0xffffffff,0x100000000]+[1<<i for i in range(64)]
    for member in range(3):
        for base in [0,0x123456780000,N-SIZE]:
            for dest in [*range(0,193),248,512,1016,1272]:
                for val in [0,0x81234567fedcba98]:add(member,base,(16,64,128),dest,value=val,seed=dest)
            for i,value in enumerate(values):add(member,base,(7,47,111),160,value=value,rdx=MASK^value,seed=i)
            for length in [0,1,7,8,15,16,23,24,63,64,71,72,127,128,135,136,159,160,167,168,1279,1280]:
                for layout,dest in [((16,64,128),160),((0,32,64),0),((1272,64,128),8),((16,1272,128),8),((16,64,1272),8)]:add(member,base,layout,dest,length=length)
            # Real exact input-role aliases with compatible pointer values.
            for dest in [0,16,24,32,40,64,128,512,1016,1272]:
                first=16;last=first+FIELDS[member]-0x8e8
                add(member,base,(first,first,last),dest,seed=1)
                last=32;add(member,base,(16,last,last),dest,value=(base+last-FIELDS[member])%N,seed=2)
                first=64;middle=128;add(member,base,(first,middle,first),dest,value=(base+middle-0x8e8)%N,seed=3)
            # Partial read-role overlaps are interpreted from the final bytes,
            # never from a requested layout value overwritten during construction.
            for delta in range(-7,8):
                for layout in [(32,32+delta,128),(32,64,64+delta),(32,64,32+delta)]:
                    add(member,base,layout,48,seed=delta+7)
        # Zero numeric bases are ordinary field roots, not implicit null guards.
        add(member,0x800,(16,0xe8,400),16)
        add(member,0x800,(16,64,FIELDS[member]-0x800),64)
        add(member,0x778,(16,64,128),128)
        add(member,N-1100,(16,64,128),160,length=SIZE)
        for i in range(600):
            base=rng.choice([0,0x100000000,N-SIZE,N-1100]);layout=tuple(rng.randrange(0,SIZE-7)for _ in range(3));dest=rng.randrange(0,SIZE+8);length=rng.choice([SIZE,SIZE,1024,256,128,0]);add(member,base,layout,dest,length=length,value=rng.getrandbits(64),rdx=rng.getrandbits(64),seed=i)
    return rows

def fixtures():
    inputs=bytearray();expected=bytearray();admitted=[0]*3;refusals=0;output_aliases=0;source_aliases=0;wrapped_objects=0
    for row in corpus():
        member,base,obj,dest,rdx,length,data=row;inputs.extend(struct.pack('<6Q',member,base,obj,dest,rdx,length)+data);result=resolve(row)
        if result is None:expected.extend(bytes(24)+data);refusals+=1
        else:
            updated,addresses,value=result;expected.extend(struct.pack('<3Q',1,1,rdx)+updated);admitted[member]+=1
            output_aliases+=any(dest<a+8 and a<dest+8 for a in addresses)
            source_aliases+=any(a<b+8 and b<a+8 for i,a in enumerate(addresses)for b in addresses[i+1:])
            wrapped_objects+=obj+0x788>=N
    return bytes(inputs),bytes(expected),{'cases':len(inputs)//1328,'admitted_per_member':admitted,'refusals':refusals,'admitted_output_aliases':output_aliases,'admitted_read_role_aliases':source_aliases,'admitted_wrapped_object_fields':wrapped_objects,'inputs_sha256':sha(inputs),'expected_sha256':sha(expected),'captured_code_executed':False}
if __name__=='__main__':
    require(not(ROOT/'src/node94-three-hop-trio').exists(),'Rust source predates freeze')
    inp,out,record=fixtures();record.update({'oracle_sha256_at_freeze':sha(Path(__file__).read_bytes()),'static_sha256_at_freeze':sha((PACKET/'static.json').read_bytes()),'source_directory_existed_at_freeze':False})
    for name,raw in [('inputs',inp),('expected',out)]:
        with (PACKET/(name+'.bin.gz')).open('xb')as f:f.write(gzip.compress(raw,compresslevel=1,mtime=0))
    with (PACKET/'frozen.json').open('x')as f:json.dump(record,f,indent=2,sort_keys=True);f.write('\n')
    print(json.dumps(record,sort_keys=True))
