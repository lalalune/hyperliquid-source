"""Pre-Rust immutable-memory, finite-address-set and whole-sum oracle."""
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
def resolve(row):
    member,base,obj,dest,rdx,length,data=row
    if base+length>N:return None
    memory={base+i:x for i,x in enumerate(data[:length])};reads=[]
    def word(address):
        address%=N;reads.append(address)
        return sum(memory[address+i]*256**i for i in range(8))
    try:
        p=word(obj+0x788);q=word(p+0x30);begin=word(q+0xb18);end=word(q+0xb20)
        distance=(end-begin)%N
        if distance%16:return None
        count=distance//16
        # Distinct entry qwords require at least eight distinct mapped bytes each.
        if count>len(memory)//8:return None
        pointers=[word((begin+16*i)%N)for i in range(count)]
        args=[word(pointer)for pointer in pointers]
        helper_values=[word(arg+16)+62 for arg in args]
        contributions=helper_values if member==0 else [word(pointer+80)for pointer in pointers]
        total=sum(contributions)%N
        if any(dest+i not in memory for i in range(8)):return None
        patch={dest+i:(total>>(8*i))&255 for i in range(8)}
        return bytes(patch.get(base+i,data[i])for i in range(SIZE)),(1,rdx,args[-1]if args else obj,dest),reads,count,total
    except KeyError:return None

def corpus():
    rows=[];rng=random.Random(0x514bc60)
    def add(member,base=0,output=0,count=3,entry=128,length=SIZE,seed=0,values=None,overrides=(),begin_end=None,entry_rdx=0xfedcba9876543210):
        data=bytearray(((i*13)^(i>>3)^(seed%256))&255 for i in range(SIZE))
        obj=(base+16-0x788)%N;p=(base+48-0x30)%N;q=(base+80-0xb18)%N
        begin,end=((base+entry)%N,(base+entry+16*count)%N)if begin_end is None else begin_end
        writes=[(16,p),(48,q),(80,begin),(88,end)]
        values=values or [0,1,MASK,0x8123456789abcdef]
        for i in range(4):writes.extend([(320+16*i,(base+576+16*i-16)%N),(400+16*i,values[(i+1)%len(values)]),(576+16*i,values[i%len(values)])])
        for i in range(min(count,16)):writes.append((entry+16*i,(base+320+16*(i%4))%N))
        for off,val in [*writes,*overrides]:
            if 0<=off and off+8<=SIZE:data[off:off+8]=(val%N).to_bytes(8,'little')
        rows.append((member,base,obj,(base+output)%N,entry_rdx%N,length,bytes(data)))
    for member in (0,1):
        for base in (0,0x123456780000,N-SIZE):
            for count in (0,1,2,4,8):
                for output in list(range(0,105))+list(range(312,385))+[128,135,144,159,248,255,400,407,416,448,575,576,583,608,624,760]:
                    add(member,base,output,count,seed=count)
            for i in range(64):
                add(member,base,values=[1<<i,MASK^(1<<i),MASK,0],seed=i,entry_rdx=MASK^(1<<i))
            for length in (0,7,8,15,16,23,24,47,48,55,56,79,80,87,88,95,96,127,128,135,136,143,144,151,152,319,320,327,328,399,400,407,408,575,576,583,584,767,768):
                add(member,base,count=1,length=length,output=0)
                add(member,base,count=0,length=length,output=0)
            for end_delta in (1,7,8,15,17,31,32,47,48,49,MASK,MASK-15):
                add(member,base,count=0,begin_end=((base+128)%N,(base+128+end_delta)%N))
            for address in (0,1,MASK,N-16,base,base+SIZE+512):add(member,base,count=0,begin_end=(address%N,address%N))
            # Missing helper input must still refuse the field variant.
            for off in (16,48,80,88,128,320):add(member,base,count=1,overrides=[(off,MASK-3)])
            for off in (128,320,400,576):
                for value in (0,MASK,1<<63):add(member,base,count=1,overrides=[(off,value)])
        # A wrapped terminal cursor is allowed: only its last qword is read.
        for entry in (752,760):
            for output in (0,128,320,400,576,760):add(member,N-SIZE,output,1,entry=entry)
        add(member,0x778,count=1)  # zero object, with an accessible +0x788 field
        add(member,N-700,count=1) # overflowing image; every reached field itself fits
        for i in range(700):
            count=rng.randrange(9);base=rng.choice([0,0x100000000,N-SIZE,N-700]);values=[rng.getrandbits(64)for _ in range(4)]
            add(member,base,rng.randrange(0,SIZE+8),count,entry=rng.choice([128,129,240,752]),length=rng.choice([SIZE,SIZE,640,600,408,136,96,0]),seed=i,values=values,entry_rdx=rng.getrandbits(64))
    return rows

def fixtures():
    inputs=bytearray();expected=bytearray();counts={'cases':0,'admitted':[0,0],'refusals':[0,0],'empty':[0,0],'output_aliases':[0,0],'terminal_cursor_wrap':[0,0]}
    for row in corpus():
        member,base,obj,dest,rdx,length,data=row;inputs.extend(struct.pack('<6Q',member,base,obj,dest,rdx,length)+data);r=resolve(row);counts['cases']+=1
        if r is None:expected.extend(bytes(40)+data);counts['refusals'][member]+=1
        else:
            updated,regs,reads,count,total=r;expected.extend(struct.pack('<5Q',1,*regs)+updated);counts['admitted'][member]+=1;counts['empty'][member]+=count==0;counts['output_aliases'][member]+=any(dest<a+8 and a<dest+8 for a in reads)
            if count:counts['terminal_cursor_wrap'][member]+=reads[4]+16*count>=N
    return bytes(inputs),bytes(expected),{**counts,'inputs_sha256':sha(inputs),'expected_sha256':sha(expected),'captured_code_executed':False}
if __name__=='__main__':
    require(not(ROOT/'src/node94-range-sum-pair').exists(),'Rust source predates freeze')
    inp,out,record=fixtures();record.update({'oracle_sha256_at_freeze':sha(Path(__file__).read_bytes()),'static_sha256_at_freeze':sha((PACKET/'static.json').read_bytes()),'source_directory_existed_at_freeze':False})
    for name,raw in [('inputs',inp),('expected',out)]:
        with(PACKET/(name+'.bin.gz')).open('xb')as f:f.write(gzip.compress(raw,compresslevel=1,mtime=0))
    with(PACKET/'frozen.json').open('x')as f:json.dump(record,f,indent=2,sort_keys=True);f.write('\n')
    print(json.dumps(record,sort_keys=True))
