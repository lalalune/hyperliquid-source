"""Pre-Rust chained reads, arithmetic sign extension and final byte replacement."""
import argparse,gzip,hashlib,json,random,struct
from pathlib import Path
PACKET=Path(__file__).resolve().parent
ROOT=PACKET.parents[2]
MOD=2**64
SIZE=256
INPUT='<BQQQH256s'
OUTPUT='<BQ256s'


def require(ok,message):
    if not ok:raise ValueError(message)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def expected(row):
    kind,base,object_,output,length,image=row
    def fail(tag):return (tag,0,image)
    if length and base+length>MOD:return fail(1)
    def read(address,width):
        offset=address-base
        if not(0<=offset and offset+width<=length):return None
        return sum(image[offset+j]*256**j for j in range(width))
    first=read((object_+0x788)%MOD,8)
    if first is None:return fail(2)
    second=read((first+0x30)%MOD,8)
    if second is None:return fail(3)
    field,width=(0xb30,4) if kind==0 else (0x1008,8)
    value=read((second+field)%MOD,width)
    if value is None:return fail(4)
    if kind==0 and value>=2**31:value+=MOD-2**32
    start=output-base
    if not(0<=start and start+8<=length):return fail(5)
    final=bytearray(image)
    final[start:start+8]=bytes(value//256**j%256 for j in range(8))
    return (0,1,bytes(final))


def corpus():
    rows=[]
    def make(kind,value,base=0,first_at=16,second_at=64,value_at=128,out_at=192,length=SIZE,seed=11):
        image=bytearray((seed+37*j)%256 for j in range(SIZE))
        field,width=(0xb30,4) if kind==0 else (0x1008,8)
        def put(at,value,width):
            if 0<=at and at+width<=SIZE:image[at:at+width]=bytes(value//256**j%256 for j in range(width))
        put(first_at,(base+second_at-0x30)%MOD,8)
        put(second_at,(base+value_at-field)%MOD,8)
        put(value_at,value,width)
        rows.append((kind,base,(base+first_at-0x788)%MOD,(base+out_at)%MOD,length,bytes(image)))
    edges=[0,1,127,128,255,256,0x7fffffff,0x80000000,0xffffffff,2**32,2**63-1,2**63,MOD-1]
    for kind in (0,1):
        for value in edges:
            for base in (0,0x1000,MOD-SIZE):make(kind,value,base)
        for out in range(-8,SIZE+1):
            for value in (0,1,0x7fffffff,0x80000000,0xffffffff,MOD-1):make(kind,value,out_at=out)
        for bit in range(64):
            for value in (2**bit-1,2**bit,min(MOD-1,2**bit+1)):make(kind,value)
        for byte in range(256):
            make(kind,0x12345600+byte)
            make(kind,(byte<<24)|0x0055aa11)
        for first in (0,1,7,8,15,16,17,56,64,127,128,129,248,249):
            for second in (0,1,8,16,56,64,65,120,128,248,249):
                for value_at in (0,16,64,128,249,252):make(kind,0x8877665544332211,first_at=first,second_at=second,value_at=value_at,out_at=second)
        for length in (0,7,8,15,16,23,24,63,64,71,72,127,128,131,132,135,136,191,192,199,200,255,256):
            for output in (0,16,64,128,192,248,249):make(kind,MOD-1,length=length,out_at=output)
        for base in (MOD-SIZE+1,MOD-8,MOD-1):make(kind,MOD-1,base)
    rng=random.Random(0x514ac20)
    for _ in range(2048):make(rng.randrange(2),rng.getrandbits(64),rng.choice((0,0x1000,MOD-SIZE)),first_at=rng.choice((16,16,rng.randrange(256))),second_at=rng.choice((64,64,rng.randrange(256))),value_at=rng.choice((128,128,rng.randrange(256))),out_at=rng.randrange(257),length=rng.choice((SIZE,SIZE,rng.randrange(257))),seed=rng.randrange(256))
    return rows


def fixtures():
    rows=corpus();results=[expected(row) for row in rows]
    inputs=b''.join(struct.pack(INPUT,*r) for r in rows);outputs=b''.join(struct.pack(OUTPUT,*r) for r in results)
    record={'cases':len(rows),'input_record_bytes':struct.calcsize(INPUT),'output_record_bytes':struct.calcsize(OUTPUT),'inputs_sha256':sha(inputs),'expected_sha256':sha(outputs),'outcomes':{str(tag):sum(x[0]==tag for x in results) for tag in range(6)},'source_directory_existed_at_freeze':False,'oracle_sha256_at_freeze':sha(Path(__file__).read_bytes()),'static_sha256_at_freeze':sha((PACKET/'static.json').read_bytes()),'captured_code_executed':False}
    return inputs,outputs,record


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--freeze',action='store_true');args=ap.parse_args();inputs,outputs,record=fixtures()
    if args.freeze:
        require(not (ROOT/'src/node94-chained-field-pair').exists(),'Rust exists before freeze')
        for name,raw in [('inputs',inputs),('expected',outputs)]:
            with (PACKET/(name+'.bin.gz')).open('xb') as f:f.write(gzip.compress(raw,mtime=0))
        with (PACKET/'frozen.json').open('x') as f:f.write(json.dumps(record,indent=2)+'\n')
    else:
        require(json.loads((PACKET/'frozen.json').read_text())==record,'frozen metadata')
        for name,raw in [('inputs',inputs),('expected',outputs)]:require(gzip.decompress((PACKET/(name+'.bin.gz')).read_bytes())==raw,'frozen stream')
    print(json.dumps(record,indent=2))


if __name__=='__main__':main()
