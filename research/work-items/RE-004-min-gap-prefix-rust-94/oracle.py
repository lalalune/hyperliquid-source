"""Pre-Rust immutable-image oracle: squared byte differences and bounded modular gap."""
import gzip
import struct
from verify_static import ROOT, PACKET, TARGET, encoded, require, sha

MOD=2**64
MASK=MOD-1
SIZE=256
HEADER=struct.Struct('<QQQH')
OUTPUT=struct.Struct('<BQ')


def expected(row):
    base,a,b,length,image=row
    if length and base+length>MOD:return (1,0)
    def offset(address,width):
        j=address-base
        return j if 0<=j and j+width<=length else None
    def number(j):return sum(image[j+k]*256**k for k in range(8))
    by=offset((b+8)%MOD,8);ax=offset((a+8)%MOD,8)
    if by is None or ax is None:return (2,0)
    x,y=number(ax),number(by);n=min(x,y)
    equal=True
    if n:
        bp=offset(b,8);ap=offset(a,8)
        if bp is None or ap is None:return (3,0)
        left,right=offset(number(ap),n),offset(number(bp),n)
        if left is None or right is None:return (4,0)
        equal=sum((image[left+k]-image[right+k])**2 for k in range(n))==0
    # This independent arithmetic formulation retains the bounded signed-gap
    # predicate. Rust instead uses the proved unsigned length ordering.
    residue=(n-y)%MOD
    signed=residue if residue<2**63 else residue-MOD
    accepted=(-2**31<=signed<2**31 and signed%(2**32)==0)
    return (0,int(equal and accepted))


def corpus():
    rows=set()
    def add(x=1,y=1,left=b'\x7f',right=b'\x7f',base=4096,a=16,b=48,ap=128,bp=192,length=SIZE,seed=29):
        image=bytearray((seed+37*j)%256 for j in range(SIZE))
        def put(j,data):
            if 0<=j and j+len(data)<=SIZE:image[j:j+len(data)]=data
        put(ap,left);put(bp,right)
        put(a,((base+ap)%MOD).to_bytes(8,'little'));put(a+8,x.to_bytes(8,'little'))
        put(b,((base+bp)%MOD).to_bytes(8,'little'));put(b+8,y.to_bytes(8,'little'))
        rows.add((base,(base+a)%MOD,(base+b)%MOD,length,bytes(image)))
    for left in range(256):
        for right in range(256):add(left=bytes([left]),right=bytes([right]))
    for n in range(1,33):
        data=bytes((37*j)%256 for j in range(n))
        for extra in [0,1,16]:
            add(n+extra,n,data,data)
            for at in sorted({0,n//2,n-1}):
                changed=data[:at]+bytes([data[at]^255])+data[at+1:]
                add(n+extra,n,data,changed);add(n+extra,n,changed,data)
        add(n,n+1,data,data)
    edges=[0,1,2,7,8,15,16,31,32,33,127,128,255,256,257,2**31-1,2**31,2**32-1,2**32,2**32+1,2**63-1,2**63, MASK]
    for x in edges:
        for y in edges:add(x,y)
    for base in [0,4096,MOD-SIZE]:
        for n in [0,1,2,8,16]:
            for ap in [-1,0,1,128,248,255,256,MASK]:
                for bp in [0,192,248,255,256]:add(n,n,b'\0'*n,b'\0'*n,base=base,ap=ap,bp=bp)
        for a,b in [(-8,48),(16,-8),(-8,-8),(0,32),(1,33),(240,208),(241,208),(256,48)]:
            for x,y in [(0,0),(0,1),(1,0),(1,1),(MASK,0),(0,MASK)]:add(x,y,base=base,a=a,b=b)
    for displacement in range(-15,16):
        for n in [0,1,2,8]:add(n,n,a=32,b=32+displacement)
    for ap in [16,24,48,56,17,23,25,47,49,55,57]:
        for bp in [16,24,48,56,128]:
            for n in [1,2,8,16]:add(n,n,ap=ap,bp=bp)
    for length in [0,7,8,15,16,23,24,31,32,47,48,55,56,63,64,127,128,129,191,192,193,255,256]:
        for n in [0,1,2,16]:add(n,n,length=length)
    for base in [MOD-SIZE+1,MASK-7,MASK]:add(base=base)
    for bit in range(64):
        add(1<<bit,0);add(0,1<<bit);add(1<<bit,1);add(1,1<<bit)
    for index in range(1024):
        digest=bytes.fromhex(sha(f'min-gap-prefix94:{index}'.encode()))
        x=int.from_bytes(digest[:8],'little') if digest[31]&1 else digest[0]%34
        y=int.from_bytes(digest[8:16],'little') if digest[31]&2 else digest[8]%34
        add(x,y,digest[:16],digest[8:24],a=digest[24]%249,b=digest[25]%249,
            ap=digest[26],bp=digest[27],length=digest[28],seed=digest[29])
    return sorted(rows)


def fixtures():
    rows=corpus();results=[expected(row) for row in rows]
    inputs=b''.join(HEADER.pack(*r[:4])+r[4] for r in rows);outputs=b''.join(OUTPUT.pack(*r) for r in results)
    counts={str(tag):sum(r[0]==tag for r in results) for tag in range(5)}
    require(all(counts.values()),'all safe outcomes')
    values={str(v):sum(r==(0,v) for r in results) for v in range(2)}
    require(all(values.values()),'both normal results')
    return inputs,outputs,{'target_sha256':TARGET,'cases':len(rows),'input_record_bytes':HEADER.size+SIZE,
        'output_record_bytes':OUTPUT.size,'image_bytes':SIZE,'outcome_counts':counts,'normal_values':values,
        'exhaustive_one_byte_pairs':65536,'inputs_sha256':sha(inputs),'expected_sha256':sha(outputs),
        'oracle':'unbounded squared byte differences and bounded signed modular gap',
        'external_premise':'standard normal-return readonly memcmp zero/equality contract',
        'refusals':'new checked image/length fields/pointers/byte spans, not original fault observations'}


def main():
    import sys
    require(sys.argv[1:]==['--freeze'],'only --freeze supported')
    require(not (ROOT/'src/node94-min-gap-prefix').exists(),'freeze before Rust')
    inputs,outputs,record=fixtures();record.update(oracle_sha256_at_freeze=sha((PACKET/'oracle.py').read_bytes()),
        static_sha256_at_freeze=sha((PACKET/'static.json').read_bytes()),rust_source_existed_at_freeze=False)
    for name,raw in [('inputs',inputs),('expected',outputs)]:
        with (PACKET/(name+'.bin.gz')).open('xb') as file:file.write(gzip.compress(raw,mtime=0))
    with (PACKET/'frozen.json').open('xb') as file:file.write(encoded(record))
    print(encoded(record).decode(),end='')


if __name__=='__main__':main()
