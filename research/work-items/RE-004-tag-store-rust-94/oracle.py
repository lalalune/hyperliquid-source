"""Pre-Rust immutable-image byte overlay for the complete low32 tag domain."""
import gzip,struct
from verify_static import ROOT,PACKET,TARGET,encoded,require,sha
MOD=1<<64
SIZE=64
POINT=0x57592a0
INPUT=struct.Struct('<5QH64s')
OUTPUT=struct.Struct('<BQ64s')

def expected(row):
    base,bias,destination,source,tag,length,image=row
    def fail(code):return (code,0,image)
    if base+length>MOD:return fail(1)
    selected=tag%(1<<32)
    if selected>2:return (0,0,image)
    width=16 if selected==2 else 8
    if selected==2:
        first=source-base
        if first<0 or first+16>length:return fail(2)
        replacement=tuple(image[first+j] for j in range(16))
    else:
        value=(bias+POINT)%MOD if selected==0 else source
        replacement=tuple(value//256**j%256 for j in range(8))
    first=destination-base
    if first<0 or first+width>length:return fail(3)
    overlay={first+j:b for j,b in enumerate(replacement)}
    return (0,0,bytes(overlay.get(j,b) for j,b in enumerate(image)))

def corpus():
    rows=set()
    def add(tag=2,source=4096+16,destination=4096+32,base=4096,bias=0,length=SIZE,seed=23):
        image=bytes((seed+37*j)%256 for j in range(SIZE))
        rows.add((base,bias,destination,source,tag,length,image))
    for src in range(-16,SIZE+1):
        for dst in range(-16,SIZE+1):add(source=(4096+src)%MOD,destination=(4096+dst)%MOD)
    values=[0,1,7,8,15,16,255,256,2**31-1,2**31,2**32-1,2**32,2**63-1,2**63,MOD-POINT-1,MOD-POINT,MOD-POINT+1,MOD-1]
    for tag in [0,1]:
        for dst in range(-8,SIZE+1):
            for value in values:add(tag=tag,source=value,bias=value,destination=4096+dst)
    for low in range(256):
        for high in [0,1,0x80000000,0xffffffff]:
            add(tag=low+(high<<32),source=MOD-1,destination=MOD-1,bias=MOD-POINT)
            add(tag=low+(high<<32),source=4096+16,destination=4096+32,bias=0x123400000000)
    for base in [0,4096,MOD-SIZE]:
        for bias in [0,1,0x1000,MOD-POINT,MOD-1]:
            for tag in [0,1,2,3,2**32,2**32+1,2**32+2,MOD-1]:
                for src,dst in [(0,0),(1,2),(2,1),(8,0),(0,8),(48,48),(48,49),(49,48),(56,56),(63,63),(64,64),(-1,0),(0,-1)]:
                    add(tag=tag,source=(base+src)%MOD,destination=(base+dst)%MOD,base=base,bias=bias)
    for length in range(SIZE+1):
        for tag in [0,1,2,3]:
            for src,dst in [(0,0),(1,2),(16,32),(32,16),(48,48),(56,56),(64,64)]:
                add(tag=tag,source=4096+src,destination=4096+dst,length=length)
    for base in [MOD-SIZE+1,MOD-8,MOD-1]:
        for tag in range(4):add(base=base,tag=tag)
    for bit in range(64):
        for tag in [0,1]:add(tag=tag,source=1<<bit,bias=1<<bit)
    for i in range(2048):
        d=bytes.fromhex(sha(f'tag-store94:{i}'.encode()));base=[0,4096,MOD-SIZE][d[0]%3]
        tag=int.from_bytes(d[8:16],'little') if i%3 else (int.from_bytes(d[8:12],'little')<<32)+(d[12]%4)
        source=(base+d[1]%80-8)%MOD if tag%(1<<32)==2 else int.from_bytes(d[16:24],'little')
        add(tag,source,(base+d[2]%80-8)%MOD,base,int.from_bytes(d[24:32],'little'),d[3]%65,d[4])
    return sorted(rows)

def fixtures():
    rows=corpus();answers=[expected(r) for r in rows]
    inputs=b''.join(INPUT.pack(*r) for r in rows);outputs=b''.join(OUTPUT.pack(*r) for r in answers)
    counts={str(t):sum(r[0]==t for r in answers) for t in range(4)};require(all(counts.values()),'all safe outcomes')
    return inputs,outputs,{'target_sha256':TARGET,'cases':len(rows),'input_record_bytes':INPUT.size,'output_record_bytes':OUTPUT.size,'image_bytes':SIZE,'outcome_counts':counts,'inputs_sha256':sha(inputs),'expected_sha256':sha(outputs),'oracle':'low32 modulo selection and immutable positional-byte overlay','overlap_grid':'all source/destination offsets -16..64 at image base4096','refusals':'new nonwrapping image/source/destination errors, atomic and not native faults'}

def main():
    import sys
    require(sys.argv[1:]==['--freeze'],'only --freeze');require(not (ROOT/'src/node94-tag-store').exists(),'freeze before Rust')
    inputs,outputs,r=fixtures();r.update(oracle_sha256_at_freeze=sha((PACKET/'oracle.py').read_bytes()),static_sha256_at_freeze=sha((PACKET/'static.json').read_bytes()),rust_source_existed_at_freeze=False)
    for name,raw in [('inputs',inputs),('expected',outputs)]:
        with (PACKET/(name+'.bin.gz')).open('xb') as f:f.write(gzip.compress(raw,mtime=0))
    with (PACKET/'frozen.json').open('xb') as f:f.write(encoded(r))
    print(encoded(r).decode(),end='')
if __name__=='__main__':main()
