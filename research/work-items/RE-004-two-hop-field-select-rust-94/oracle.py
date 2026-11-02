"""Pre-Rust relation over all valid qword intervals of immutable input bytes."""
from pathlib import Path
import gzip
import hashlib
import json
import random
import struct

PACKET=Path(__file__).resolve().parent
ROOT=PACKET.parents[2]
N=1<<64
SIZE=512


def sha(raw):return hashlib.sha256(raw).hexdigest()
def require(ok,why):
    if not ok:raise ValueError(why)


def corpus():
    rows=set()
    def add(base,layout,kind,value,length=SIZE,salt=0):
        entry,selector,terminal=layout
        p=(base+selector-0x1e0)%N
        q={'point':(base+terminal-8)%N,'zero':0,'one':1,'high':1<<32,'allones':N-1}.get(kind,kind)
        data=bytearray((i*37+(i>>2)+salt)%256 for i in range(SIZE))
        for at,v in [(selector-104,value^0xfedcba9876543210),(terminal,value),(selector,q),(entry,p)]:
            if 0<=at<=SIZE-8:data[at:at+8]=(v%N).to_bytes(8,'little')
        rows.add((base,(base+entry-8)%N,length,bytes(data)))
    bases=[0,1,8,0x1000,0x100000008,1<<63,N-SIZE]
    layouts=[(0,128,176),(16,128,0),(0,16,176),(0,480,504),(0,504,176),
             (504,128,176),(7,479,7),(8,112,8),(0,104,504),(0,103,176),
             (128,128,176),(0,128,128),(0,128,24),(24,128,176),(0,128,0),
             (0,128,7),(0,128,184)]
    values=[0,1,N-1,(1<<32)-1,1<<32,(1<<63)-1,1<<63,0x80000000ffffffff,0xfedcba9876543210]
    for base in bases:
        for layout in layouts:
            for kind in ['point','zero','one','high','allones']:
                for i,value in enumerate(values):add(base,layout,kind,value,salt=i)
        for bit in range(64):
            for delta in [-1,0,1]:
                for kind in ['point','zero']:add(base,(16,128,176),kind,((1<<bit)+delta)%N,salt=bit)
    for length in [0,1,7,8,15,16,23,24,31,32,103,104,111,112,119,120,127,128,135,136,175,176,183,184,191,192,375,376,383,384,479,480,487,488,503,504,511,512]:
        for layout in layouts:
            for kind in ['point','zero']:add(0x1000,layout,kind,0x8877665544332211,length)
    # Whole image overflows, while every selected field fits below 2^64.
    for kind in ['point','zero']:add(N-400,(0,128,176),kind,0x1122334455667788)
    rng=random.Random(0x5361710)
    for i in range(1800):
        add(rng.choice(bases),rng.choice(layouts),rng.choice(['point','zero','one','high','allones']),rng.getrandbits(64),rng.choice([SIZE,SIZE,488,184,136,32]),i)
    return sorted(rows)


def relation(row):
    base,obj,length,data=row
    if base+length>N:return (0,0,0),'image',{}
    # All admissible 8-byte intervals are formed independently of pointer roles.
    words={base+i:sum(data[i+j]*256**j for j in range(8)) for i in range(max(0,length-7))}
    try:
        p=words[(obj+8)%N];q=words[(p+480)%N]
        selected=(p+376)%N if q==0 else (q+8)%N
        other=(q+8)%N if q==0 else (p+376)%N
        value=words[selected]
        return (1,value,p),'fallback' if q==0 else 'indirect',{'p':p,'q':q,'selected':selected,'unused_absent':other not in words}
    except KeyError:return (0,0,0),'missing',{}


def fixtures():
    inputs=bytearray();expected=bytearray()
    counts={'cases':0,'outcomes':{},'unused_field_absent':{'fallback':0,'indirect':0},
            'zero_first_pointer_admitted':0,'zero_object_admitted':0,'high_only_second_pointer_admitted':0,'wrapped_selected_address':0}
    for row in corpus():
        result,outcome,details=relation(row);base,obj,length,data=row
        inputs.extend(struct.pack('<3Q',base,obj,length)+data);expected.extend(struct.pack('<3Q',*result));counts['cases']+=1
        counts['outcomes'][outcome]=counts['outcomes'].get(outcome,0)+1
        if result[0]:
            counts['unused_field_absent'][outcome]+=details['unused_absent']
            counts['zero_first_pointer_admitted']+=details['p']==0
            counts['zero_object_admitted']+=obj==0
            counts['high_only_second_pointer_admitted']+=details['q']!=0 and details['q']%(1<<32)==0
            counts['wrapped_selected_address']+=(details['p']+376>=N if outcome=='fallback' else details['q']+8>=N)
    return bytes(inputs),bytes(expected),{**counts,'input_record_bytes':536,'output_record_bytes':24,
        'inputs_sha256':sha(inputs),'expected_sha256':sha(expected),
        'oracle_sha256_at_freeze':sha(Path(__file__).read_bytes()),'static_sha256_at_freeze':sha((PACKET/'static.json').read_bytes()),
        'target_sha256':'3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f',
        'captured_execution':False,'instruction_emulation':False}


if __name__=='__main__':
    require(not(ROOT/'src/node94-two-hop-field-select').exists(),'freeze before Rust')
    inputs,expected,record=fixtures();record['rust_source_existed_at_freeze']=False
    for name,raw in [('inputs',inputs),('expected',expected)]:
        with(PACKET/(name+'.bin.gz')).open('xb')as f:f.write(gzip.compress(raw,compresslevel=1,mtime=0))
    with(PACKET/'frozen.json').open('xb')as f:f.write((json.dumps(record,sort_keys=True,indent=2)+'\n').encode())
    print(json.dumps(record,sort_keys=True))
