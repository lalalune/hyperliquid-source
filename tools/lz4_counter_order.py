#!/usr/bin/env python3
"""RE-001: selected LZ4 counter updates, ordered drains and checked accumulation."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from evm_amount_scale import ROOT,BINARY,SHA256,Image
from fde_extents import eh_frame_records

PACKET=ROOT/'research/work-items/RE-001-lz4-counter-order-94'
CASES=[(0x3d230c0,0x3d2328b,'8951b495f63bad976d23b39e4d7ef4073955ea3a3f9947772454d1d4c2420c7e'),
       (0x3d2a730,0x3d2abf0,'d4ce74cb5ce457957406bb40258a5a45c6444d3e7811c33497b6a38224cf1c7f')]
MASK=(1<<64)-1
ADDS=[(0x3d23188,0x3d23271,0x57199c0),(0x3d23197,0x3d2327e,0x57199d8),(0x3d231a6,0x3d23264,0x57199f0)]

def require(ok,message):
    if not ok:raise ValueError(message)

def observe(data):
    img=Image(data);read=img.read
    patterns={
      0x3d2a749:'488b07f048017010488b4708f048015010488b4710f048ff4010bf32000000',
      0x3d23163:'4531f64d877424104e8b64fae84531ed4d876c24104e8b64faf04531ff4d877c2410',
      0x3d23185:'4c8b274d01f40f82e00000004c89274d8b214d01ec0f82de0000004d89214d8b224d01fc0f82b50000004d8922',
      0x3d231b2:'4d85f6400f94c54989dc49c1ec304180fc020f94c14008e97417',
      0x3d23225:'f20f5ed9',
      0x3d23234:'891f48c1eb2066895f048847074c8977084c897f10f20f115f18',
      0x3d2324e:'44886706',
      0x203e80:'0000304300003045',0x202ea0:'00000000000030430000000000003045',
    }
    for va,raw in patterns.items():
        expected=bytes.fromhex(raw);require(read(va,len(expected))==expected,f'LZ4 operand/order changed at {va:#x}')
    sources=[];rel=img.relative_relocs()
    for index,(add,panic,loc) in enumerate(ADDS):
        branch=add+3;raw=read(branch,6)
        require(raw[:2]==b'\x0f\x82' and branch+6+struct.unpack('<i',raw[2:])[0]==panic,'LZ4 overflow edge changed')
        raw=read(panic,7)
        require(raw[:3]==b'\x48\x8d\x3d' and panic+7+struct.unpack('<i',raw[3:])[0]==loc,'LZ4 overflow source route changed')
        n,line,col=struct.unpack('<QII',read(loc+8,16));require(loc in rel,'LZ4 source relocation missing')
        path=read(rel[loc],n).decode('utf8')
        require(path=='/home/ubuntu/hl/code_Mainnet/net_utils/src/tcp/lz4_stats.rs' and (line,col)==(96+index,21),'LZ4 source context changed')
        sources.append(dict(location=hex(loc),path=path,line=line,column=col))
    _,fdes=eh_frame_records(data);owners=[]
    for start,end,digest in CASES:
        fs=[f for f in fdes if f['start']==start]
        require(len(fs)==1 and fs[0]['end']==end,'LZ4 owner FDE changed')
        require(hashlib.sha256(read(start,end-start)).hexdigest()==digest,'LZ4 owner body changed')
        owners.append(dict(start=hex(start),end_exclusive=hex(end),sha256=digest,fde=hex(fs[0]['fde']),cie=hex(fs[0]['cie'])))
    return dict(target_sha256=SHA256,owners=owners,sources=sources,
                exchanges=['0x3d23166','0x3d23173','0x3d23180'],checked_adds=[hex(a) for a,_,_ in ADDS],
                predicate='drained_input != 0 AND ((packed_key >> 48) & 255) != 2',
                output={'key_low32':0,'key_mid16':4,'key_byte48':6,'key_top8':7,'input':8,'samples':16,'ratio':24},
                limits='Selected sequential protocol with distinct counters/disjoint accumulators and normal helpers, not a coherent concurrent tuple, Rust atomic ordering or full table traversal.',
                captured_binaries_executed=False)

def build(data):
    require(hashlib.sha256(data).hexdigest()==SHA256,'Wrong node94 SHA-256')
    return observe(data)

def uint_float(img,value):
    require(type(value) is int and 0<=value<=MASK,'Expected raw u64')
    magic=img.read(0x203e80,8);offsets=struct.unpack('<dd',img.read(0x202ea0,16))
    lanes=[struct.unpack('<d',struct.pack('<I',word)+magic[4*n:4*n+4])[0]-offsets[n]
           for n,word in enumerate((value&0xffffffff,value>>32))]
    return lanes[0]+lanes[1]

def record_prefix(counters,input_bytes,output_bytes):
    require(len(counters)==3 and all(type(v) is int and 0<=v<=MASK for v in (*counters,input_bytes,output_bytes)),'Expected raw counter words')
    return tuple((old+delta)&MASK for old,delta in zip(counters,(input_bytes,output_bytes,1)))

def drain(img,counters,totals,key):
    require(len(counters)==len(totals)==3 and all(type(v) is int and 0<=v<=MASK for v in (*counters,*totals,key)),'Expected raw drain words')
    # Each bound XCHG is separate; synthetic cells are distinct and there is no interleaving.
    drained=list(counters);remaining=[0,0,0];updated=list(totals)
    for index,(va,_,_) in enumerate(ADDS):
        opcode=img.read(va,3)
        require(opcode[0]==0x4d and opcode[1] in (0x01,0x29),'Unsupported accumulator instruction')
        if opcode[1]==0x01:
            total=updated[index]+drained[index];overflow=total>MASK
        else:
            total=updated[index]-drained[index];overflow=total<0
        if overflow:return dict(route='overflow_'+str(index),remaining=remaining,totals=updated,record=None)
        updated[index]=total&MASK
    flag=(key>>48)&255
    if drained[0]==0 or flag==img.read(0x3d231c3,1)[0]:record=None
    else:record=dict(key=key,input=drained[0],samples=drained[2],ratio=uint_float(img,drained[1])/uint_float(img,drained[0]))
    return dict(route='skip' if record is None else 'emit',remaining=remaining,totals=updated,record=record)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',type=Path,default=ROOT/BINARY)
    p.add_argument('--out',type=Path,default=ROOT/'work/lz4-counter-order.json');a=p.parse_args()
    result=build(a.binary.read_bytes());a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf8',newline='\n')
    print('Verified selected LZ4 three-counter update and drain protocol')
if __name__=='__main__':main()
