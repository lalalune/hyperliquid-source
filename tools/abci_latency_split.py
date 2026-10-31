#!/usr/bin/env python3
"""RE-001: selected ABCI latency samples and raw prepared row field, node94."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import struct
from evm_amount_scale import ROOT,BINARY,SHA256,Image
from fde_extents import eh_frame_records

PACKET=ROOT/'research/work-items/RE-001-abci-latency-split-94'
CASES=[(0x3d22500,0x3d22911,'0076c7ca0d02e0b123d189d519afd88ec40b3a45f6ecbbee04b9fb5e8ac110b1'),
       (0x3d22920,0x3d22a97,'e33e61eb44814d2cc675fb3ee1fba959934e28e99c0c4a0894923e74b4401cf9')]

def require(ok,message):
    if not ok:raise ValueError(message)

def finite(bits):
    require(type(bits) is int and 0<=bits<1<<64,'Expected raw f64 bits')
    value=struct.unpack('<d',struct.pack('<Q',bits))[0]
    require(math.isfinite(value),'Declared model requires finite helper return')
    return value

def capped(img,bits):
    raw=finite(bits);cap=struct.unpack('<d',img.read(0x20abf8,8))[0]
    return bits if raw<=cap else int.from_bytes(img.read(0x20abf8,8),'little')

def begin_selected(img,saved_word,raw_flag,block_bits,backlog_bits):
    require(type(saved_word) is int and 0<=saved_word<1<<32 and type(raw_flag) is int and 0<=raw_flag<1<<32,'Expected declared raw words')
    samples=[]
    if saved_word!=0:samples.append((0,capped(img,block_bits)))
    if raw_flag&255:finite(backlog_bits);samples.append((0x260,backlog_bits))
    return samples

def commit_selected(img,saved_word,bits):
    require(type(saved_word) is int and 0<=saved_word<1<<32,'Expected raw saved word')
    if saved_word==0:return {'metric':None,'prepared_row_bits':None}
    finite(bits)
    # Interpret the selected MOVAPD/MOVSD/MINSD spill/reload sequence only.
    require(img.read(0x3d225cc,4)==bytes.fromhex('660f28c8'),'Unexpected raw-to-XMM1 copy')
    xmm1=bits;stack={}
    spill=img.read(0x3d225d0,6);require(spill[:4]==bytes.fromhex('f20f1144'),'Unexpected raw spill')
    stack[spill[5]]=bits
    raw=img.read(0x3d225dd,8);require(raw[:4]==bytes.fromhex('f20f1005'),'Unexpected cap load')
    address=0x3d225e5+struct.unpack('<i',raw[4:])[0]
    xmm0=int.from_bytes(img.read(address,8),'little')
    opcode=img.read(0x3d225e5,4)
    require(opcode in (bytes.fromhex('f20f5dc1'),bytes.fromhex('f20f5fc1')),'Unsupported scalar selection')
    choose_raw=finite(xmm1)<=finite(xmm0) if opcode[2]==0x5d else finite(xmm1)>=finite(xmm0)
    metric=xmm1 if choose_raw else xmm0
    # The sample call may clobber XMM0: the row reload uses the saved stack word.
    reload=img.read(0x3d22603,6);require(reload[:5]==bytes.fromhex('f20f104424'),'Unexpected row reload')
    require(reload[5] in stack,'Row reload escaped saved raw value')
    row=stack[reload[5]]
    require(img.read(0x3d22609,9)==bytes.fromhex('f20f118424a8000000'),'Unexpected row field store')
    return {'metric':metric,'prepared_row_bits':row}

def observe(data):
    img=Image(data);read=img.read;rel=img.relative_relocs()
    patterns={
      0x3d22522:'83bbd0070000000f8458030000',0x3d2293d:'4183bed0070000000f8482000000',
      0x3d229d4:'4084ed7471',0x3d229d9:'4981c660020000',
      0x3d225cc:'660f28c8f20f11442470488dbbc0040000f20f100513864efcf20f5dc1',
      0x3d22603:'f20f10442470f20f118424a8000000',
      0x3d2282e:'488d9424a00000004c89f7e8b2270000',
      0x3d229a8:'f20f100d48824efcf20f5dc8',
      0x3d22a6b:'488b4424284989078b442430418947088b4424344189470c488b44243849894710',
      0x20abf8:'0000000000004e40',
    }
    for va,raw in patterns.items():
        expected=bytes.fromhex(raw);require(read(va,len(expected))==expected,f'ABCI operand/dataflow changed at {va:#x}')
    for va,slot,target in ((0x3d2251c,0x576e8a0,0x151cba0),(0x3d22937,0x576e8a0,0x151cba0),
                           (0x3d225c6,0x576e8c0,0x1447130),(0x3d229a2,0x576e8c0,0x1447130),(0x3d22a2f,0x576e8c0,0x1447130),
                           (0x3d225f5,0x576efb0,0x14027b0),(0x3d229c7,0x576efb0,0x14027b0),(0x3d22a44,0x576efb0,0x14027b0)):
        raw=read(va,6)
        require(raw[:2]==b'\xff\x15' and va+6+struct.unpack('<i',raw[2:])[0]==slot and rel.get(slot)==target,'ABCI helper binding changed')
    for va in (0x3d225f0,0x3d229bb,0x3d22a3c):
        require(read(va,5)==b'\xbe\x01\x00\x00\x00','ABCI sample weight changed')
    sources=[]
    for loc,line,col in ((0x57193a0,67,48),(0x57193b8,55,41),(0x57193d0,58,34)):
        n,l,c=struct.unpack('<QII',read(loc+8,16));require(loc in rel,'ABCI source relocation missing')
        path=read(rel[loc],n).decode('utf8')
        require(path.endswith('/net_utils/src/abci_latency_sampler.rs') and (l,c)==(line,col),'ABCI source context changed')
        sources.append(dict(location=hex(loc),path=path,line=l,column=c))
    _,fdes=eh_frame_records(data);owners=[]
    for start,end,digest in CASES:
        fs=[f for f in fdes if f['start']==start]
        require(len(fs)==1 and fs[0]['end']==end,'ABCI owner FDE changed')
        require(hashlib.sha256(read(start,end-start)).hexdigest()==digest,'ABCI owner body changed')
        owners.append(dict(start=hex(start),end_exclusive=hex(end),sha256=digest,fde=hex(fs[0]['fde']),cie=hex(fs[0]['cie'])))
    return dict(target_sha256=SHA256,owners=owners,sources=sources,cap_bits='404e000000000000',
                metrics={'block':'+0','backlog':'+0x260','commit':'+0x4c0'},raw_row_field='stack+0xa8 prepared before later reporter guards',
                limits='Conditional normal finite helper returns only. Chrono grammar, nonfinite FP states, complete row serializer/persistence, reporter rotation, flush and unwind unclosed.',
                captured_binaries_executed=False)

def build(data):
    require(hashlib.sha256(data).hexdigest()==SHA256,'Wrong node94 SHA-256')
    return observe(data)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',type=Path,default=ROOT/BINARY)
    p.add_argument('--out',type=Path,default=ROOT/'work/abci-latency-split.json');a=p.parse_args()
    result=build(a.binary.read_bytes());a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf8',newline='\n')
    print('Verified ABCI capped samples and raw prepared row field')
if __name__=='__main__':main()
