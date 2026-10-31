#!/usr/bin/env python3
"""RE-001: selected resolved-record predecessor walk and exact watermark, node94."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from evm_amount_scale import ROOT,BINARY,SHA256,Image
from fde_extents import eh_frame_records

PACKET=ROOT/'research/work-items/RE-001-mempool-parent-walk-94'
START,END=0x44b9800,0x44b9a4a
BODY='56b6b61a641c14db0b926cc42bd4fd5b3bf55f82d01d73e4a2211d6dd31a19f3'

def require(ok,message):
    if not ok:raise ValueError(message)

def walk(img,initial,watermark,records,step_bound=64):
    """Conditional stable resolved-record model; index lookup and insertion opaque."""
    require(type(initial) is bytes and len(initial)==32 and type(watermark) is int and 0<=watermark<1<<64,'Declared key/word domain')
    current=initial;calls=[];visited=[]
    for _ in range(step_bound):
        visited.append(current)
        if current not in records:return dict(status=1,key=current,insert_calls=calls,visited=visited)
        sequence,parent,hashes=records[current]
        require(type(sequence) is int and 0<=sequence<1<<64 and type(parent) is bytes and len(parent)==32,'Declared resolved record')
        require(all(type(h) is bytes and len(h)==32 for h in hashes),'Declared hash elements')
        first=img.read(0x44b9932,1)[0];require(first in (0x82,0x86),'Unsupported sequence branch')
        below_arm=sequence<watermark if first==0x82 else sequence<=watermark
        if below_arm:
            final=img.read(0x44b99d0,1)[0];require(final in (0x74,0x75),'Unsupported watermark join')
            error=(sequence!=watermark) if final==0x75 else (sequence==watermark)
            return dict(status=1 if error else 0,key=current if error else None,insert_calls=calls,visited=visited)
        calls.extend(hashes);current=parent
    raise ValueError('Synthetic model step bound; no native cycle-prevention claim')

def observe(data):
    img=Image(data);read=img.read
    patterns={
      0x44b9827:'0f1042300f104a400f294c24600f29442450',
      0x44b9839:'488b86b8010000',0x44b984e:'488b8698010000',0x44b985a:'488b86c0010000',
      0x44b9870:'0f1043400f104b500f294c24600f29442450',
      0x44b9920:'488b44242048398380000000488d6c24700f8699000000',
      0x44b9937:'4c8b73084d85f64c8d6c24080f8427ffffff',
      0x44b9949:'4c8b3b49c1e6054531e4',
      0x44b9960:'430f100427430f104c27100f298c24800000000f29442470',
      0x44b997e:'e87dfc46004983c4204d39e675d4e9dffeffff',
      0x44b99a9:'0f1148110f114001c60001',0x44b99b9:'e882284f00',
      0x44b99d0:'75c9488b442418488b0c24488941180f104424080f114108c60100',
    }
    for va,raw in patterns.items():
        expected=bytes.fromhex(raw);require(read(va,len(expected))==expected,f'Parent walk operand/route changed at {va:#x}')
    _,fdes=eh_frame_records(data);fs=[f for f in fdes if f['start']==START]
    require(len(fs)==1 and fs[0]['end']==END,'Parent walk owner FDE changed')
    require(hashlib.sha256(read(START,END-START)).hexdigest()==BODY,'Parent walk owner body changed')
    return dict(target_sha256=SHA256,owner=dict(start=hex(START),end_exclusive=hex(END),sha256=BODY,
                fde=hex(fs[0]['fde']),cie=hex(fs[0]['cie'])),initial_key='input+0x30 32 bytes',
                resolved_record={'sequence_word':'+0x80','next_key':'+0x40 32 bytes','elements_pointer':'+0','element_count':'+8'},
                watermark='state+0x198 copied at entry',element_bytes=32,insert_helper='0x4929600',error_cleanup='0x49ac240',
                termination={'above':'insert each element then follow next key','equal':'status byte 0','below_or_absent':'status byte 1 and current key'},
                limits='Stable resolved-record/normal-helper protocol only. Index tree geometry, original types, insertion/dedup effects, valid chains and output ownership unclosed.',
                captured_binaries_executed=False)

def build(data):
    require(hashlib.sha256(data).hexdigest()==SHA256,'Wrong node94 SHA-256')
    return observe(data)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',type=Path,default=ROOT/BINARY)
    p.add_argument('--out',type=Path,default=ROOT/'work/mempool-parent-walk.json');a=p.parse_args()
    result=build(a.binary.read_bytes());a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf8',newline='\n')
    print('Verified selected predecessor walk and exact-watermark join')
if __name__=='__main__':main()
