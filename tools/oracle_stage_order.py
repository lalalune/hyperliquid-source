#!/usr/bin/env python3
"""RE-001: selected post-membership oracle update stages, node94; static only."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from evm_amount_scale import ROOT,BINARY,SHA256,Image
from fde_extents import eh_frame_records

PACKET=ROOT/'research/work-items/RE-001-oracle-stage-order-94'
START,END=0x2707190,0x2707742
BODY='16242a8063ae3035b88fbec9173e9b33f66ea5a68e5525c4c383b96a5e6a0979'

def require(ok,message):
    if not ok:raise ValueError(message)

def stages(img,gate,lengths,validation,slot,slots,apply_word):
    require(all(type(s) is int and 0<=s<65536 for s in (gate,validation)),'Raw u16 status domain')
    require(len(lengths)==2 and all(type(v) is int and 0<=v<1<<64 for v in (*lengths,slot,slots,apply_word)),'Raw word domain')
    calls=['gate']
    if gate!=int.from_bytes(img.read(0x27072d5,2),'little'):return dict(route='forward_gate',status=gate,calls=calls)
    for index,va in enumerate((0x27072e1,0x2707368)):
        if lengths[index]>=int.from_bytes(img.read(va+4,4),'little'):return dict(route='bounds_'+str(index),status=323,calls=calls)
    calls.append('external_validation')
    if validation!=int.from_bytes(img.read(0x27073a0,4),'little'):return dict(route='forward_validation',status=validation,calls=calls)
    if slot>=slots:return dict(route='slot_failure',status=None,calls=calls)
    calls.append('apply')
    # NEG overflows only for the raw sign-bit-only word. MOVs preserve OF until JNO.
    overflow=apply_word==1<<63
    branch=img.read(0x2707491,1)[0];require(branch in (0x80,0x81),'Unsupported apply flag branch')
    post=(not overflow) if branch==0x81 else overflow
    if not post:return dict(route='forward_apply_packet',status=None,calls=calls)
    calls.append('post_apply')
    return dict(route='normal_return',status=int.from_bytes(img.read(0x270764c,2),'little'),calls=calls)

def observe(data):
    img=Image(data);read=img.read;rel=img.relative_relocs()
    patterns={0x27072cb:'e8307ab50066817c24208601752c',
      0x27072e1:'48817a10112700007265',0x27072ef:'66c7004301',
      0x2707350:'488d4218488984249800000048c784249000000000000000',
      0x2707368:'48817a4011270000720b',0x2707376:'66c7004301',
      0x270737d:'4c8d4230',0x2707394:'e857d503000fb754242081fa860100000f852d010000',
      0x27073c2:'4d3bbd783300000f83b2020000',0x27073ec:'4969c738010000',
      0x270742b:'41b801000000',0x2707437:'488b4424204889c148f7d9',
      0x2707442:'0f104424280f298424900000000f104424380f298424a00000000f104424480f298424b00000000f104424580f298424c00000000f104424680f298424d00000000f104424780f298424e00000000f8193000000',
      0x2707628:'e89378b500',0x2707649:'66c7008601',
    }
    for va,raw in patterns.items():
        expected=bytes.fromhex(raw);require(read(va,len(expected))==expected,f'Oracle stage/operand changed at {va:#x}')
    raw=read(0x2707431,6)
    require(raw[:2]==b'\xff\x15' and 0x2707437+struct.unpack('<i',raw[2:])[0]==0x5774988 and rel.get(0x5774988)==0x3709040,'Oracle apply helper changed')
    _,fdes=eh_frame_records(data);fs=[f for f in fdes if f['start']==START]
    require(len(fs)==1 and fs[0]['end']==END,'Oracle owner FDE changed')
    require(hashlib.sha256(read(START,END-START)).hexdigest()==BODY,'Oracle owner body changed')
    return dict(target_sha256=SHA256,owner=dict(start=hex(START),end_exclusive=hex(END),sha256=BODY,
                fde=hex(fs[0]['fde']),cie=hex(fs[0]['cie'])),model_entry='normal return from 0x325ed00 at 0x27072d0',
                calls=['0x325ed00','0x27448f0','0x3709040','0x325eec0'],length_checks=['action+0x10','action+0x40'],
                auxiliary_descriptor='action+0x18 passed onward; no selected length check here',
                apply_failure_raw_word='0x8000000000000000',
                limits='Selected normal-helper stage protocol only. Earlier validator/Dex preconditions, helper effects, input types, complete oracle mutation and final payloads unclosed.',
                captured_binaries_executed=False)

def build(data):
    require(hashlib.sha256(data).hexdigest()==SHA256,'Wrong node94 SHA-256')
    return observe(data)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',type=Path,default=ROOT/BINARY)
    p.add_argument('--out',type=Path,default=ROOT/'work/oracle-stage-order.json');a=p.parse_args()
    result=build(a.binary.read_bytes());a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf8',newline='\n')
    print('Verified selected oracle update stage ordering')
if __name__=='__main__':main()
