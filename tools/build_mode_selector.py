#!/usr/bin/env python3
"""RE-001: selected raw-byte build-mode/name selector priority, node94."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from evm_amount_scale import ROOT,BINARY,SHA256,Image
from fde_extents import eh_frame_records

PACKET=ROOT/'research/work-items/RE-001-build-mode-selector-94'
START,END=0x13cd410,0x13cd6cb
BODY='3c00a1876747c4feac86952f4df7de8a7ff631cbf484886bcf4667beabf85d49'

def require(ok,message):
    if not ok:raise ValueError(message)

def select(img,kind,flag,program):
    require(type(kind) is int and type(flag) is int and 0<=kind<256 and 0<=flag<256,'Expected raw mode bytes')
    require(type(program) is bytes,'Expected raw program bytes')
    # Lower the actual OR/length/two-XOR name predicate, before the kind compares.
    active=kind|flag
    if active==0:return {'route':'local','tag':img.read(0x13cd5f5,1)[0]}
    length=img.read(0x13cd432,1)[0]
    matched=False
    if len(program)==length:
        first=int.from_bytes(img.read(0x13cd437,8),'little')^int.from_bytes(program[:8],'little')
        second=int.from_bytes(program[8:10],'little')^struct.unpack('<I',img.read(0x13cd449,4))[0]
        matched=(first|second)==0
    if matched:return {'route':'special_client','tag':img.read(0x13cd5f5,1)[0]}
    if kind==img.read(0x13cd461,1)[0]:profile='debug'
    elif kind==img.read(0x13cd469,1)[0]:profile='release'
    else:return {'route':'invalid_kind','tag':None}
    return {'route':profile,'tag':img.read(0x13cd550,1)[0]}

def observe(data):
    img=Image(data);read=img.read;rel=img.relative_relocs()
    patterns={
      0x13cd428:'4489c008c8744f4883fa0a7521',
      0x13cd435:'48b872756e2d636c69654833060fb756084881f26e7400004809c20f8440010000',
      0x13cd456:'884c2428448844242980f901742e0fb6c183f8020f85c6010000',
      0x13cd470:'488d0563c0e4feb907000000eb20',
      0x13cd492:'488d053cc0e4feb905000000',
      0x13cd54d:'c6431801',0x13cd5f2:'c6431800',
      0x13cd4ee:'4c8b3d33143a04',0x13cd501:'4983c718',
      0x13cd596:'4c8b358b133a04',0x13cd5a9:'4983c618',
      0x13cd525:'488d35dbd8e2fe',0x13cd5be:'488d35b276e1fe',
      0x1fae07:'c00b2f6177735f6275696c642fc000',0x1e4c77:'c0102f636f64652f72756e2d636c69656e7400',
    }
    for va,raw in patterns.items():
        expected=bytes.fromhex(raw);require(read(va,len(expected))==expected,f'Build selector/operand changed at {va:#x}')
    require(read(0x2194d5,5)==b'debug' and read(0x2194da,7)==b'release','Build profile literal changed')
    require(rel.get(0x576e928)==0x577b288,'Build global context relocation changed')
    for va in (0x13cd4de,0x13cd536,0x13cd5cd):
        raw=read(va,6)
        require(raw[:2]==b'\xff\x15' and va+6+struct.unpack('<i',raw[2:])[0]==0x576e040 and rel.get(0x576e040)==0x1344760,'Build formatter call changed')
    loc=0x566a0c0;raw=read(0x13cd653,7)
    require(raw[:3]==b'\x48\x8d\x15' and 0x13cd65a+struct.unpack('<i',raw[3:])[0]==loc,'Build failure source route changed')
    require(loc in rel,'Build source relocation missing')
    n,line,col=struct.unpack('<QII',read(loc+8,16));path=read(rel[loc],n).decode('utf8')
    require(path.endswith('/base/src/build_mode.rs') and (line,col)==(199,30),'Build source context changed')
    _,fdes=eh_frame_records(data);fs=[f for f in fdes if f['start']==START]
    require(len(fs)==1 and fs[0]['end']==END,'Build owner FDE changed')
    require(hashlib.sha256(read(START,END-START)).hexdigest()==BODY,'Build owner body changed')
    return dict(target_sha256=SHA256,owner=dict(start=hex(START),end_exclusive=hex(END),sha256=BODY,
                fde=hex(fs[0]['fde']),cie=hex(fs[0]['cie'])),source=dict(location=hex(loc),path=path,line=line,column=col),
                priority=['both raw mode bytes zero','exact run-client','kind1 debug','kind2 release','invalid-kind failure'],
                global_argument='relocated context +0x18, opaque contents',tags={'local_and_special':0,'profile':1},
                limits='Selected byte/name predicate and output tag only; valid Rust mode domain, formatter/global contents, allocation/drop/unwind and command execution unproved.',
                captured_binaries_executed=False)

def build(data):
    require(hashlib.sha256(data).hexdigest()==SHA256,'Wrong node94 SHA-256')
    return observe(data)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',type=Path,default=ROOT/BINARY)
    p.add_argument('--out',type=Path,default=ROOT/'work/build-mode-selector.json');a=p.parse_args()
    result=build(a.binary.read_bytes());a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf8',newline='\n')
    print('Verified selected build-mode/name precedence and output tag')
if __name__=='__main__':main()
