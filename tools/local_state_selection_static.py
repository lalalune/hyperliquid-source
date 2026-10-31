#!/usr/bin/env python3
"""RE-001: message-bound raw-word selection in node94 local-state poller."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from evm_amount_scale import ROOT,BINARY,SHA256,Image
from fde_extents import eh_frame_records

PACKET=ROOT/'research/work-items/RE-001-local-state-selection-94'
START,END=0x22689f0,0x226b503
BODY_SHA='cc7958c8348146f55ce6e1be694987407e96b2142a737b136f03b87fea817b94'
MAX=(1<<64)-1
ANCHORS={
    0x226a974:'4c89bc24c8000000',0x226a97c:'4c89b424d0000000',
    0x226a984:'488b83b0000000',0x226a98b:'48898424d8000000',
    0x226ab0a:'488b8424d8000000',0x226ab12:'483de0b1ffff',0x226ab18:'7238',
    0x226ab1a:'4889c2',0x226ab1d:'4881c2204e0000',0x226ab24:'48c7c1ffffffff',
    0x226ab2b:'480f43ca',0x226ab36:'483b8c24d0000000',0x226ab3e:'772a',
    0x226ab43:'41bd1e000000',0x226ab50:'eb36',0x226ab52:'488d88204e0000',
    0x226ab60:'483b8c24d0000000',0x226ab68:'76d6',
    0x226ab6a:'483b8424c8000000',0x226ab72:'0f8339020000',0x226ab7b:'41bd23000000',
    0x226ab88:'c683f049000000',0x226ab97:'bae83a0000',
    0x226aba2:'48896c2420',0x226aba7:'4c896c2428',
}
RANGES=((0x226987c,0x2269883),(0x226a974,0x226a993),
        (0x226ab0a,0x226ab88),(0x226ab88,0x226abac))


def require(ok,message):
    if not ok:raise ValueError(message)


def saturated_limit(local):
    require(type(local) is int and 0<=local<=MAX,'Expected u64 local word')
    if local<(1<<64)-20000:
        return local+20000
    wrapped=(local+20000)&MAX
    carry=local+20000>MAX
    return MAX if carry else wrapped


def select(local,peer,initial):
    require(type(peer) is int and 0<=peer<=MAX and type(initial) is int and 0<=initial<=MAX,'Expected u64 comparison words')
    if saturated_limit(local)<=peer:return 'too_far_behind_message'
    if local<initial:return 'stale_hardfork_message'
    return 'continue_selected_window'


def observe(data):
    img=Image(data);read=img.read;relocs=img.relative_relocs()
    for va,raw in ANCHORS.items():
        require(read(va,len(bytes.fromhex(raw)))==bytes.fromhex(raw),f'State operand/control changed at {va:#x}')
    messages=[]
    for lea,text,size,expected in [(0x226ab49,0x3d79b2,30,b'local height is too far behind'),
                                   (0x226ab81,0x3d798f,35,b'local height is from stale hardfork')]:
        raw=read(lea,7)
        require(raw[:3]==b'\x48\x8d\x2d' and lea+7+struct.unpack('<i',raw[3:])[0]==text,'State reason LEA changed')
        require(read(text,size)==expected,'State reason bytes changed')
        messages.append({'lea':hex(lea),'text_va':hex(text),'length':size,'bytes_hex':expected.hex()})
    raw=read(0x226987c,7)
    require(raw[:3]==b'\x48\x8d\x3d' and 0x226987c+7+struct.unpack('<i',raw[3:])[0]==0x569e5d0,'Owner context LEA changed')
    loc=0x569e5d0;size,line,col=struct.unpack('<QII',read(loc+8,16))
    require(relocs.get(loc)==0x1ebd7c and read(0x1ebd7c,size)==b'/home/ubuntu/hl/code_Mainnet/node/src/local_abci_state.rs' and (line,col)==(111,18),'Owner source context changed')
    _,fdes=eh_frame_records(data);fs=[f for f in fdes if f['start']==START]
    require(len(fs)==1 and fs[0]['end']==END,'State owner FDE changed')
    require(hashlib.sha256(read(START,END-START)).hexdigest()==BODY_SHA,'State owner body changed')
    f=fs[0]
    return {'target_sha256':SHA256,'owner':{'start':hex(START),'end_exclusive':hex(END),'sha256':BODY_SHA,'fde':hex(f['fde']),'cie':hex(f['cie'])},
            'excerpt_ranges':[[hex(lo),hex(hi)] for lo,hi in RANGES],
            'raw_inputs':{'A':'[RBX+0xb0] -> [RSP+0xd8]','B':'prior R14 -> [RSP+0xd0]','C':'prior R15 -> [RSP+0xc8]'},
            'limit':'min(A + 20000, u64::MAX), with unsigned nonwrapping mathematical addition',
            'selection_order':['limit <= B: too far behind message','A < C: stale hardfork message','otherwise: continue selected window'],
            'messages':messages,'owner_source_context':{'location':hex(loc),'line':line,'column':col},
            'stale_join':{'clear_byte':'RBX+0x49f0','copy_size':0x3ae8,'reason_pointer':'RSP+0x20','reason_length':'RSP+0x28'},
            'limits':'Selected raw-word/message branches only. Prior register producers, peer selection, actual '
                     'height/time units, diagnostic emission, other admission checks, reachability and full poller semantics unproved.',
            'captured_binaries_executed':False}


def build(data):
    require(hashlib.sha256(data).hexdigest()==SHA256,'Wrong node94 SHA-256')
    return observe(data)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,default=ROOT/BINARY)
    p.add_argument('--out',type=Path,default=ROOT/'work/local-state-selection-94.json')
    args=p.parse_args();result=build(args.binary.read_bytes())
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf8',newline='\n')
    print(result['selection_order'])


if __name__=='__main__':main()
