#!/usr/bin/env python3
"""RE-001: node94 gossip request/response tag-to-helper routing, static only."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from evm_amount_scale import ROOT,BINARY,SHA256,Image
from fde_extents import eh_frame_records

PACKET=ROOT/'research/work-items/RE-001-gossip-enum-routes-94'
CASES=[(0x438b5c0,0x438b6d7,'7a48fd979909abac3a2a0afaf73f2b63ee8ee30111626fb3e0d859171661feeb'),
       (0x438b6e0,0x438b944,'e39709a89eda075e7e8272d5f4c0fc83214c46764cd1166abfe26c886d45423b')]
TABLE=0x6ef9c0
ARMS=[(0x438b71e,0x438b72b,0x4589b30),(0x438b831,0x438b837,0x496f730),
      (0x438b795,0x438b79b,0x466c770),(0x438b7d1,0x438b7d7,0x466dc10)]

def require(ok,message):
    if not ok:raise ValueError(message)

def call_target(img,va):
    raw=img.read(va,5);require(raw[0]==0xe8,'Expected direct call')
    return va+5+struct.unpack('<i',raw[1:])[0]

def request_arm(img,tag):
    """Interpret only TEST/CMP and branches in the real tag selector."""
    require(type(tag) is int and 0<=tag<1<<32,'Expected raw u32 tag')
    pc=0x438b5e3;zero=False
    stops={0x438b640:'two_u64',0x438b630:'unit_1',0x438b5f5:'unit_2',0x438b682:'invalid'}
    for _ in range(10):
        if pc in stops:return stops[pc]
        raw=img.read(pc,6)
        if raw[:2]==b'\x85\xc0':zero=tag==0;pc+=2
        elif raw[:2]==b'\x83\xf8':zero=tag==raw[2];pc+=3
        elif raw[0]==0x74:pc+=2+(int.from_bytes(raw[1:2],'little',signed=True) if zero else 0)
        elif raw[:2]==b'\x0f\x85':pc+=6+(struct.unpack('<i',raw[2:])[0] if not zero else 0)
        else:raise ValueError('Unknown request selector instruction')
    raise ValueError('Request selector step bound')

def request_route(img,tag,header_status,payload_statuses=(18,18)):
    require(type(header_status) is int and 0<=header_status<256,'Expected raw header status')
    success=img.read(0x438b5dc,1)[0]
    if header_status!=success:return dict(route='header_error',calls=[])
    arm=request_arm(img,tag)
    if arm!='two_u64':return dict(route=arm,calls=[])
    require(len(payload_statuses)==2 and all(type(s) is int and 0<=s<256 for s in payload_statuses),'Expected two raw statuses')
    calls=[]
    for va,status in zip((0x438b646,0x438b65e),payload_statuses):
        calls.append(hex(call_target(img,va)))
        if status!=success:return dict(route='payload_error',calls=calls)
    return dict(route='two_u64',calls=calls)

def response_arm(img,tag):
    require(type(tag) is int and 0<=tag<1<<32,'Expected raw u32 tag')
    if tag>img.read(0x438b707,1)[0]:return None
    target=TABLE+struct.unpack('<i',img.read(TABLE+4*tag,4))[0]
    # Real arm prologues have one optional payload-decoder argument LEA.
    raw=img.read(target,3);offset=13 if raw==b'\x48\x8d\x15' else 6
    return dict(target=hex(target),callee=hex(call_target(img,target+offset)))

def observe(data):
    img=Image(data);read=img.read
    def exact(va,hexbytes,label):
        expected=bytes.fromhex(hexbytes);require(read(va,len(expected))==expected,label+' changed')
    for va,target in ((0x438b5d2,0x466bc10),(0x438b6f3,0x466bc10),
                      (0x438b646,0x466bd10),(0x438b65e,0x466bd10)):
        require(call_target(img,va)==target,'Enum helper target changed')
    exact(0x438b5db,'3c127520','Request header status branch')
    exact(0x438b5e3,'85c0745983f801744483f8020f858d000000','Request selector')
    exact(0x438b64f,'3c127555','First request field status')
    exact(0x438b667,'3c12753d','Second request field status')
    exact(0x438b630,'48c7430801000000c60312','Request unit1 stores')
    exact(0x438b5f5,'48c7430802000000','Request unit2 store')
    exact(0x438b670,'48c74308000000004c897b1048894318','Request pair stores')
    exact(0x438b682,'c60305894304','Request invalid tag stores')
    exact(0x438b6fc,'3c127563','Response header status branch')
    exact(0x438b704,'4883f8030f8766010000','Response tag bound')
    exact(0x438b70e,'488d0dab4236fc486304814801c8ffe0','Response table dispatch')
    for index,(arm,call,helper) in enumerate(ARMS):
        require(response_arm(img,index)==dict(target=hex(arm),callee=hex(helper)),'Response arm binding changed')
        require(call_target(img,call)==helper,'Response payload helper changed')
        exact(call+9,'3c12','Response payload success check')
    for va,raw in ((0x438b860,'48c7430801000000'),(0x438b7c4,'48c7430802000000'),
                   (0x438b800,'48c7430803000000'),(0x438b868,'48c70300000000'),
                   (0x438b92f,'48c70301000000'),(0x438b874,'c643080589430c')):
        exact(va,raw,'Response tag/status store')
    for va,text in ((0x204640,b'GossipRpcRequest'),(0x6f160f,b'GossipRpcResponse')):
        require(read(va,len(text))==text,'Enum type literal changed')
    exact(0x438b688,'488d05b18fe7fb','Request type reference')
    exact(0x438b693,'48c7431010000000','Request type length')
    exact(0x438b69b,'488d056edde7fb','Request range reference')
    exact(0x438b87b,'488d058d5d36fc','Response type reference')
    exact(0x438b886,'48c7431811000000','Response type length')
    exact(0x438b88e,'488d053b7ae7fb','Response range reference')
    exact(0x209410,'00000000000000000000000002000000','Request range data')
    exact(0x2032d0,'00000000000000000000000003000000','Response range data')
    _,fdes=eh_frame_records(data);owners=[]
    for start,end,digest in CASES:
        fs=[f for f in fdes if f['start']==start]
        require(len(fs)==1 and fs[0]['end']==end,'Enum owner FDE changed')
        require(hashlib.sha256(read(start,end-start)).hexdigest()==digest,'Enum owner body changed')
        owners.append(dict(start=hex(start),end_exclusive=hex(end),sha256=digest,fde=hex(fs[0]['fde']),cie=hex(fs[0]['cie'])))
    return dict(target_sha256=SHA256,owners=owners,
                request={'header_helper':'0x466bc10','pair_helpers':['0x466bd10','0x466bd10'],'unit_tags':[1,2],'pair_tag':0,'invalid_from':3},
                response={'header_helper':'0x466bc10','table':hex(TABLE),'arms':[response_arm(img,n) for n in range(4)],'invalid_from':4},
                helper_success_byte=18,invalid_tag_error_byte=5,
                limits='Selected enum routing and conditional raw helper-status protocol only. Payload grammar, helper closure, actual wire consumption, original Rust layouts and networking remain unproved.',
                captured_binaries_executed=False)

def build(data):
    require(hashlib.sha256(data).hexdigest()==SHA256,'Wrong node94 SHA-256')
    return observe(data)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',type=Path,default=ROOT/BINARY)
    p.add_argument('--out',type=Path,default=ROOT/'work/gossip-enum-routes.json');a=p.parse_args()
    result=build(a.binary.read_bytes());a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf8',newline='\n')
    print('Verified paired gossip enum selector and helper routing')
if __name__=='__main__':main()
