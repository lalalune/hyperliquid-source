#!/usr/bin/env python3
"""RE-001: captured chainId/address/nonce key and prepared-map control flow."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from evm_amount_scale import ROOT,BINARY,SHA256,Image
from fde_extents import eh_frame_records

PACKET=ROOT/'research/work-items/RE-001-three-field-map-94'
OWNERS={0x4674b50:(0x467538c,'5db7141e11a748d3fefc5d59a5537382b436d4a7eabd860708cc454f0eade952'),
        0x4bd2c90:(0x4bd2f16,'9e2bb9190072510abfbbfbf0f0905b1252da8f0b387e4410f05def6a4880defc')}
KEYS=(b'chainId',b'address',b'nonce')
TARGETS=(0x4674c8d,0x4674da5,0x4674d27,0x4674d6b)
ANCHORS={
    0x4674b64:'488b5e08',0x4674b68:'488b4610',0x4674b6f:'49c1e506',
    0x4674be0:'4c8d6340',0x4674bfe:'807c245016',0x4674c03:'750d',
    0x4674c6f:'80f909',0x4674c72:'0f8523050000',0x4674c7d:'488d0da02308fc',
    0x4674c84:'48630481',0x4674c88:'4801c8',0x4674c8b:'ffe0',
    0x4674c8d:'4883bc24b800000001',0x4674c96:'0f84b4050000',
    0x4674d27:'4883bc24a800000001',0x4674d30:'0f8462050000',
    0x4674da5:'f68424b000000001',0x4674dad:'0f852a050000',
    0x4674ce0:'837c245001',0x4674ce5:'0f8445050000',
    0x4674e3d:'0fb6442450',0x4674e42:'3c09',0x4674e44:'7557',
    0x4674e79:'807c245009',0x4674e7e:'7578',
    0x4674f66:'f68424b800000001',0x4674f73:'0f8485000000',
    0x4674f79:'f68424b000000001',0x4674f81:'0f8401010000',
    0x4674f9f:'f68424a800000001',0x4674fa7:'0f8469010000',
    0x4674fbd:'410f114c2418',0x4674fc3:'410f11442408',
    0x4674fce:'410f11442430',0x4674fd8:'4189442440',0x4674fe5:'4989442428',
    0x4674fea:'49c7042400000000',0x4675054:'49c7042401000000',
    0x4bd2cd1:'4883f905',0x4bd2cdb:'4883f907',
    0x4bd2d8b:'31c9',0x4bd2d17:'b101',0x4bd2e3b:'b102',0x4bd2ee0:'b103',
    0x4bd2ee2:'884b01',0x4bd2ee5:'c60309',
}
CALLS={0x4674c61:0x4bd2c90,0x4674cdb:0x4b7f180,0x4674e38:0x4b7afa0,
       0x4674e74:0x4b78e80,0x4674e07:0x4c6daf0}
NAME_LEAS={0x4675003:(0x6f71da,b'chainId'),0x4675088:(0x6f708d,b'address'),
           0x4675116:(0x6f71e1,b'nonce'),0x4675250:(0x6f71da,b'chainId'),
           0x4675298:(0x6f71e1,b'nonce'),0x46752dd:(0x6f708d,b'address')}


def require(ok,message):
    if not ok:raise ValueError(message)


def byte_key(value):
    require(isinstance(value,bytes),'Expected byte slice')
    # Same 4+4 overlapping or 4+1 comparisons observed in the slice branch.
    if len(value)==7:
        if value[:4]==b'chai' and value[3:]==b'inId':return 0
        if value[:4]==b'addr' and value[3:]==b'ress':return 1
    if len(value)==5 and value[:4]==b'nonc' and value[4]==0x65:return 2
    return 3


def prepared_fields(keys):
    """Present values, successful key/value helpers, ordinary drops only."""
    seen=[False]*3
    for key in keys:
        field=byte_key(key)
        if field==3:continue
        if seen[field]:return {'path':'duplicate','field':KEYS[field].decode()}
        seen[field]=True
    for field,label in [(0,'chainId_missing_path'),(1,'address_missing_helper'),(2,'nonce_missing_helper')]:
        if not seen[field]:return {'path':label,'field':KEYS[field].decode()}
    return {'path':'success_candidate','field':None}


def observe(data):
    img=Image(data);read=img.read
    for va,raw in ANCHORS.items():
        require(read(va,len(bytes.fromhex(raw)))==bytes.fromhex(raw),f'Map operand/control changed at {va:#x}')
    table=0x4674c7d+7+struct.unpack('<i',read(0x4674c7d+3,4))[0]
    targets=tuple(table+struct.unpack('<i',read(table+4*i,4))[0] for i in range(4))
    require(table==0x6f7024 and targets==TARGETS,'Map field table changed')
    for va,target in CALLS.items():
        raw=read(va,5)
        require(raw[0]==0xe8 and va+5+struct.unpack('<i',raw[1:])[0]==target,'Map helper call changed')
    relocs=img.relative_relocs();raw=read(0x4674bf8,6)
    require(raw[:2]==b'\xff\x15' and 0x4674bf8+6+struct.unpack('<i',raw[2:])[0]==0x57746b0 and
            relocs.get(0x57746b0)==0x4eb8d00,'Map item helper binding changed')
    for va,(text,value) in NAME_LEAS.items():
        raw=read(va,7)
        require(raw[:3]==b'\x48\x8d\x05' and va+7+struct.unpack('<i',raw[3:])[0]==text and read(text,len(value))==value,'Map diagnostic field binding changed')
    for va,text,size in [(0x7041cd,b'chainId',7),(0x7040a8,b'address',7),(0x7041d4,b'nonce',5)]:
        require(read(va,size)==text,'Key comparison data changed')
    _,fdes=eh_frame_records(data);owners=[]
    for start,(end,digest) in OWNERS.items():
        fs=[f for f in fdes if f['start']==start]
        require(len(fs)==1 and fs[0]['end']==end,'Map owner FDE changed')
        require(hashlib.sha256(read(start,end-start)).hexdigest()==digest,'Map owner body changed')
        f=fs[0];owners.append({'start':hex(start),'end_exclusive':hex(end),'sha256':digest,'fde':hex(f['fde']),'cie':hex(f['cie'])})
    return {'target_sha256':SHA256,'owners':owners,'field_table_va':hex(table),
            'fields':[{'key':k.decode(),'field_id':i,'dispatch_target':hex(targets[i])} for i,k in enumerate(KEYS)],
            'unknown_field':{'field_id':3,'dispatch_target':hex(targets[3])},
            'prepared_item_stride':64,'item_skip_tag':22,'decoded_key_success_tag':9,
            'value_helpers':{'chainId':{'target':'0x4b7f180','error_dword_tag':1},
                             'address':{'target':'0x4b78e80','success_byte_tag':9},
                             'nonce':{'target':'0x4b7afa0','success_byte_tag':9}},
            'duplicate_flags':{'chainId':'rsp+0xb8','address':'rsp+0xb0','nonce':'rsp+0xa8'},
            'successful_stores':{'outer_qword_tag':0,'chainId_bytes':[8,40],'nonce_bytes':[40,48],'address_bytes':[48,68]},
            'limits':'Prepared byte-key/present-value successful-helper control model only. Full input Content tags, '
                     'value conversion, missing/default helpers, protocol/type/caller labels, signing and wire layout unproved.',
            'captured_binaries_executed':False}


def build(data):
    require(hashlib.sha256(data).hexdigest()==SHA256,'Wrong node94 SHA-256')
    return observe(data)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,default=ROOT/BINARY)
    p.add_argument('--out',type=Path,default=ROOT/'work/three-field-map-94.json')
    args=p.parse_args();result=build(args.binary.read_bytes())
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf8',newline='\n')
    print(result['fields'])


if __name__=='__main__':main()
