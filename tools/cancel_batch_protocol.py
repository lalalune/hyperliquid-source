#!/usr/bin/env python3
"""RE-001: two cancellation-labelled batch cores' selected raw protocols."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from evm_amount_scale import ROOT,BINARY,SHA256,Image
from fde_extents import eh_frame_records

PACKET=ROOT/'research/work-items/RE-001-cancel-batch-protocol-94'
MASK=(1<<64)-1
CASES=[
 dict(name='oid',start=0x2721120,end=0x2721254,sha='eda3da37222bc09a5b6bcff59f59bd9205ad95f127b918bd73c8c23ad9e040b5',
      bound=0x2721141,prepare=0x2721190,helper=0x2518ad0,add=0x27211a5,first=0x27211af,second=0x27211b8,
      tag=0x27211b3,pred1=0x27211c6,pred2=0x27211d3,snapshot=0x27211dd,worker=0x2721234,reject=0x272115f,normal=0x2721239),
 dict(name='cloid',start=0x2725010,end=0x2725149,sha='2d2a407b02711a7477b2f564316f1d31edabff2566a057f2e47ca4ea30a34653',
      bound=0x272502e,prepare=0x2725085,helper=0x251a940,add=0x272509a,first=0x27250a4,second=0x27250ad,
      tag=0x27250a8,pred1=0x27250bb,pred2=0x27250c8,snapshot=0x27250d2,worker=0x2725129,reject=0x2725050,normal=0x272512e),
]

def require(ok,message):
    if not ok:raise ValueError(message)

def model(img,index,length,prepared,old,first_status,second_status):
    require(index in (0,1),'Expected declared core')
    require(all(type(v) is int and 0<=v<=MASK for v in (length,prepared,old)),'Expected raw u64 words')
    require(all(type(v) is int and 0<=v<256 for v in (first_status,second_status)),'Expected raw helper status bytes')
    case=CASES[index];limit=int.from_bytes(img.read(case['bound']+3,4),'little')
    if length>=limit:return dict(status=int.from_bytes(img.read(case['reject']+2,2),'little'),counter=old,
                                 predicate_calls=0,snapshot_bytes=0,worker=False)
    total=old+prepared;carry=total>MASK;rax=total&MASK;rcx=MASK
    for va in (case['first'],case['second']):
        raw=img.read(va,4);require(raw[:2]==b'\x48\x0f' and raw[2] in (0x42,0x43) and raw[3]==0xc8,'Unsupported counter CMOV')
        if (carry if raw[2]==0x42 else not carry):rcx=rax
    return dict(status=int.from_bytes(img.read(case['normal']+2,2),'little'),counter=rcx,
                predicate_calls=1 if first_status else 2,snapshot_bytes=12 if first_status or second_status else 0,worker=True)

def observe(data):
    img=Image(data);read=img.read;rel=img.relative_relocs();_,fdes=eh_frame_records(data);owners=[]
    def exact(va,raw,label):
        expected=bytes.fromhex(raw);require(read(va,len(expected))==expected,label+' changed')
    def direct(va,target):
        raw=read(va,5);require(raw[0]==0xe8 and va+5+struct.unpack('<i',raw[1:])[0]==target,'Cancel direct helper changed')
    for index,c in enumerate(CASES):
        exact(c['bound'],'4981fc11270000','Input length limit')
        branch=c['bound']+7;raw=read(branch,2)
        require(raw[0]==0x72 and branch+2+raw[1]==(0x2721168 if index==0 else 0x2725059),'Input bound branch changed')
        exact(c['reject']-4,'4c896318','Rejected input count payload')
        exact(c['worker']-55,'49c1e5054901cd','Prepared result stride')
        direct(c['prepare'],c['helper']);direct(c['worker'],0x251a180)
        exact(c['prepare']+9,'4c8b6c2420','Prepared count load')
        exact(c['add']-7,'498b8778080000','Counter source')
        exact(c['add'],'4c01e848c7c1ffffffff480f43c8','Prepared counter addition')
        exact(c['first'],'480f43c8','First counter CMOV')
        exact(c['tag'],'c644240e'+('02' if index==0 else '03'),'Worker kind byte')
        exact(c['second'],'480f43c849898f78080000','Second CMOV/counter store')
        exact(c['reject'],'66b84301','Oversize status')
        exact(c['normal'],'66b88601668903','Normal status store')
        for va,slot,target in ((c['pred1'],0x5773228,0x37e4fb0),(c['pred2'],0x5773230,0x37e4e50)):
            raw=read(va,6)
            require(raw[:2]==b'\xff\x15' and va+6+struct.unpack('<i',raw[2:])[0]==slot and rel.get(slot)==target,'Predicate helper changed')
        exact(c['pred1']+6,'84c0750d','First predicate short circuit')
        exact(c['pred2']+6,'84c07416','Second predicate snapshot gate')
        exact(c['snapshot'],'418b4768418987a03a0000498b4760498987983a0000','Twelve-byte snapshot operands')
        fs=[f for f in fdes if f['start']==c['start']]
        require(len(fs)==1 and fs[0]['end']==c['end'],'Cancel owner FDE changed')
        require(hashlib.sha256(read(c['start'],c['end']-c['start'])).hexdigest()==c['sha'],'Cancel owner body changed')
        owners.append(dict(name=c['name'],start=hex(c['start']),end_exclusive=hex(c['end']),sha256=c['sha'],
                           fde=hex(fs[0]['fde']),cie=hex(fs[0]['cie']),prepare=hex(c['prepare']),worker=hex(c['worker']),
                           counter_add=hex(c['add']),snapshot=hex(c['snapshot'])))
    return dict(target_sha256=SHA256,owners=owners,input_limit_exclusive=10001,
                counter='state+0x878 saturating-add prepared result count, not input length',
                snapshot={'source':['+0x60 qword','+0x68 dword'],'destination':['+0x3a98 qword','+0x3aa0 dword'],'bytes':12},
                helper_targets=['0x2518ad0','0x251a940','0x251a180','0x37e4fb0','0x37e4e50'],
                limits='Selected raw batch/normal-helper protocol only; preparation, per-item cancellation, helper predicates, original types and valid count domains unclosed.',
                captured_binaries_executed=False)

def build(data):
    require(hashlib.sha256(data).hexdigest()==SHA256,'Wrong node94 SHA-256')
    return observe(data)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',type=Path,default=ROOT/BINARY)
    p.add_argument('--out',type=Path,default=ROOT/'work/cancel-batch-protocol.json');a=p.parse_args()
    result=build(a.binary.read_bytes());a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf8',newline='\n')
    print('Verified paired cancellation-labelled batch protocols')
if __name__=='__main__':main()
