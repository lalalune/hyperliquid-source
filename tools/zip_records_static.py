#!/usr/bin/env python3
"""RE-001: two equal-length adapters and 40+24 -> 64 byte collectors."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from evm_amount_scale import ROOT,BINARY,SHA256,Image
from fde_extents import eh_frame_records

PACKET=ROOT/'research/work-items/RE-001-zipped-record-layout-94'
MAX=(1<<64)-1;SIGN=1<<63
OWNERS={0x28315f0:(0x28316ca,'ad8d0514c82e85389fa99d896062f0e4684eb155d5ed960df0d97fa7f02628ae'),
        0x471e100:(0x471e1e0,'6b34082b639b02348b775d807200ae315bb5ac74771d8661e69ea5b94b24f693'),
        0x2519c60:(0x2519eae,'31456d732efed674f5ee950429785051cc8d6c3e223f63dd0c27bacc6d545afb'),
        0x47f8e70:(0x47f9174,'441d139a49c9f4dc70d973eeda86e407f470ff0ce39f0993eb5f10658bf7b66a')}
ANCHORS={0x28315ff:'488b4610',0x2831607:'488b4a10',0x2831610:'4839c8',0x2831613:'756b',
         0x283161f:'488d3480',0x2831623:'488d34f2',0x283162e:'488d0440',0x2831632:'498d04c0',
         0x471e10f:'488b4610',0x471e117:'488b4a10',0x471e120:'4839c8',0x471e123:'756b',
         0x471e12f:'488d3480',0x471e133:'488d34f2',0x471e13e:'488d0440',0x471e142:'498d04c0',
         0x2519c8a:'48c1e803',0x2519c8e:'49becdcccccccccccccc',
         0x2519ca4:'48bdabaaaaaaaaaaaaaa',0x2519cbc:'48c1e606',0x2519cc3:'48c1e83a',
         0x2519cca:'498d4df8',0x2519cd1:'0f97c1',0x2519cd6:'740a',0x2519d0c:'41b808000000',
         0x2519de5:'4c8977f0',0x2519de9:'0f114fe0',0x2519ded:'0f1147d0',
         0x2519df1:'4c895ff8',0x2519dfd:'0f1107',0x2519e00:'4883c740',
         0x47f8ea0:'48b9cdcccccccccccccc',0x47f8ec0:'48b8abaaaaaaaaaaaaaa',
         0x47f8ed8:'48c1e606',0x47f8edf:'48c1e83a',0x47f8ee6:'498d49f8',0x47f8eed:'0f97c1',
         0x47f8fc6:'488979f0',0x47f8fca:'0f1149e0',0x47f8fce:'0f1141d0',
         0x47f8fd2:'488971f8',0x47f8fde:'0f1101',0x47f8fe4:'4883c140'}


def require(ok,message):
    if not ok:raise ValueError(message)


def allocation_allowed(count):
    require(type(count) is int and 0<=count<=MAX,'Expected u64 count')
    size=(count<<6)&MAX
    return not ((count>>58)!=0 or size>SIGN-8)


def recovered_count(byte_length,stride):
    require(type(byte_length) is int and 0<=byte_length<=MAX and stride in (40,24) and byte_length%stride==0,'Expected valid strided byte length')
    inverse=0xcccccccccccccccd if stride==40 else 0xaaaaaaaaaaaaaaab
    return ((byte_length>>3)*inverse)&MAX


def pack_records(left,right):
    require(len(left)==len(right),'Unequal input lengths')
    output=bytearray()
    for a,b in zip(left,right):
        require(isinstance(a,bytes) and len(a)==40 and isinstance(b,bytes) and len(b)==24,'Expected 40/24-byte records')
        row=bytearray(64)
        row[0:16]=a[0:16];row[16:32]=a[16:32];row[32:40]=a[32:40]
        row[40:48]=b[0:8];row[48:64]=b[8:24];output.extend(row)
    return bytes(output)


def observe(data):
    img=Image(data);read=img.read;relocs=img.relative_relocs()
    for va,raw in ANCHORS.items():
        require(read(va,len(bytes.fromhex(raw)))==bytes.fromhex(raw),f'Zip operand/control changed at {va:#x}')
    for va,target in [(0x283166e,0x2519c60),(0x471e17e,0x47f8e70)]:
        raw=read(va,5)
        require(raw[0]==0xe8 and va+5+struct.unpack('<i',raw[1:])[0]==target,'Zip collector call changed')
    for lea,loc in [(0x2831680,0x56c4f80),(0x471e190,0x572e878)]:
        raw=read(lea,7)
        require(raw[:3]==b'\x4c\x8d\x0d' and lea+7+struct.unpack('<i',raw[3:])[0]==loc,'Zip assertion Location LEA changed')
        n,line,col=struct.unpack('<QII',read(loc+8,16))
        require(relocs.get(loc)==0x1ef2de and read(0x1ef2de,n)==b'/home/ubuntu/hl/code_Mainnet/base/src/u.rs' and (line,col)==(101,9),'Zip source binding changed')
    require(relocs.get(0x576e2b8)==0x157b5e3,'Zip assertion callee changed')
    _,fdes=eh_frame_records(data);owners=[]
    for start,(end,digest) in OWNERS.items():
        fs=[f for f in fdes if f['start']==start]
        require(len(fs)==1 and fs[0]['end']==end,'Zip owner FDE changed')
        require(hashlib.sha256(read(start,end-start)).hexdigest()==digest,'Zip owner body changed')
        f=fs[0];owners.append({'start':hex(start),'end_exclusive':hex(end),'sha256':digest,'fde':hex(f['fde']),'cie':hex(f['cie'])})
    return {'target_sha256':SHA256,'owners':owners,'input_header_fields':{'capacity':0,'pointer':8,'length':16},
            'iterator_words':['left start','left current','left capacity','left end','right start','right current','right capacity','right end','zero','zero'],
            'input_strides':[40,24],'output_stride':64,'output_regions':{'left':[0,40],'right':[40,64]},
            'allocation':{'guard':'(n >> 58) != 0 or ((n << 6) mod 2**64) > 2**63-8',
                          'largest_admitted_count':(1<<57)-1,'empty_pointer_word':8},
            'limits':'Valid equal-length strided nonoverlapping owned byte buffers only. No portable Rust layout, '
                     'allocator/drop/unwind closure, arbitrary pointer validity, actual allocation or native equivalence.',
            'captured_binaries_executed':False}


def build(data):
    require(hashlib.sha256(data).hexdigest()==SHA256,'Wrong node94 SHA-256')
    return observe(data)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,default=ROOT/BINARY)
    p.add_argument('--out',type=Path,default=ROOT/'work/zipped-record-layout-94.json')
    args=p.parse_args();result=build(args.binary.read_bytes())
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf8',newline='\n')
    print(result['output_regions'],result['allocation'])


if __name__=='__main__':main()
