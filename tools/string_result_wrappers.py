#!/usr/bin/env python3
"""RE-001: five node94 string-result wrappers' selected output-collapse arms."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from evm_amount_scale import ROOT,BINARY,SHA256,Image
from fde_extents import eh_frame_records

PACKET=ROOT/'research/work-items/RE-001-string-result-wrappers-94'
CASES=[
 (0x28bf690,1337,'a611d00d1fcbd05d20b30ebd0203324b71c49ecdfabdf362680f9d0c45a4d868'),
 (0x28bfbd0,1339,'242c74d08b10ff5428b5af366924a8dbb1a4036e2631bdc9cc83f892ac57c3a5'),
 (0x28c0110,1337,'a37980dbe1132d9349442086205d4a64ec167dc0618185e92d24b4e0863b35bf'),
 (0x28c0650,1337,'d0e2f9bf6abd835a2ec672789809ceee497d37899ed461702351d04f739c0a7c'),
 (0x28c0b90,1337,'4792504c3dcc31bf4a78193d0a2b170849583570b86c95e93b2a12a1722da9d3'),
]
SUCCESS=bytes.fromhex('488b442458488943100f104424480f1103')
ERROR=bytes.fromhex('0f104424400f104c24500f294c24200f2944241048c7030000000048c743080100000048c7431000000000')

def require(ok,message):
    if not ok:raise ValueError(message)

def observe(data):
    img=Image(data);read=img.read;_,fdes=eh_frame_records(data);records=[]
    for start,size,digest in CASES:
        body=read(start,size)
        prefix=bytes.fromhex('837c2440087516')
        at=body.find(prefix)
        require(at>=0 and body.find(prefix,at+1)<0,'Output tag guard changed')
        compare=start+at;success=compare+7;error=compare+7+0x16
        require(read(success,len(SUCCESS))==SUCCESS,'Success payload copies changed')
        require(read(success+len(SUCCESS),1)==b'\xe9','Success join changed')
        join=success+len(SUCCESS)+5+struct.unpack('<i',read(success+len(SUCCESS)+1,4))[0]
        epilog=bytes.fromhex('4881c4880000005b415c415d415e415f5dc3')
        require(read(join,3)==bytes.fromhex('4889d8') and read(join+3,len(epilog))==epilog,'Output return changed')
        require(read(error,len(ERROR))==ERROR,'Error collapse stores changed')
        dispatch=error+len(ERROR)
        require(read(dispatch,8)==bytes.fromhex('488b442410488d0d'),'Error dispatch operand changed')
        table=dispatch+12+struct.unpack('<i',read(dispatch+8,4))[0]
        require(read(dispatch+12,9)==bytes.fromhex('486304814801c8ffe0'),'Error dispatch indexing changed')
        targets=[table+struct.unpack('<i',read(table+4*n,4))[0] for n in range(8)]
        # Decode and bind the three nontrivial cleanup arms, without assigning Rust variants.
        a,b,c=targets[3],targets[5],targets[7]
        require(all(targets[n]==join for n in (0,1,2,4,6)),'Trivial error join changed')
        require(read(a,15)==bytes.fromhex('488b7424184885f67475488d442420'),'Tag3 cleanup operands changed')
        require(read(c,10)==bytes.fromhex('488d442418be10000000'),'Tag7 cleanup operands changed')
        require(read(b,9)==bytes.fromhex('4531e4488d7c2420e8'),'Tag5 cleanup operands changed')
        helper=b+13+struct.unpack('<i',read(b+9,4))[0]
        require(helper==0x283a460,'Tag5 cleanup helper changed')
        fs=[f for f in fdes if f['start']==start]
        require(len(fs)==1 and fs[0]['end']==start+size,'Owner FDE changed')
        require(hashlib.sha256(body).hexdigest()==digest,'Owner body changed')
        records.append(dict(start=hex(start),end_exclusive=hex(start+size),sha256=digest,
                            fde=hex(fs[0]['fde']),cie=hex(fs[0]['cie']),tag_compare=hex(compare),
                            success=hex(success),error=hex(error),join=hex(join),dispatch=hex(dispatch),
                            table=hex(table),cleanup_targets=[hex(t) for t in targets]))
    return dict(target_sha256=SHA256,owners=records,selected_success_tag=8,error_header=[0,1,0],
                limits='Only selected normal-return output and cleanup dispatch. Decoder semantics, valid tag reachability, cleanup effects, timing/TLS behavior and unwind remain unproved.',
                captured_binaries_executed=False)

def build(data):
    require(hashlib.sha256(data).hexdigest()==SHA256,'Wrong node94 SHA-256')
    return observe(data)

def selected_output(data,index,tag,words):
    """Interpret the bound selected output arm's loads/stores, not the decoder."""
    require(type(tag) is int and 0<=tag<=8,'Expected declared tag 0..8')
    require(len(words)==3 and all(type(w) is int and 0<=w<1<<64 for w in words),'Expected three raw payload words')
    start,size,_=CASES[index];img=Image(data);body=img.read(start,size)
    at=body.index(bytes.fromhex('837c2440087516'))
    if tag==body[at+4]:
        # MOV RAX,[stack+58]; MOV [out+10],RAX; MOVUPS copies stack+48/+50.
        require(body[at+7:at+7+len(SUCCESS)]==SUCCESS,'Success payload copies changed')
        return tuple(words)
    raw=img.read(start+at+7+body[at+6]+20,23)
    require(raw[:3]==b'\x48\xc7\x03' and raw[7:11]==b'\x48\xc7\x43\x08' and raw[15:19]==b'\x48\xc7\x43\x10','Collapse instructions changed')
    return tuple(struct.unpack('<i',raw[o:o+4])[0]&((1<<64)-1) for o in (3,11,19))

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',type=Path,default=ROOT/BINARY)
    p.add_argument('--out',type=Path,default=ROOT/'work/string-result-wrappers.json');a=p.parse_args()
    result=build(a.binary.read_bytes());a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf8',newline='\n')
    print('Verified five selected output-collapse and cleanup dispatch sites')
if __name__=='__main__':main()
