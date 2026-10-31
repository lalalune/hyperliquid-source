#!/usr/bin/env python3
"""RE-001: ASCII token filtering after the restart caller's replacement helper."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from evm_amount_scale import ROOT,BINARY,SHA256,Image
from fde_extents import eh_frame_records

PACKET=ROOT/'research/work-items/RE-001-restart-token-filter-94'
CASES=[
 (0x1438e90,0x143900c,'6b5b7dd63a03b7bcfdc12faec6d4c377bdfb0a1a4d51659c42a28def94efa916'),
 (0x13df3c0,0x13df5ed,'9c1ae2280d63ac59c11baf67ee0fae4b877d23482d3ccaf9364dc55f073959a6'),
 (0x13df5f0,0x13df766,'db26f8cfe5f6fc8db6e0beb17773db5f6f317e2d7124919b12be6a211e6b442a'),
 (0x14b1090,0x14b14b3,'845db243e509f9445bf3208536e55de103655a23377313256c47a70b6a9743d5'),
]

def require(ok,message):
    if not ok:raise ValueError(message)

def observe(data):
    img=Image(data);read=img.read
    def exact(va,raw,label):
        raw=bytes.fromhex(raw);require(read(va,len(raw))==raw,label+' changed')
    def direct(va,target):
        raw=read(va,5)
        require(raw[0]==0xe8 and va+5+struct.unpack('<i',raw[1:])[0]==target,'Direct call changed')
    def rip(va,prefix,target):
        raw=read(va,len(prefix)+4)
        require(raw.startswith(prefix) and va+len(raw)+struct.unpack('<i',raw[-4:])[0]==target,'Literal operand changed')
    for va,text in ((0x219518,b'--restart-style LoopParent'),(0x21956e,b'LoopParent'),
                    (0x219578,b'LoopChild'),(0x219581,b' --backup-logs')):
        require(read(va,len(text))==text,'Restart literal changed')
    rip(0x1438ea5,b'\x48\x8d\x3d',0x219518)
    rip(0x1438ecc,b'\x48\x8d\x0d',0x21956e)
    rip(0x1438ed3,b'\x4c\x8d\x0d',0x219578)
    exact(0x1438eac,'be1a000000','Contains length')
    exact(0x1438ebe,'0f84f1000000','Contains failure branch')
    exact(0x1438ec4,'48c7042409000000','Replacement target length')
    exact(0x1438edf,'41b80a000000','Replacement source length')
    direct(0x1438eb7,0x1440df0);direct(0x1438eeb,0x1441520)
    direct(0x1438f3a,0x13df5f0);direct(0x1438f5e,0x14b1090)
    for va in (0x13df607,0x13df67c,0x13df6b4):direct(va,0x13df3c0)
    rip(0x1438f49,b'\x48\x8d\x0d',0x219581)
    exact(0x1438f55,'41b801000000','Separator length')
    exact(0x13df3ef,'49bb003e000001000000','ASCII whitespace mask')
    exact(0x13df519,'4183fc20770d4489e1490fa3cb0f82e4feffff','ASCII mask branch')
    exact(0x13df5b5,'4883fa0d7527488b08','Filter length/first load')
    rip(0x13df5be,b'\x48\x33\x0d',0x219582)
    exact(0x13df5c5,'488b5005','Filter second load')
    rip(0x13df5c9,b'\x48\x33\x15',0x219587)
    exact(0x13df5d0,'4809ca0f8420feffff','Exact-token skip branch')
    table=0x21b94c;target=table+struct.unpack('<i',read(table+4,4))[0]
    require(target==0x14b135f,'One-byte join dispatch changed')
    exact(0x14b1393,'488b4424100fb6008807','One-byte separator load/store')
    owners=[];_,fdes=eh_frame_records(data)
    for start,end,digest in CASES:
        fs=[f for f in fdes if f['start']==start]
        require(len(fs)==1 and fs[0]['end']==end,'Restart owner FDE changed')
        require(hashlib.sha256(read(start,end-start)).hexdigest()==digest,'Restart owner body changed')
        owners.append(dict(start=hex(start),end_exclusive=hex(end),sha256=digest,fde=hex(fs[0]['fde']),cie=hex(fs[0]['cie'])))
    rel=img.relative_relocs();loc=0x566a138;n,line,col=struct.unpack('<QII',read(loc+8,16))
    require(loc in rel,'Restart source relocation missing')
    path=read(rel[loc],n).decode('utf8')
    require(path.endswith('/base/src/production.rs') and (line,col)==(101,9),'Restart source context changed')
    return dict(target_sha256=SHA256,owners=owners,source=dict(location=hex(loc),path=path,line=line,column=col),
                ascii_separator_values=[n for n in range(128) if n<=32 and (0x100003e00>>n)&1],
                removed_token='--backup-logs',join_separator_hex='20',join_separator_length=1,
                limits='ASCII post-replacement normal-output protocol only; upstream contains/replacement algorithms, Unicode, allocation/drop/unwind and process execution unclosed.',
                captured_binaries_executed=False)

def build(data):
    require(hashlib.sha256(data).hexdigest()==SHA256,'Wrong node94 SHA-256')
    return observe(data)

def skip_token(img,token):
    require(type(token) is bytes,'Expected raw token bytes')
    if len(token)!=img.read(0x13df5b8,1)[0]:return False
    return ((int.from_bytes(token[:8],'little') ^ int.from_bytes(img.read(0x219582,8),'little')) |
            (int.from_bytes(token[5:13],'little') ^ int.from_bytes(img.read(0x219587,8),'little')))==0

def normalize_ascii(img,buffer):
    """Model a returned replacement buffer, not original command replacement."""
    require(type(buffer) is bytes and all(b<128 for b in buffer),'Expected ASCII post-replacement bytes')
    mask=int.from_bytes(img.read(0x13df3f1,8),'little');parts=[];start=0
    for pos in range(len(buffer)+1):
        if pos==len(buffer) or (buffer[pos]<=32 and ((mask>>buffer[pos])&1)):
            token=buffer[start:pos]
            if token and not skip_token(img,token):parts.append(token)
            start=pos+1
    # The caller supplies only one byte from a longer rodata string.
    size=img.read(0x1438f57,1)[0]
    return img.read(0x219581,size).join(parts)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',type=Path,default=ROOT/BINARY)
    p.add_argument('--out',type=Path,default=ROOT/'work/restart-token-filter.json');a=p.parse_args()
    result=build(a.binary.read_bytes());a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf8',newline='\n')
    print('Verified restart ASCII token filter and one-byte join binding')
if __name__=='__main__':main()
