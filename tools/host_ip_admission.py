#!/usr/bin/env python3
"""RE-001: selected host-IP query admission sites, node94; static only."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from evm_amount_scale import ROOT,BINARY,SHA256,Image
from fde_extents import eh_frame_records

PACKET=ROOT/'research/work-items/RE-001-host-ip-admission-94'
START,END=0x13ca370,0x13cba3e
BODY='9bbbf50d25f9842e868621a198bebfe62137fa666eff6154b5b387f1b19423ef'
MIN=1<<63
SITES=[
 ('ifconfig.me',0x216e38,0x13ca555,0x13ca564,0x13ca589,0x13ca5d2,0x13ca77b,0x13ca799,0x13ca898),
 ('api.ipify.org',0x216e43,0x13ca9df,0x13ca9ee,0x13caa04,0x13caa4d,0x13caab9,0x13caad7,0x13cabd8),
 ('icanhazip.com',0x216e50,0x13cad1f,0x13cad2e,0x13cad44,0x13cad8d,0x13cadf9,0x13cae17,0x13caf10),
]

def require(ok,message):
    if not ok:raise ValueError(message)

def admission(length,al,remaining):
    """Raw call-site predicate; not a parser implementation or reachability claim."""
    require(type(length) is int and 0<=length<1<<64,'Invalid raw length')
    require(type(al) is int and 0<=al<256,'Invalid raw AL')
    require(type(remaining) is int and 0<=remaining<1<<64,'Invalid raw remainder')
    if length>15:return 'reject_before_parser'
    return 'admit_to_collection' if (al&1) and remaining==0 else 'reject_after_parser'

def override_route(word):
    require(type(word) is int and 0<=word<1<<64,'Invalid raw result word')
    return 'probe_path' if word==MIN else 'override_path'

def observe(data):
    img=Image(data);read=img.read;rel=img.relative_relocs()
    def raw(va,expected,label):
        require(read(va,len(expected))==expected,label+' changed')
    def rip(va,prefix,target):
        b=read(va,len(prefix)+4)
        require(b.startswith(prefix) and va+len(b)+struct.unpack('<i',b[-4:])[0]==target,'RIP operand changed')
    def near(va,opcode,target):
        b=read(va,len(opcode)+4)
        require(b.startswith(opcode) and va+len(b)+struct.unpack('<i',b[-4:])[0]==target,'Branch/call target changed')
    raw(0x216e1a,b"hostname -I | awk '{print $1}'",'Private command literal')
    raw(0x1e3739,b'\x08curl -s \xc0\x00','Probe format literal')
    raw(0x1e71f1,b'\xc0\x1b/override_public_ip_address\x00','Override format literal')
    rip(0x13ca3a3,b'\x0f\x10\x05',0x216e1a)
    rip(0x13ca46e,b'\x48\x8d\x35',0x1e71f1)
    rip(0x13ca3d6,b'\xff\x15',0x576e950)
    rip(0x13ca4b6,b'\xff\x15',0x576e958)
    require(rel.get(0x576e950)==0x13e5af0 and rel.get(0x576e958)==0x144c330,'Helper relocation changed')
    raw(0x13ca4bc,bytes.fromhex('48bd0000000000000080'),'Override sentinel')
    raw(0x13ca4c6,bytes.fromhex('4839ac2490010000'),'Override result operand')
    near(0x13ca4ce,b'\x0f\x85',0x13ca625)
    near(0x13ca759,b'\xe9',0x13cb50c)
    records=[]
    for name,text,lea,size,fmt,execute,limit,parse,reject in SITES:
        raw(text,name.encode(),'Endpoint literal')
        rip(lea,b'\x48\x8d\x05',text)
        raw(size,bytes.fromhex('48c78424f0000000')+struct.pack('<I',len(name)),'Endpoint length')
        rip(fmt,b'\x48\x8d\x35',0x1e3739)
        rip(execute,b'\xff\x15',0x576e950)
        raw(limit,bytes.fromhex('4883fd0f'),'Unsigned probe length limit')
        near(limit+4,b'\x0f\x87',reject)
        raw(parse-10,bytes.fromhex('48896c2428488d7c2420'),'Parser slice argument')
        near(parse,b'\xe8',0x1573af0)
        raw(parse+5,bytes.fromhex('48837c2428000f94c184c1'),'Parser remainder and low-bit test')
        near(parse+16,b'\x0f\x84',reject)
        records.append(dict(endpoint=name,literal=hex(text),literal_lea=hex(lea),format_lea=hex(fmt),
                            execute=hex(execute),length_guard=hex(limit),parse_call=hex(parse),reject=hex(reject)))
    _,fdes=eh_frame_records(data);fs=[f for f in fdes if f['start']==START]
    require(len(fs)==1 and fs[0]['end']==END,'Owner FDE changed')
    require(hashlib.sha256(read(START,END-START)).hexdigest()==BODY,'Owner body changed')
    loc=0x5666bb0;n,line,col=struct.unpack('<QII',read(loc+8,16))
    require(loc in rel,'Source relocation missing')
    path=read(rel[loc],n).decode('utf8')
    require(path=='/home/ubuntu/hl/code_Mainnet/base/src/u.rs' and (line,col)==(426,21),'Source context changed')
    return dict(target_sha256=SHA256,owner=dict(start=hex(START),end_exclusive=hex(END),sha256=BODY,
                 fde=hex(fs[0]['fde']),cie=hex(fs[0]['cie'])),probes=records,
                source=dict(location=hex(loc),path=path,line=line,column=col),
                override=dict(read_call='0x13ca4b6',helper='0x144c330',sentinel=hex(MIN),
                              non_sentinel_target='0x13ca625',probe_bypass_jump='0x13ca759'),
                predicate='length <= 15 AND (parser_AL & 1) != 0 AND remaining_word == 0',
                limits='Selected caller protocol only. Parser grammar, helper effects, collection insertion, file/command behavior, timeout, final output and unwind are not closed.',
                captured_binaries_executed=False)

def build(data):
    require(hashlib.sha256(data).hexdigest()==SHA256,'Wrong node94 SHA-256')
    return observe(data)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',type=Path,default=ROOT/BINARY)
    p.add_argument('--out',type=Path,default=ROOT/'work/host-ip-admission.json');a=p.parse_args()
    result=build(a.binary.read_bytes());a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf8',newline='\n')
    print('Verified three probe call sites and override branch')
if __name__=='__main__':main()
