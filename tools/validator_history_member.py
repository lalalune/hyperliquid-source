#!/usr/bin/env python3
"""RE-001: selected history-result 20-byte membership search, node94."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from evm_amount_scale import ROOT,BINARY,SHA256,Image
from fde_extents import eh_frame_records

PACKET=ROOT/'research/work-items/RE-001-validator-history-member-94'
START,END=0x44b3040,0x44b31fd
BODY='be7618990d0f260ba9b511342bccb48cd14779db2ec302b86589b2edb6b4c31a'

def require(ok,message):
    if not ok:raise ValueError(message)

def observe(data):
    img=Image(data);read=img.read;rel=img.relative_relocs()
    patterns={0x44b305f:'483bb7880900007676',0x44b3054:'4c8db730090000',
      0x44b30eb:'e84068e1ff4885c00f84d4000000',
      0x44b3114:'8b83fc0a0000894424500f1083ec0a00000f29442440',
      0x44b312a:'498b064885c00f84af0000004d8b7608488d5c2440',
      0x44b3146:'488d7060',0x44b314f:'0fb7803e010000',0x44b3162:'488d2c80',
      0x44b3175:'4c8d7e14ba140000004889df41ffd4',
      0x44b3184:'48984885c00f98c10f9fc028c849ffc54883c5ec4c89fe3c0174d1',
      0x44b31a2:'85c0750feb41',0x44b31b5:'4983ee01722a',
      0x44b31c0:'4a8b84e840010000e979ffffff',0x44b31e5:'31c0eb02b001',
    }
    for va,raw in patterns.items():
        expected=bytes.fromhex(raw);require(read(va,len(expected))==expected,f'Membership operand/route changed at {va:#x}')
    require(rel.get(0x576e978)==0x143d010,'Membership warning helper changed')
    raw=read(0x44b30d4,6)
    require(raw[:2]==b'\xff\x15' and 0x44b30da+struct.unpack('<i',raw[2:])[0]==0x576e978,'Membership warning call changed')
    # Bind the external comparator by its actual GLOB_DAT symbol, not a guessed helper name.
    _,off,size=img.sec['.rela.dyn'];_,symbols,_=img.sec['.dynsym'];_,strings,_=img.sec['.dynstr'];matches=[]
    for where,info,_ in struct.iter_unpack('<QQq',data[off:off+size]):
        if where!=0x576e488:continue
        name=struct.unpack_from('<I',data,symbols+(info>>32)*24)[0]+strings
        matches.append((info&0xffffffff,data[name:data.index(b'\0',name)]))
    require(matches==[(6,b'memcmp')],'Membership comparator relocation changed')
    raw=read(0x44b313f,7)
    require(raw[:3]==b'\x4c\x8b\x25' and 0x44b3146+struct.unpack('<i',raw[3:])[0]==0x576e488,'Membership comparator slot changed')
    loc=0x5738668;n,line,col=struct.unpack('<QII',read(loc+8,16));require(loc in rel,'Membership source relocation missing')
    path=read(rel[loc],n).decode('utf8')
    require(path.endswith('/node/src/consensus/validator_set.rs') and (line,col)==(78,13),'Membership source context changed')
    _,fdes=eh_frame_records(data);fs=[f for f in fdes if f['start']==START]
    require(len(fs)==1 and fs[0]['end']==END,'Membership owner FDE changed')
    require(hashlib.sha256(read(START,END-START)).hexdigest()==BODY,'Membership owner body changed')
    return dict(target_sha256=SHA256,owner=dict(start=hex(START),end_exclusive=hex(END),sha256=BODY,
                fde=hex(fs[0]['fde']),cie=hex(fs[0]['cie'])),source=dict(location=hex(loc),path=path,line=line,column=col),
                comparator={'slot':'0x576e488','relocation_kind':6,'symbol':'memcmp','bytes':20},
                node={'key_base':'0x60','key_stride':20,'count_u16':'0x13e','children':'0x140'},
                key_source=['state+0xaec 16 bytes','state+0xafc 4 bytes'],
                limits='Normal diagnostic/lookup-return and supplied valid-tree membership only; full history selection, Rust key identity, warning policy and caller validity unclosed.',
                captured_binaries_executed=False)

def build(data):
    require(hashlib.sha256(data).hexdigest()==SHA256,'Wrong node94 SHA-256')
    return observe(data)

def make_tree(node):
    """Independent synthetic valid 20-byte-key fixture, no native memory."""
    memory={};next_address=0x1000
    def put(address,raw):memory.update((address+i,b) for i,b in enumerate(raw))
    def emit(value):
        nonlocal next_address
        if value is None:return 0,0
        keys,children=value
        require(len(keys)<=11 and all(type(k) is bytes and len(k)==20 for k in keys),'Synthetic key domain')
        require(all(a<b for a,b in zip(keys,keys[1:])),'Synthetic keys must be sorted')
        require(not children or len(children)==len(keys)+1,'Synthetic child count')
        address=next_address;next_address+=0x200;put(address,b'\0'*0x200)
        put(address+0x13e,struct.pack('<H',len(keys)))
        for index,key in enumerate(keys):put(address+0x60+20*index,key)
        heights=[]
        for index,child in enumerate(children):
            root,height=emit(child);require(root!=0,'Synthetic interior child missing')
            put(address+0x140+8*index,struct.pack('<Q',root));heights.append(height)
        require(not heights or len(set(heights))==1,'Synthetic tree must have one height')
        return address,0 if not heights else heights[0]+1
    root,height=emit(node);return memory,root,height

def member(img,memory,root,height,key):
    require(type(key) is bytes and len(key)==20 and type(height) is int and 0<=height<=8,'Declared search domain')
    key_base=img.read(0x44b3149,1)[0];stride=img.read(0x44b3178,1)[0]
    width=int.from_bytes(img.read(0x44b317a,4),'little')
    count_offset=int.from_bytes(img.read(0x44b3152,4),'little');child_offset=int.from_bytes(img.read(0x44b31c4,4),'little')
    require(0<width<=20,'Unsupported key width')
    def read(address,size):
        require(all(address+i in memory for i in range(size)),'Synthetic read escaped RAM')
        return bytes(memory[address+i] for i in range(size))
    if root==0:return False
    for _ in range(height+1):
        count=int.from_bytes(read(root+count_offset,2),'little');require(count<=11,'Synthetic count invalid')
        index=0
        while index<count:
            other=read(root+key_base+index*stride,width)
            comparison=(key[:width]>other)-(key[:width]<other)
            if comparison==0:return True
            if comparison<0:break
            index+=1
        if height==0:return False
        root=int.from_bytes(read(root+child_offset+index*8,8),'little');height-=1
    raise ValueError('Synthetic search step bound')

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',type=Path,default=ROOT/BINARY)
    p.add_argument('--out',type=Path,default=ROOT/'work/validator-history-member.json');a=p.parse_args()
    result=build(a.binary.read_bytes());a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf8',newline='\n')
    print('Verified selected history-result 20-byte membership search')
if __name__=='__main__':main()
