#!/usr/bin/env python3
"""RE-001: selected node94 bootstrap window arithmetic, no async/network execution."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from evm_amount_scale import ROOT,BINARY,SHA256,Image
from fde_extents import eh_frame_records

PACKET=ROOT/'research/work-items/RE-001-bootstrap-window-94'
START,END=0x4389070,0x438a38c
LOWER,JOIN,EQUAL,AHEAD=0x43892a6,0x43892f0,0x4389c32,0x4389e32
BODY='78db20a2c3de64e35135b7730c8b45e77a3b551674136401c6f2de70f4d5f00f'
MASK=(1<<64)-1
PATTERNS={
 0x4389298:'488b8388000000488bb008010000',
 0x43892a6:'4839ce0f84830900000f877d0b0000',
 0x43892b5:'4889f048ffc048c7c7ffffffff480f44c7488983a0000000',
 0x43892cd:'488d50634883f89d720b4883c664480f42f74889f2',
 0x43892e2:'4839d1480f42d1488993a8000000',
 0x43892fe:'488983d0000000488993d8000000',
 0x4389321:'488983e8000000488993f0000000',
}

def require(ok,message):
    if not ok:raise ValueError(message)

def observe(data):
    img=Image(data);read=img.read
    for va,raw in PATTERNS.items():
        expected=bytes.fromhex(raw);require(read(va,len(expected))==expected,f'Window operand/route changed at {va:#x}')
    idiom=bytes.fromhex(PATTERNS[0x43892cd][:-6]);va,text=img.text();positions=[];at=0
    while True:
        at=text.find(idiom,at)
        if at<0:break
        positions.append(va+at);at+=1
    require(positions==[0x43892cd],'Exact window idiom census changed')
    _,fdes=eh_frame_records(data);fs=[f for f in fdes if f['start']==START]
    require(len(fs)==1 and fs[0]['end']==END,'Window owner FDE changed')
    require(hashlib.sha256(read(START,END-START)).hexdigest()==BODY,'Window owner body changed')
    return dict(target_sha256=SHA256,owner=dict(start=hex(START),end_exclusive=hex(END),sha256=BODY,
                fde=hex(fs[0]['fde']),cie=hex(fs[0]['cie'])),selected_region=dict(start=hex(LOWER),end_exclusive=hex(JOIN)),
                selected_branches={'equal':hex(EQUAL),'ahead':hex(AHEAD)},exact_idiom_sites=[hex(n) for n in positions],
                stores={'start_state':'+0xa0','end_state':'+0xa8','copies':[['+0xd0','+0xd8'],['+0xe8','+0xf0']]},
                limits='Conditional selected raw-word arithmetic only. Earlier lag gate, source field types, full async states, network/callback/response behavior and completion remain unproved.',
                captured_binaries_executed=False)

def build(data):
    require(hashlib.sha256(data).hexdigest()==SHA256,'Wrong node94 SHA-256')
    return observe(data)

def lower(code,current,target):
    require(all(type(v) is int and 0<=v<=MASK for v in (current,target)),'Expected raw u64 words')
    r=dict(rsi=current,rcx=target);stored={};pc=LOWER;carry=zero=False
    for _ in range(32):
        if pc in (EQUAL,AHEAD):return dict(route='equal_branch' if pc==EQUAL else 'ahead_branch',window=None)
        if pc==JOIN:return dict(route='window',window=(stored[0xa0],stored[0xa8]))
        require(LOWER<=pc<JOIN,'Window escaped selected region')
        b=code[pc-LOWER:]
        def op(raw):return b.startswith(bytes.fromhex(raw))
        if op('4839ce'):carry=r['rsi']<r['rcx'];zero=r['rsi']==r['rcx'];pc+=3
        elif op('0f84') or op('0f87'):
            take=zero if b[1]==0x84 else not carry and not zero
            pc+=6+(struct.unpack('<i',b[2:6])[0] if take else 0)
        elif op('4889f0'):r['rax']=r['rsi'];pc+=3
        elif op('48ffc0'):r['rax']=(r['rax']+1)&MASK;zero=r['rax']==0;pc+=3
        elif op('48c7c7ffffffff'):r['rdi']=MASK;pc+=7
        elif op('480f44c7'):
            if zero:r['rax']=r['rdi']
            pc+=4
        elif op('488983') or op('488993'):
            offset=struct.unpack('<I',b[3:7])[0];stored[offset]=r['rax' if b[2]==0x83 else 'rdx'];pc+=7
        elif op('488d50'):r['rdx']=(r['rax']+int.from_bytes(b[3:4],'little',signed=True))&MASK;pc+=4
        elif op('4883f8'):
            value=int.from_bytes(b[3:4],'little',signed=True)&MASK
            carry=r['rax']<value;zero=r['rax']==value;pc+=4
        elif b[0]==0x72:pc+=2+(int.from_bytes(b[1:2],'little',signed=True) if carry else 0)
        elif op('4883c6'):
            value=r['rsi']+int.from_bytes(b[3:4],'little',signed=True)
            carry=value>MASK;r['rsi']=value&MASK;zero=r['rsi']==0;pc+=4
        elif op('480f42f7'):
            if carry:r['rsi']=r['rdi']
            pc+=4
        elif op('4889f2'):r['rdx']=r['rsi'];pc+=3
        elif op('4839d1'):carry=r['rcx']<r['rdx'];zero=r['rcx']==r['rdx'];pc+=3
        elif op('480f42d1'):
            if carry:r['rdx']=r['rcx']
            pc+=4
        else:raise ValueError(f'Unmodelled window instruction at {pc:#x}')
    raise ValueError('Window step bound')

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',type=Path,default=ROOT/BINARY)
    p.add_argument('--out',type=Path,default=ROOT/'work/bootstrap-window.json');a=p.parse_args()
    result=build(a.binary.read_bytes());a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf8',newline='\n')
    print('Verified selected bootstrap inclusive-window formation')
if __name__=='__main__':main()
