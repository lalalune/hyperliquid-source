#!/usr/bin/env python3
"""RE-001: conditional raw-limb fee calculation inside node94 response builder."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from evm_amount_scale import ROOT,BINARY,SHA256,Image
from fde_extents import eh_frame_records

PACKET=ROOT/'research/work-items/RE-001-response-fee-limbs-94'
START,END=0x1606580,0x1606c6d
LOWER,JOIN,PANIC=0x1606a58,0x1606adb,0x1606b78
BODY='ee0758f714f9b7e05ff3e8becaa1f3b55ec39fd5fa7f68f8602fccdcb21002a8'
MASK=(1<<64)-1

def require(ok,message):
    if not ok:raise ValueError(message)

def observe(data):
    img=Image(data);read=img.read;rel=img.relative_relocs()
    patterns={
      0x1606a0f:'41f60601',0x1606a36:'4d8b6610',0x1606a54:'498b6e18',
      0x1606a5f:'4c39e14889c24883da00',0x1606a6b:'4c29e14883d800',
      0x1606abe:'4839ce4889d74819c7480f42c2480f42ce',
      0x1606acf:'4901cc4811c50f829d000000',
      0x1606b2e:'48c7030100000048c74308000000004c89631048896b18',
      0x16069ed:'488d842410020000488d9424f0010000488d8c24e0010000',
      0x1606a3a:'498d75ff4883fe027210498d75fd4889ca4883fe0273034889c2',
      0x1606a8c:'498d75ff4883fe0272104983c5fd4889ca4983fd0273034889c2',
    }
    for va,raw in patterns.items():
        expected=bytes.fromhex(raw)
        require(read(va,len(expected))==expected,f'Fee operand/guard changed at {va:#x}')
    require(read(0x1606a23,2)==bytes.fromhex('7467'),'Fee presence branch changed')
    require(read(0x1606aa6,9)==bytes.fromhex('4c8b22488b6a08eb2c'),'Absent-context copy changed')
    raw=read(PANIC,7)
    require(raw[:3]==b'\x48\x8d\x3d' and PANIC+7+struct.unpack('<i',raw[3:])[0]==0x5677fa8,'Overflow source route changed')
    require(rel.get(0x576e118)==0x157b480,'Overflow helper relocation changed')
    raw=read(0x1606b7f,6)
    require(raw[:2]==b'\xff\x15' and 0x1606b85+struct.unpack('<i',raw[2:])[0]==0x576e118,'Overflow helper call changed')
    loc=0x5677fa8;n,line,col=struct.unpack('<QII',read(loc+8,16))
    require(loc in rel,'Fee source relocation missing')
    path=read(rel[loc],n).decode('utf8')
    require(path.endswith('/evm_rpc/src/reth_eth_tx_builder_copied.rs') and (line,col)==(51,21),'Fee source context changed')
    _,fdes=eh_frame_records(data);fs=[f for f in fdes if f['start']==START]
    require(len(fs)==1 and fs[0]['end']==END,'Fee owner FDE changed')
    require(hashlib.sha256(read(START,END-START)).hexdigest()==BODY,'Fee owner body changed')
    return dict(target_sha256=SHA256,owner=dict(start=hex(START),end_exclusive=hex(END),sha256=BODY,
                fde=hex(fs[0]['fde']),cie=hex(fs[0]['cie'])),selected_region=dict(start=hex(LOWER),end_exclusive=hex(JOIN)),
                source=dict(location=hex(loc),path=path,line=line,column=col),
                fields={'context_present':'byte context+0 bit0','base_low':'+0x10','base_high':'+0x18',
                        'max_pair_stack_by_tag':['0x1e0','0x1f0','0x1f0','0x210','0x210'],
                        'priority_pair_stack_by_tag':[None,None,'0x200','0x220','0x220']},
                limits='Conditional raw-register/word model, not valid typed transaction/context reachability, full response layout or Rust equivalence.',
                captured_binaries_executed=False)

def build(data):
    require(hashlib.sha256(data).hexdigest()==SHA256,'Wrong node94 SHA-256')
    return observe(data)

def lower(code,tag,base,maximum,priority):
    """Interpret only LOWER..JOIN arithmetic with synthetic registers and RAM."""
    require(type(tag) is int and 0<=tag<=4,'Expected declared tag 0..4')
    require(all(type(v) is int and 0<=v<1<<128 for v in (base,maximum,priority)),'Expected raw 128-bit pairs')
    r=dict(r12=base&MASK,rbp=base>>64,r13=tag,rdx=0x200000)
    memory={0x200000:maximum&MASK,0x200008:maximum>>64,
            0x100200:priority&MASK,0x100208:priority>>64,
            0x100220:priority&MASK,0x100228:priority>>64}
    pc=LOWER;carry=False
    def sub(dst,x,y):
        nonlocal carry
        carry=x<y;r[dst]=(x-y)&MASK
    for _ in range(60):
        if pc==JOIN:return (r['rbp']<<64)|r['r12']
        if pc==PANIC:return None
        require(LOWER<=pc<JOIN,'Arithmetic escaped selected region')
        b=code[pc-LOWER:]
        def op(raw):return b.startswith(bytes.fromhex(raw))
        if op('488b0a'):r['rcx']=memory[r['rdx']];pc+=3
        elif op('488b4208'):r['rax']=memory[r['rdx']+8];pc+=4
        elif op('4c39e1'):carry=r['rcx']<r['r12'];pc+=3
        elif op('4889c2'):r['rdx']=r['rax'];pc+=3
        elif op('4883da'):
            require(b[3] in (0,1),'Unsupported SBB immediate')
            sub('rdx',r['rdx'],int(carry)+b[3]);pc+=4
        elif op('4c29e1'):sub('rcx',r['rcx'],r['r12']);pc+=3
        elif op('4883d8'):
            require(b[3] in (0,1),'Unsupported SBB immediate')
            sub('rax',r['rax'],int(carry)+b[3]);pc+=4
        elif op('4183fd02'):carry=(r['r13']&0xffffffff)<2;pc+=4
        elif op('498d55fd'):r['rdx']=(r['r13']-3)&MASK;pc+=4
        elif op('4883fa02'):carry=r['rdx']<2;pc+=4
        elif op('488d942420020000'):r['rdx']=0x100220;pc+=8
        elif op('488d942400020000'):r['rdx']=0x100200;pc+=8
        elif op('488b32'):r['rsi']=memory[r['rdx']];pc+=3
        elif op('488b5208'):r['rdx']=memory[r['rdx']+8];pc+=4
        elif op('4839ce'):carry=r['rsi']<r['rcx'];pc+=3
        elif op('4889d7'):r['rdi']=r['rdx'];pc+=3
        elif op('4819c7'):sub('rdi',r['rdi'],r['rax']+int(carry));pc+=3
        elif op('480f42c2'):
            if carry:r['rax']=r['rdx']
            pc+=4
        elif op('480f42ce'):
            if carry:r['rcx']=r['rsi']
            pc+=4
        elif op('4901cc'):
            value=r['r12']+r['rcx'];carry=value>MASK;r['r12']=value&MASK;pc+=3
        elif op('4811c5'):
            value=r['rbp']+r['rax']+int(carry);carry=value>MASK;r['rbp']=value&MASK;pc+=3
        elif b[0] in (0x72,0x73,0xeb):
            take=b[0]==0xeb or (carry if b[0]==0x72 else not carry)
            pc+=2+(int.from_bytes(b[1:2],'little',signed=True) if take else 0)
        elif op('0f82'):
            pc+=6+(struct.unpack('<i',b[2:6])[0] if carry else 0)
        else:raise ValueError(f'Unmodelled arithmetic instruction at {pc:#x}')
    raise ValueError('Arithmetic step bound exceeded')

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',type=Path,default=ROOT/BINARY)
    p.add_argument('--out',type=Path,default=ROOT/'work/response-fee-limbs.json');a=p.parse_args()
    result=build(a.binary.read_bytes());a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf8',newline='\n')
    print('Verified selected transaction-response fee limb operands')
if __name__=='__main__':main()
