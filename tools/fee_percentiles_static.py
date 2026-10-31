#!/usr/bin/env python3
"""RE-001: selected fee-history candidate binary64 percentile loop, static only."""
import argparse
import hashlib
import itertools
import json
from pathlib import Path
import struct
from evm_amount_scale import ROOT,BINARY,SHA256,Image
from fde_extents import eh_frame_records

PACKET=ROOT/'research/work-items/RE-001-fee-percentiles-94'
START,END=0x27b6540,0x27b840b
BODY_SHA='d0b178e9c8092ee1aff19326e514bc99ff88034d0816601b2def6727d86b6a98'
MAX=(1<<64)-1;SIGN=1<<63;HUNDRED=0x4059000000000000
BITS=[0xfff0000000000000,0xffe0000000000000,0xc059000000000000,0xbff0000000000000,
      0x8000000000000001,SIGN,0,1,0x3ff0000000000000,0x4058ffffffffffff,HUNDRED,HUNDRED+1,
      0x4059400000000000,0x4069000000000000,0x7ff0000000000000,0x7ff8000000000000,
      0x7ff8000000001234,0xfff8000000000000,0x7ff0000000000001,0xfff0000000000001]
ANCHORS={0x27b667e:'4885c0',0x27b6681:'7477',0x27b6683:'4883f805',0x27b6687:'7610',
         0x27b6689:'48c7839000000005000000',0x27b6694:'b805000000',
         0x27b67da:'488d8ba8000000',0x27b6801:'48ba0000000000000080',
         0x27b680b:'483911',0x27b680e:'7510',0x27b6820:'488b8bb0000000',
         0x27b6827:'488b93b8000000',0x27b682e:'4883c108',0x27b6832:'f20f10052641a5fd',
         0x27b6840:'4883fa02',0x27b6844:'72ca',0x27b6846:'f20f1049f8',
         0x27b684b:'660f2ec8',0x27b684f:'770d',0x27b6851:'48ffca',
         0x27b6854:'660f2e09',0x27b6858:'488d4908',0x27b685c:'76e2'}
RANGES=((0x27b667e,0x27b6699),(0x27b67da,0x27b67e1),(0x27b6801,0x27b685e),(0x27b8008,0x27b800f))


def require(ok,message):
    if not ok:raise ValueError(message)


def relation(a,b):
    """Integer-only UCOMISD relation, conditional on masked FP invalid exception."""
    for word in (a,b):require(type(word) is int and 0<=word<=MAX,'Expected binary64 bits')
    def nan(w):return w & 0x7ff0000000000000==0x7ff0000000000000 and w & 0xfffffffffffff!=0
    if nan(a) or nan(b):return None
    if (a & ~SIGN)==0 and (b & ~SIGN)==0:return 0
    key=lambda w:(~w & MAX) if w & SIGN else w ^ SIGN
    return (key(a)>key(b))-(key(a)<key(b))


def passes_loop(words):
    for word in words:relation(word,0)
    for prev,nxt in zip(words,words[1:]):
        if relation(prev,HUNDRED)==1:return False  # JA: CF=0 and ZF=0
        if relation(prev,nxt)==1:return False      # opposite of JBE: CF=1 or ZF=1
    return True


def reference_ordered_form(words):
    return all(relation(a,HUNDRED) in (-1,0) and relation(a,b) in (-1,0) for a,b in zip(words,words[1:]))


def population():
    rows=[]
    for length in range(4):
        count=passed=differences=0
        for words in itertools.product(BITS,repeat=length):
            value=passes_loop(words);count+=1;passed+=value
            differences+=value!=reference_ordered_form(words)
        rows.append({'length':length,'vectors':count,'loop_pass':passed,'differs_from_reference_ordered_form':differences})
    return rows


def observe(data):
    img=Image(data);read=img.read;relocs=img.relative_relocs()
    for va,raw in ANCHORS.items():
        require(read(va,len(bytes.fromhex(raw)))==bytes.fromhex(raw),f'Percentile operand/control changed at {va:#x}')
    require(struct.unpack('<Q',read(0x20a960,8))[0]==HUNDRED,'Percentile upper-bound bits changed')
    raw=read(0x27b8008,7)
    require(raw[:3]==b'\x48\x8d\x3d' and 0x27b8008+7+struct.unpack('<i',raw[3:])[0]==0x56c2ec0,'Fee owner source LEA changed')
    loc=0x56c2ec0;n,line,col=struct.unpack('<QII',read(loc+8,16))
    require(relocs.get(loc)==0x1f4185 and read(0x1f4185,n)==b'/home/ubuntu/hl/code_Mainnet/evm_rpc/src/reth_rpc_helpers_copied.rs' and (line,col)==(33,29),'Fee owner source context changed')
    _,fdes=eh_frame_records(data);fs=[f for f in fdes if f['start']==START]
    require(len(fs)==1 and fs[0]['end']==END,'Fee owner FDE changed')
    require(hashlib.sha256(read(START,END-START)).hexdigest()==BODY_SHA,'Fee owner body changed')
    f=fs[0]
    return {'target_sha256':SHA256,'owner':{'start':hex(START),'end_exclusive':hex(END),'sha256':BODY_SHA,'fde':hex(f['fde']),'cie':hex(f['cie'])},
            'excerpt_ranges':[[hex(lo),hex(hi)] for lo,hi in RANGES],
            'raw_count_context':{'zero_branch_target':'0x27b66fa','nonzero_cap':5},
            'percentile_fields':{'optional_tag':'RBX+0xa8','buffer':'RBX+0xb0','count':'RBX+0xb8','none_word':hex(SIGN)},
            'loop':'Reject only ordered(prev > 100.0) or ordered(prev > next); no comparison for length < 2.',
            'assumption':'Masked floating-point invalid exception; MXCSR and signaling-NaN reachability are not recovered.',
            'population_bits':[f'{b:016x}' for b in BITS],'population':population(),
            'limits':'Selected raw-bit loop and count context only. Loop pass is not complete request admission. '
                     'JSON NaN admission, valid API populations, block/range/provider semantics, FP exception state and Rust type unproved.',
            'captured_binaries_executed':False}


def build(data):
    require(hashlib.sha256(data).hexdigest()==SHA256,'Wrong node94 SHA-256')
    return observe(data)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,default=ROOT/BINARY)
    p.add_argument('--out',type=Path,default=ROOT/'work/fee-percentiles-94.json')
    args=p.parse_args();result=build(args.binary.read_bytes())
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf8',newline='\n')
    print(result['population'])


if __name__=='__main__':main()
