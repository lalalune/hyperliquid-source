#!/usr/bin/env python3
"""RE-001: FodName age candidate fallback and conditional minimum reduction."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import struct
from evm_amount_scale import ROOT,BINARY,SHA256,Image
from fde_extents import eh_frame_records

PACKET=ROOT/'research/work-items/RE-001-fod-age-selection-94'
START,END=0x13d1b00,0x13d2134
BODY_SHA='a55a97006d67253f946e76591466f5237c15b0268c2d34941f25165a087bacb1'
ANCHORS={0x13d1b11:'833f01',0x13d1b14:'0f85b0000000',
         0x13d1b4d:'4d85e4',0x13d1b50:'0f94c0',0x13d1b5b:'4d85ff',0x13d1b5e:'0f94c1',
         0x13d1b61:'08c1',0x13d1b63:'0f848a000000',
         0x13d1b7a:'837c241801',0x13d1bdd:'837c241801',0x13d1d7a:'837c241801',
         0x13d1d8a:'f20f10542420',0x13d1ec7:'837c241801',
         0x13d1ede:'660f2ed0',0x13d1ee2:'660f28ca',0x13d1ee6:'f20fc2c802',
         0x13d1eeb:'660f54d1',0x13d1eef:'660f55c8',0x13d1ef3:'660f56d1',
         0x13d1ef7:'0f8bb3feffff',0x13d1efd:'e902010000',0x13d1faa:'0f28442460'}


def require(ok,message):
    if not ok:raise ValueError(message)


def selected_path(tag,root_word,count_word):
    require(type(tag) is int and 0<=tag<1<<32,'Expected u32 tag')
    require(all(type(w) is int and 0<=w<1<<64 for w in (root_word,count_word)),'Expected u64 helper words')
    if tag!=1:return 'own_path_age'
    return 'entry_age_fold' if root_word!=0 and count_word!=0 else 'own_path_age_fallback'


def age_fold(words):
    """Successful result bits, assuming masked FP invalid exceptions."""
    require(bool(words),'Expected nonempty successful age results')
    for w in words:require(type(w) is int and 0<=w<1<<64,'Expected binary64 bits')
    def number(w):return struct.unpack('<d',struct.pack('<Q',w))[0]
    acc=words[0]
    for current in words[1:]:
        a,b=number(acc),number(current)
        if math.isnan(a) or math.isnan(b):raise ValueError('unordered_age_panic_arm')
        if not a<=b:acc=current
    return acc


def observe(data):
    img=Image(data);read=img.read;relocs=img.relative_relocs()
    for va,raw in ANCHORS.items():
        require(read(va,len(bytes.fromhex(raw)))==bytes.fromhex(raw),f'Fod age operand/control changed at {va:#x}')
    for va,slot,target in [(0x13d1b37,0x576ead8,0x144bfd0),(0x13d1b74,0x576eae0,0x144fe90),
                           (0x13d1bd7,0x576eae0,0x144fe90),(0x13d1d74,0x576eae0,0x144fe90),
                           (0x13d200b,0x576e470,0x157a9f0)]:
        raw=read(va,6)
        require(raw[:2]==b'\xff\x15' and va+6+struct.unpack('<i',raw[2:])[0]==slot and relocs.get(slot)==target,'Fod helper binding changed')
    require(read(0x13d1d95,3)==b'\x48\x8b\x2d' and 0x13d1d95+7+struct.unpack('<i',read(0x13d1d95+3,4))[0]==0x576eae0,'Fold helper load changed')
    require(read(0x13d1ec5,2)==b'\xff\xd5','Fold indirect call changed')
    sources=[]
    for loc,line,col in [(0x5666e80,31,34),(0x5666e98,34,17),(0x5666eb0,43,46),(0x5666ec8,38,42)]:
        n,l,c=struct.unpack('<QII',read(loc+8,16))
        require(relocs.get(loc)==0x1df934 and read(0x1df934,n)==b'/home/ubuntu/hl/code_Mainnet/base/src/fodname.rs' and (l,c)==(line,col),'Fod source binding changed')
        sources.append({'location':hex(loc),'line':l,'column':c})
    loc=0x566ad30;n,line,col=struct.unpack('<QII',read(loc+8,16))
    require(relocs.get(loc)==0x1f05d3 and read(0x1f05d3,n)==b'/home/ubuntu/hl/code_Mainnet/base/src/duration.rs' and (line,col)==(58,33),'Unordered duration source changed')
    _,fdes=eh_frame_records(data);fs=[f for f in fdes if f['start']==START]
    require(len(fs)==1 and fs[0]['end']==END,'Fod owner FDE changed')
    require(hashlib.sha256(read(START,END-START)).hexdigest()==BODY_SHA,'Fod owner body changed')
    f=fs[0]
    return {'target_sha256':SHA256,'owner':{'start':hex(START),'end_exclusive':hex(END),'sha256':BODY_SHA,'fde':hex(f['fde']),'cie':hex(f['cie'])},
            'sources':sources,'fallback':'tag != 1, or tag == 1 and (enumeration root word == 0 or count word == 0)',
            'age_helper_slot':'0x576eae0','age_helper_target':'0x144fe90','age_error_dword_tag':1,
            'fold':'Seed from first successful result; ordered <= preserves accumulator bits, otherwise current bits; unordered comparison takes panic arm.',
            'unordered_location':{'path':'base/src/duration.rs','line':line,'column':col},
            'limits':'Conditional successful callback-result model only. Enumeration/tree traversal, filesystem state, '
                     'age units/clock behavior, helper errors/unwind, FP exception masks and original Rust ABI unproved.',
            'captured_binaries_executed':False}


def build(data):
    require(hashlib.sha256(data).hexdigest()==SHA256,'Wrong node94 SHA-256')
    return observe(data)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,default=ROOT/BINARY)
    p.add_argument('--out',type=Path,default=ROOT/'work/fod-age-94.json')
    args=p.parse_args();result=build(args.binary.read_bytes())
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf8',newline='\n')
    print(result['fallback'])


if __name__=='__main__':main()
