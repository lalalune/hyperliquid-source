#!/usr/bin/env python3
"""RE-001: selected TLS state brackets in four node94 runtime wrappers."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from evm_amount_scale import ROOT,BINARY,SHA256,Image
from fde_extents import eh_frame_records

PACKET=ROOT/'research/work-items/RE-001-runtime-state-brackets-94'
CASES=[
 (0x28302f0,0x283069c,'87bb0af77b9030d0f568e8e94cf84396f3fe88955060f5b73606fb4fbf482001',
  0x28304f7,0x28304fe,0x283050f,0x2830516,0x283051a,0x2830520,0x2830536,0x2830544,0x2830548,0x283054a),
 (0x28306a0,0x2830a4c,'b2c45141cb583ba6eae9155521d0289f26379f41b50644b2728bb2c4a4361e0f',
  0x28308a7,0x28308ae,0x28308bf,0x28308c6,0x28308ca,0x28308d0,0x28308e6,0x28308f4,0x28308f8,0x28308fa),
 (0x2830a50,0x2830e18,'a1a5c0a1c90e027a67c6f79a4bd2416994172ace439a674bcb0d2a17c1343e65',
  0x2830c78,0x2830c7d,0x2830c8c,0x2830c92,0x2830c96,0x2830c9c,0x2830cb6,0x2830cc4,0x2830cc8,0x2830cca),
 (0x2830e20,0x28313ec,'d6c96e8032180024f6b2f839ed831f4ac85ec7563720ea8b576befaf9235864c',
  0x2831181,0x2831186,0x2831195,0x283119a,0x283119e,0x28311a4,0x2831258,0x283126d,0x2831271,0x2831273),
]
FORMS=[('64410fb7442444','6441c644244400','64410fb66c2446','4080fd02','6441c644244602','40886846'),
       ('64410fb7442444','6441c644244400','64410fb66c2446','4080fd02','6441c644244602','40886846'),
       ('640fb74544','64c6454400','64440fb66d46','4180fd02','64c6454602','44886846'),
       ('640fb74144','64c6414400','640fb66946','4080fd02','64c6414602','40886846')]


def require(ok,message):
    if not ok:raise ValueError(message)


def bracket(prior,after,context_present):
    require(type(prior) is int and 0<=prior<256 and type(after) is int and 0<=after<256,'Expected raw state bytes')
    require(type(context_present) is bool,'Expected context-presence class')
    if prior==2:return {'path':'pre_body_state_failure','body_state':None,'restored':None}
    if not context_present:return {'path':'post_body_context_missing','body_state':2,'restored':None}
    if after!=2:return {'path':'post_body_state_failure','body_state':2,'restored':None}
    return {'path':'restore_prior_state','body_state':2,'restored':prior}


def saved_flags(word):
    require(type(word) is int and 0<=word<65536,'Expected raw flag word')
    return word,word & 0xff00


def observe(data):
    img=Image(data);read=img.read;relocs=img.relative_relocs();_,fdes=eh_frame_records(data)
    records=[]
    for index,case in enumerate(CASES):
        start,end,digest,load,clear,prior,cmp,branch,enter,context,post_cmp,post_branch,restore=case
        for va,raw in zip((load,clear,prior,cmp,enter,restore),FORMS[index]):
            require(read(va,len(bytes.fromhex(raw)))==bytes.fromhex(raw),f'TLS operand/store changed at {va:#x}')
        require(read(branch,2)==b'\x0f\x84','TLS prior-state branch changed')
        fail_before=branch+6+struct.unpack('<i',read(branch+2,4))[0]
        require(read(post_cmp,4)==b'\x80\x78\x46\x02' and read(post_branch,1)==b'\x75','TLS post-state branch changed')
        fail_after=post_branch+2+struct.unpack('<b',read(post_branch+1,1))[0]
        for va,target in ((fail_before,0x56b7c30),(fail_after,0x57556e8)):
            raw=read(va,7)
            require(raw[:3]==b'\x48\x8d\x15' and va+7+struct.unpack('<i',raw[3:])[0]==target,'TLS failure source route changed')
        raw=read(context,5)
        require(raw[0]==0xe8 and context+5+struct.unpack('<i',raw[1:])[0]==0x4f72510,'TLS context helper changed')
        require(read(context+5,3)==b'\x48\x85\xc0','TLS context pointer test changed')
        null_branch=context+(15 if index==3 else 8)
        if index==3:
            require(read(context+8,7)==bytes.fromhex('48c7c1d8eeffff'),'TLS flag-preserving base reload changed')
        require(read(null_branch,2)==b'\x0f\x84','TLS missing-context branch changed')
        missing_context=null_branch+6+struct.unpack('<i',read(null_branch+2,4))[0]
        fs=[f for f in fdes if f['start']==start]
        require(len(fs)==1 and fs[0]['end']==end,'TLS owner FDE changed')
        require(hashlib.sha256(read(start,end-start)).hexdigest()==digest,'TLS owner body changed')
        f=fs[0]
        records.append({'start':hex(start),'end_exclusive':hex(end),'sha256':digest,'fde':hex(f['fde']),'cie':hex(f['cie']),
                        'save_flag_word':hex(load),'clear_flag_byte':hex(clear),'read_prior_state':hex(prior),
                        'set_state_2':hex(enter),'post_context_call':hex(context),'check_post_state':hex(post_cmp),
                        'restore_prior_state':hex(restore),'prior_failure':hex(fail_before),'post_failure':hex(fail_after)})
        records[-1]['missing_context_target']=hex(missing_context)
    sources=[]
    for loc,line,col in ((0x56b7c30,28,9),(0x57556e8,17,17)):
        n,l,c=struct.unpack('<QII',read(loc+8,16))
        require(loc in relocs,'TLS source relocation missing')
        path=read(relocs[loc],n).decode('utf8')
        require(path=='/home/ubuntu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tokio-1.44.2/src/runtime/context/runtime_mt.rs' and (l,c)==(line,col),'TLS source context changed')
        sources.append({'location':hex(loc),'path':path,'line':l,'column':c})
    return {'target_sha256':SHA256,'owners':records,'sources':sources,
            'selected_fields':{'saved_word':'TLS context +0x44/+0x45','cleared_byte':'+0x44','bracket_state_byte':'+0x46','temporary_state':2},
            'model_domain':'Raw state bytes and context-presence class, conditional on reaching selected bracket and normal body return.',
            'limits':'Partial state-cell protocol only. Entry bypasses, TLS initialization/destruction, scheduler/park helpers, '
                     'full flag restoration, body effects, unwinding and original Rust/runtime enum validity remain unproved.',
            'captured_binaries_executed':False}


def build(data):
    require(hashlib.sha256(data).hexdigest()==SHA256,'Wrong node94 SHA-256')
    return observe(data)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,default=ROOT/BINARY)
    p.add_argument('--out',type=Path,default=ROOT/'work/runtime-state-94.json')
    args=p.parse_args();result=build(args.binary.read_bytes())
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf8',newline='\n')
    print('Verified selected state brackets in',len(result['owners']),'owners')


if __name__=='__main__':main()
