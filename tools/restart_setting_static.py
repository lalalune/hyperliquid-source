#!/usr/bin/env python3
"""RE-001: restart setting wrapper, component codec selection and result protocols."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from evm_amount_scale import ROOT,BINARY,SHA256,Image
from fde_extents import eh_frame_records

PACKET=ROOT/'research/work-items/RE-001-restart-setting-codecs-94'
MAX=(1<<64)-1;MIN=1<<63
OWNERS={0x13ca000:(0x13ca0d5,'26ff919843c88069e817118bd6928c8f57ff2a96be397f64ebe2fca53f1a8285'),
        0x144b900:(0x144bfcb,'b15cfdc6858f004e6c4ca67a5f8b1f09f29b9044503022c5e702c7ad307f9bb2')}
ANCHORS={0x13ca072:'4883f801',0x13ca076:'4883d000',
         0x144b938:'84c0',0x144b93a:'740e',0x144b9bb:'80bc24a000000009',
         0x144b9cb:'480f44c6',0x144b9cf:'0f85b2010000',
         0x144b9dd:'4883fa02',0x144b9e3:'66813e2e2e',0x144b9e8:'0f8499010000',
         0x144ba11:'807c3eff2e',0x144ba1b:'4885c9',0x144ba1e:'0f8463010000',
         0x144ba24:'4883c2fc',0x144ba28:'4839ca',0x144ba2b:'0f8556010000',
         0x144ba39:'4080fe1a',0x144ba41:'40c0e605',0x144ba48:'4080fe72',
         0x144ba5a:'4080fe1a',0x144ba62:'40c0e605',0x144ba69:'4080fe6d',
         0x144ba7b:'80f91a',0x144ba81:'c0e105',0x144ba86:'80f970',
         0x144bab5:'48f7d8',0x144bab8:'0f810f030000',
         0x144bbad:'48f7d8',0x144bbb0:'0f81f9000000',
         0x144bceb:'f6c101',0x144bcee:'0f8432010000',
         0x144be14:'80bc248000000009',0x144be1c:'7547',0x144be1e:'488b842488000000',
         0x144bdbc:'31c0'}
SLOTS={0x13ca007:(0x576e928,0x577b288,b'\x48\x8b\x1d'),
       0x144b91c:(0x576f628,0x144a600,b'\xff\x15'),
       0x144b932:(0x576e9e8,0x144a710,b'\xff\x15'),
       0x144b9b3:(0x576e850,0x4f11400,b'\xff\x15'),
       0x144baa4:(0x576f640,0x4ed97e0,b'\xff\x15'),
       0x144bb9c:(0x576f648,0x4ed9180,b'\xff\x15')}


def require(ok,message):
    if not ok:raise ValueError(message)


def component_codec(component):
    """Supplied normal final-component byte slice only; not a path parser."""
    require(isinstance(component,bytes),'Expected component bytes')
    dot=component.rfind(b'.')
    if dot<=0 or len(component)-dot!=4:return 'json_candidate'
    def fold(c):return c | (((c-65)&255)<26)*32
    return 'rmp_candidate' if bytes(fold(c) for c in component[dot+1:])==b'rmp' else 'json_candidate'


def loader_value(codec,eligible,read_word,parse_tag,payload):
    require(codec in ('json_candidate','rmp_candidate') and type(eligible) is bool,'Expected selected codec/predicate')
    require(all(type(w) is int and 0<=w<=MAX for w in (read_word,parse_tag,payload)),'Expected u64 helper words')
    if not eligible or read_word==MIN:return 0
    success=(parse_tag & 255)==9 if codec=='rmp_candidate' else (parse_tag & 1)==0
    return payload if success else 0


def page_count(word):
    require(type(word) is int and 0<=word<=MAX,'Expected u64 reader result')
    return word+int(word<1)


def observe(data):
    img=Image(data);read=img.read;relocs=img.relative_relocs()
    for va,raw in ANCHORS.items():
        require(read(va,len(bytes.fromhex(raw)))==bytes.fromhex(raw),f'Setting operand/control changed at {va:#x}')
    for va,(slot,target,opcode) in SLOTS.items():
        raw=read(va,len(opcode)+4)
        require(raw.startswith(opcode) and va+len(raw)+struct.unpack('<i',raw[-4:])[0]==slot and relocs.get(slot)==target,'Setting helper/global binding changed')
    for va,target in [(0x13ca052,0x144b900),(0x144bce0,0x149e2b0),(0x144be0f,0x13aa0c0)]:
        raw=read(va,5)
        require(raw[0]==0xe8 and va+5+struct.unpack('<i',raw[1:])[0]==target,'Setting decoder call changed')
    prefix=b'\xc0\x29/hyperliquid_data/n_restarts_to_page.json\0'
    require(read(0x1de68f,len(prefix))==prefix,'Setting path template changed')
    label=b'\x16serde_json::from_str: \xc0\0'
    require(read(0x1fd0ce,len(label))==label,'JSON decoder label changed')
    loc=0x5666b80;n,line,col=struct.unpack('<QII',read(loc+8,16))
    require(relocs.get(loc)==0x1ef2de and read(0x1ef2de,n)==b'/home/ubuntu/hl/code_Mainnet/base/src/u.rs' and (line,col)==(549,5),'Setting source binding changed')
    _,fdes=eh_frame_records(data);owners=[]
    for start,(end,digest) in OWNERS.items():
        fs=[f for f in fdes if f['start']==start]
        require(len(fs)==1 and fs[0]['end']==end,'Setting owner FDE changed')
        require(hashlib.sha256(read(start,end-start)).hexdigest()==digest,'Setting owner body changed')
        f=fs[0];owners.append({'start':hex(start),'end_exclusive':hex(end),'sha256':digest,'fde':hex(f['fde']),'cie':hex(f['cie'])})
    return {'target_sha256':SHA256,'owners':owners,'path_template_va':'0x1de68f','source_location':{'va':hex(loc),'line':line,'column':col},
            'component_choice':'Nonleading final dot plus exactly three ASCII-folded rmp bytes selects binary path; otherwise text path.',
            'reader_result_protocols':{'read_error_word':hex(MIN),'binary_parser_success_byte':9,'text_parser_success':'RAX low bit 0, payload RDX'},
            'error_normal_return_word':0,'wrapper_formula':'word + unsigned(word < 1)',
            'decoder_targets':{'text_candidate':'0x149e2b0','binary_candidate':'0x13aa0c0'},
            'limits':'Normal helper-return/component-result model only. Actual path expansion/predicate, file bytes, '
                     'JSON/messagepack grammar, concrete Rust types, diagnostics/drop/unwind and live global/root state unproved.',
            'captured_binaries_executed':False}


def build(data):
    require(hashlib.sha256(data).hexdigest()==SHA256,'Wrong node94 SHA-256')
    return observe(data)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,default=ROOT/BINARY)
    p.add_argument('--out',type=Path,default=ROOT/'work/restart-setting-94.json')
    args=p.parse_args();result=build(args.binary.read_bytes())
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf8',newline='\n')
    print(result['component_choice'],result['wrapper_formula'])


if __name__=='__main__':main()
