#!/usr/bin/env python3
"""RE-001/consensus: raw early guards in the node94 timeout-certificate path."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from artifacts import ROOT
from elf_index import sections
from fde_extents import eh_frame_records

SHA256='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
START,END=0x47594f0,0x4759963
BODY_SHA256='eb5f1f913174c49a88970690822c87031076f18c9966efe6356a5d145ea55696'
MASK=(1<<64)-1


def require(value,message):
    if not value:raise ValueError(message)


def prefix_model(helper_rax,header_word,entry_words,tags):
    """Conditional raw stores only; continuation is NOT certificate acceptance."""
    require(0<=helper_rax<=MASK and 0<=header_word<=MASK,'Expected u64 values')
    require(all(0<=v<=MASK for v in entry_words),'Expected u64 entry words')
    if helper_rax==0:return {'stage':'raw_error_store','tag':tags['helper_zero'],'payload_qwords':[header_word]}
    if not entry_words:return {'stage':'raw_error_store','tag':tags['empty'],'payload_qwords':[]}
    for word in entry_words:
        if word!=header_word:
            return {'stage':'raw_error_store','tag':tags['mismatch'],'payload_qwords':[word,header_word]}
    return {'stage':'later_checks'}


def observe(data):
    secs=sections(data)

    def read(va,size):
        ss=[s for s in secs if s['type']!=8 and s['address']<=va and va+size<=s['address']+s['size']]
        require(len(ss)==1,'Expected one file-backed mapping')
        off=ss[0]['offset']+va-ss[0]['address'];require(off+size<=len(data),'Truncated mapped bytes')
        return data[off:off+size]

    def code(va,prefix,size):
        raw=read(va,size);require(raw.startswith(bytes.fromhex(prefix)),f'Instruction changed at {va:#x}')
        return raw

    def rel_branch(va,prefix,size,disp_offset):
        raw=code(va,prefix,size)
        disp=struct.unpack_from('<i',raw,disp_offset)[0] if size>=5 else struct.unpack_from('<b',raw,disp_offset)[0]
        return va+size+disp

    _,frames=eh_frame_records(data,secs)
    fs=[f for f in frames if f['start']==START]
    require(len(fs)==1 and fs[0]['end']==END,'TC guard FDE changed')
    require(read(0x475950a,4)==bytes.fromhex('4c8b7618'),'Header word source changed')
    require(read(0x4759515,4)==bytes.fromhex('4c3b7258'),'Cached word comparison changed')
    require(rel_branch(0x4759519,'0f86',6,2)==0x47595a1,'Diagnostic bypass branch changed')
    helper=rel_branch(0x47595a4,'e8',5,1)
    require(helper==0x42c9930,'Preceding helper call changed')
    require(read(0x47595a9,3)==bytes.fromhex('4885c0'),'Helper return test changed')
    require(rel_branch(0x47595ac,'0f84',6,2)==0x4759655,'Helper-zero branch changed')
    base=struct.unpack_from('<Q',code(0x47595ba,'49bc',10),2)[0]
    require(base==0x800000000000002a,'Raw tag base changed')
    require(read(0x47595e1,7)==bytes.fromhex('498b6f104885ed'),'Batch count load/test changed')
    require(rel_branch(0x47595e8,'0f84',6,2)==0x4759673,'Empty batch branch changed')
    require(read(0x47595ee,4)==bytes.fromhex('4d8b6708'),'Entry buffer source changed')
    stride=struct.unpack_from('<I',code(0x47595f2,'4869d5',7),3)[0]
    require(stride==184,'Entry stride changed')
    require(read(0x47595f9,7)==bytes.fromhex('498d341431c090'),'Entry span/loop initialization changed')
    load=code(0x4759600,'498b4c04',5);field_offset=load[4]
    require(field_offset==0x50,'Entry word offset changed')
    require(read(0x4759605,3)==bytes.fromhex('4c39f1'),'Entry/header comparison changed')
    require(rel_branch(0x4759608,'75',2,1)==0x475967f,'Mismatch branch changed')
    require(read(0x475960a,6)==bytes.fromhex('4805b8000000') and
            read(0x4759610,3)==bytes.fromhex('4839c2'),'Stride advance/end compare changed')
    require(rel_branch(0x4759613,'75',2,1)==0x4759600,'Loop back-edge changed')
    zero_base=struct.unpack_from('<Q',code(0x4759659,'48b9',10),2)[0]
    zero_adjust=struct.unpack_from('<b',code(0x4759663,'4883c1',4),3)[0]
    empty_adjust=struct.unpack_from('<b',code(0x4759673,'4983c4',4),3)[0]
    mismatch_base=struct.unpack_from('<Q',code(0x475967f,'48b8',10),2)[0]
    mismatch_adjust=struct.unpack_from('<b',code(0x4759689,'4883c0',4),3)[0]
    tags={'helper_zero':hex((zero_base+zero_adjust)&MASK),'empty':hex((base+empty_adjust)&MASK),
          'mismatch':hex((mismatch_base+mismatch_adjust)&MASK)}
    require(tags=={'helper_zero':'0x8000000000000028','empty':'0x800000000000000b',
                   'mismatch':'0x800000000000000f'},'Raw error tag stores changed')
    require(read(0x4759667,7)==bytes.fromhex('48890b48894308'),'Helper-zero payload stores changed')
    require(read(0x4759677,3)==bytes.fromhex('4c8923'),'Empty payload tag store changed')
    require(read(0x475968d,11)==bytes.fromhex('48890348894b084c897310'),'Mismatch payload stores changed')
    relsec=next(s for s in secs if s['name']=='.rela.dyn')
    relocs={}
    for slot,info,addend in struct.iter_unpack('<QQq',read(relsec['address'],relsec['size'])):
        if info==8:
            require(slot not in relocs,'Duplicate RELATIVE relocation');relocs[slot]=addend
    loc_raw=code(0x4759583,'488d0d',7)
    location=0x475958a+struct.unpack_from('<i',loc_raw,3)[0]
    require(location==0x5738668 and relocs.get(location)==0x1f7ea2,'Validator-set source relocation changed')
    size,line,column=struct.unpack('<QII',read(location+8,16))
    path=read(relocs[location],size).decode('utf8')
    require(path=='/home/ubuntu/hl/code_Mainnet/node/src/consensus/validator_set.rs' and (line,column)==(78,13),
            'Validator-set source Location changed')
    require(hashlib.sha256(read(START,END-START)).hexdigest()==BODY_SHA256,'Enclosing TC path body changed')
    cases=[(0,9,[]),(0,9,[9]),(1,9,[]),(1,9,[9]),(1,9,[9,9]),
           (1,9,[8,9]),(1,9,[9,10,9]),(MASK,MASK,[MASK]),(1,0,[0,MASK])]
    vectors=[{'helper_rax':flag,'header_word':header,'entry_words':words,
              'prefix_model':prefix_model(flag,header,words,tags)} for flag,header,words in cases]
    return {'target_sha256':SHA256,'range':{'start_va':hex(START),'end_va_exclusive':hex(END),
            'bytes':END-START,'sha256':BODY_SHA256,'fde_va':hex(fs[0]['fde']),'cie_va':hex(fs[0]['cie'])},
            'source_location':{'slot_va':hex(location),'path':path,'line':line,'column':column},
            'preceding_helper':{'call_va':'0x47595a4','target_va':hex(helper),'zero_branch_va':'0x4759655'},
            'input_words':{'header_offset':'0x18','count_offset':'0x10','buffer_offset':'0x8',
                           'element_stride':stride,'element_word_offset':hex(field_offset)},
            'raw_tags':tags,'model_vectors':vectors,'captured_binaries_executed':False,
            'limits':'Conditional prefix stores only, assuming valid backing memory and returning ABI-conforming '
                     'callees. The diagnostic arm rejoins the helper call on normal return. Continuation is not signature/quorum '
                     'acceptance. No full Rust layout, wire error enum, cryptographic verification, helper closure '
                     'or progress gate.'}


def build(data):
    require(hashlib.sha256(data).hexdigest()==SHA256,'Wrong node94 SHA-256')
    return observe(data)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,default=ROOT/'artifacts/node/94/hl-node')
    p.add_argument('--out',type=Path,default=ROOT/'work/tc-batch-guards-94.json')
    args=p.parse_args();record=build(args.binary.read_bytes())
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(record,indent=2)+'\n',encoding='utf8',newline='\n')
    print('Verified raw TC batch guards and error stores; no signature or target execution.')


if __name__=='__main__':main()
