#!/usr/bin/env python3
"""RE-001: node94 tagged compound comparison with HTTP-scheme source context."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from artifacts import ROOT
from elf_index import sections
from fde_extents import eh_frame_records

SHA256='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
START,END=0x284b430,0x284b54b
BODY_SHA256='50e4f0f9f5fd62dacfee715eaad7581abe496c1e3375d0e2c022a4248ab845c4'


def require(value,message):
    if not value:raise ValueError(message)


def fold_observed(byte,bias,bound,shift):
    require(0<=byte<=255,'Expected byte')
    flag=int(((byte+bias)&255)<bound)
    return (byte|(flag<<shift))&255


def byte_string_equal(left,right,constants):
    if len(left)!=len(right):return False
    return all(fold_observed(a,**constants)==fold_observed(b,**constants) for a,b in zip(left,right))


def compound_model(left,right,constants):
    """Abstract field inputs for modeled tags 1/2; result is only the returned AL."""
    require(left['tag'] in (1,2) and right['tag'] in (1,2),'Outside modeled tag domain')
    if left['tag']!=right['tag']:return False
    if left['tag']==1:
        if (left['byte1']==0)!=(right['byte1']==0):return False
    elif not byte_string_equal(left['indirect_bytes'],right['indirect_bytes'],constants):
        return False
    return byte_string_equal(left['common_bytes'],right['common_bytes'],constants)


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

    _,frames=eh_frame_records(data,secs)
    fs=[f for f in frames if f['start']==START]
    require(len(fs)==1 and fs[0]['end']==END,'Compound comparator FDE changed')
    require(read(0x284b431,17)==bytes.fromhex('0fb60783f801747683f8020f85f0000000'),'Left tag dispatch changed')
    require(read(0x284b442,11)==bytes.fromhex('0fb6063c020f8579000000'),'Right tag-2 dispatch changed')
    require(read(0x284b4af,7)==bytes.fromhex('0fb6063c017510'),'Right tag-1 dispatch changed')
    require(read(0x284b4b6,22)==bytes.fromhex('0fb64601807f0100740e84c07406eb0c84c0746831c0'),
            'Tag-1 byte-zero comparison changed')
    require(read(0x284b44d,18)==bytes.fromhex('488b4f08488b4110488b5608483b4210756b'),
            'Indirect component length/pointer layout changed')
    require(read(0x284b45f,8)==bytes.fromhex('488b4908488b5208'),'Indirect byte-buffer loads changed')
    require(read(0x284b4d2,18)==bytes.fromhex('488b4f20483b4e2075ee488b5718488b7618'),
            'Common component length/pointer layout changed')
    fold_sites=[(0x284b47a,'458d51','4180fa','410f92c2','41c0e2','4508ca'),
                (0x284b492,'458d59','4180fb','410f92c3','41c0e3','4508cb'),
                (0x284b4fd,'458d48','4180f9','410f92c1','41c0e1','4508c1'),
                (0x284b515,'458d50','4180fa','410f92c2','41c0e2','4508c2')]
    extracted=[]
    for va,lea,cmp_,setb,shl,or_ in fold_sites:
        bias=struct.unpack_from('<b',code(va,lea,4),3)[0]
        bound=code(va+4,cmp_,4)[3]
        require(read(va+8,4)==bytes.fromhex(setb),'ASCII range condition changed')
        shift=code(va+12,shl,4)[3]
        require(read(va+16,3)==bytes.fromhex(or_),'ASCII fold combination changed')
        extracted.append({'bias':bias,'bound':bound,'shift':shift})
    require(all(c=={'bias':-65,'bound':26,'shift':5} for c in extracted),'ASCII fold constants changed')
    constants=extracted[0]
    require(read(0x284b4a8,7)==bytes.fromhex('4538da74c3eb1b'),'First folded-byte comparison changed')
    require(read(0x284b52b,7)==bytes.fromhex('4538d174c059c3'),'Common folded-byte comparison/return changed')
    require(read(0x284b4f0,8)==bytes.fromhex('4839f90f94c07438'),'Common loop AL completion changed')
    relsec=next(s for s in secs if s['name']=='.rela.dyn')
    relocs={}
    for slot,info,addend in struct.iter_unpack('<QQq',read(relsec['address'],relsec['size'])):
        if info==8:
            require(slot not in relocs,'Duplicate RELATIVE relocation');relocs[slot]=addend
    raw=code(0x284b539,'488d15',7);location=0x284b540+struct.unpack_from('<i',raw,3)[0]
    require(location==0x56c9370 and relocs.get(location)==0x1fd235,'HTTP scheme source binding changed')
    length,line,column=struct.unpack('<QII',read(location+8,16))
    path=read(relocs[location],length).decode('utf8')
    require(path.endswith('/http-0.2.12/src/uri/scheme.rs') and (line,column)==(136,40),'HTTP scheme Location changed')
    require(relocs.get(0x576e108)==0x157b7f0,'Unreachable call slot binding changed')
    require(hashlib.sha256(read(START,END-START)).hexdigest()==BODY_SHA256,'Enclosing compound comparator body changed')
    reference=lambda x:x+32 if 65<=x<=90 else x
    fold_mismatches=sum(fold_observed(x,**constants)!=reference(x) for x in range(256))
    pair_mismatches=sum((fold_observed(a,**constants)==fold_observed(b,**constants))!=(reference(a)==reference(b))
                        for a in range(256) for b in range(256))
    require(fold_mismatches==pair_mismatches==0,'Byte fold differs from independent ASCII range form')
    return {'target_sha256':SHA256,'range':{'start_va':hex(START),'end_va_exclusive':hex(END),
            'bytes':END-START,'sha256':BODY_SHA256,'fde_va':hex(fs[0]['fde']),'cie_va':hex(fs[0]['cie'])},
            'fold_constants':constants,'fold_sites':[hex(s[0]) for s in fold_sites],
            'input_layout':{'tag_offset':'0x0','tag1_zero_test_byte':'0x1',
                            'tag2_indirect_header_pointer':'0x8','indirect_buffer_offset':'0x8',
                            'indirect_length_offset':'0x10','common_buffer_offset':'0x18','common_length_offset':'0x20'},
            'source_location':{'slot_va':hex(location),'path':path,'line':line,'column':column},
            'byte_comparison':{'byte_inputs':256,'byte_mismatches':fold_mismatches,
                               'byte_pairs':65536,'pair_mismatches':pair_mismatches},
            'captured_binaries_executed':False,
            'limits':'Valid-memory, modeled-tag 1/2 comparator observations only; AL result, not full RAX. '
                     'Original private function name, complete Rust object/URI type, caller role, parsing/hostname '
                     'policy and invalid-enum reachability remain unresolved. No progress gate.'}


def build(data):
    require(hashlib.sha256(data).hexdigest()==SHA256,'Wrong node94 SHA-256')
    return observe(data)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,default=ROOT/'artifacts/node/94/hl-node')
    p.add_argument('--out',type=Path,default=ROOT/'work/compound-ascii-94.json')
    args=p.parse_args();record=build(args.binary.read_bytes())
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(record,indent=2)+'\n',encoding='utf8',newline='\n')
    print(json.dumps(record['byte_comparison']))


if __name__=='__main__':main()
