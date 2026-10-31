#!/usr/bin/env python3
"""RE-001: raw 32-bit code classification and result stores at node94 0x15bb930."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from evm_amount_scale import ROOT, BINARY, SHA256, Image
from fde_extents import eh_frame_records

PACKET=ROOT/'research/work-items/RE-001-rpc-code-classifier-94'
OWNERS={
    0x15bb930:(0x15bbb45,'9fb896ffae1b686b9d844e108de20b463f96726cbbba89c3cada6ec9c672c424'),
    0x1611910:(0x1615281,'6d9a41f7a41c9152a30cc84e81b87b247c4c473d257d44e04ff0ae1114997e3c'),
}
ANCHORS={
    0x15bb942:'4189f4',0x15bb945:'4989fe',
    0x15bb948:'48bd0000000000000080',0x15bb952:'488d4505',
    0x15bb956:'483901',0x15bb959:'7508',0x15bb95b:'4531ed',
    0x15bba19:'418d84245b7f0000',0x15bba21:'83f803',0x15bba24:'7717',
    0x15bba26:'488d0d2b5acafe',0x15bba2d:'48630481',0x15bba31:'4801c8',0x15bba34:'ffe0',
    0x15bba3d:'4181fc4480ffff',0x15bba44:'7415',
    0x15bba46:'b807000000',0x15bba4b:'4181fcf982ffff',0x15bba52:'751e',
    0x15bba54:'b801000000',0x15bba5b:'31c0',
    0x15bba72:'488b1424',0x15bba76:'488b4a10',0x15bba7a:'49894e28',
    0x15bba7e:'0f1002',0x15bba81:'410f114618',
    0x15bba86:'31c9',0x15bba88:'4983fd01',0x15bba8c:'4883d101',
    0x15bba90:'41894630',0x15bba94:'45896634',
    0x15bba98:'49890e',0x15bba9b:'4d896e08',0x15bba9f:'49896e10',0x15bbaa3:'4c89f0',
    0x161434b:'8bb424d0000000',0x161436c:'488d8c2470070000',
    0x1614374:'488d7c2470',0x1614379:'488d942448070000',0x1614381:'e8aa75faff',
}
HANDLERS={0x15bba36:6,0x15bba6d:5,0x15bba5f:3,0x15bba66:2}
MASK=(1<<32)-1


def require(ok,message):
    if not ok:raise ValueError(message)


def classify(word,table_tags=(6,5,3,2),bias=32603):
    """Raw u32 primitive only. No claim about wider JSON number admission."""
    require(type(word) is int and 0<=word<=MASK,'Expected u32 word')
    index=(word+bias)&MASK
    if index<=3:return table_tags[index]
    if word==0xffff8044:return 0
    if word==0xffff82f9:return 1
    return 7


def observe(data):
    img=Image(data);read=img.read
    for va,raw in ANCHORS.items():
        require(read(va,len(bytes.fromhex(raw)))==bytes.fromhex(raw),f'Code operand/control changed at {va:#x}')
    bias=struct.unpack('<I',read(0x15bba19+4,4))[0]
    table=0x15bba26+7+struct.unpack('<i',read(0x15bba26+3,4))[0]
    require(table==0x261458,'Code table pointer changed')
    rows=[];tags=[]
    for index in range(4):
        target=table+struct.unpack('<i',read(table+index*4,4))[0]
        require(target==tuple(HANDLERS)[index],'Code table target changed')
        require(read(target,1)==b'\xb8','Code handler is not MOV EAX,imm32')
        tag=struct.unpack('<I',read(target+1,4))[0]
        require(tag==HANDLERS[target],'Code handler tag changed')
        if target+5==0x15bba72:
            merge=target+5
        else:
            require(read(target+5,1)==b'\xeb','Code handler merge changed')
            merge=target+7+struct.unpack('<b',read(target+6,1))[0]
        require(merge==0x15bba72,'Code handler merge target changed')
        word=(index-bias)&MASK;signed=word-(1<<32) if word>>31 else word
        rows.append({'index':index,'code_i32':signed,'code_u32':word,'target':hex(target),'tag':tag})
        tags.append(tag)
    _,fdes=eh_frame_records(data);owners=[]
    for start,(end,digest) in OWNERS.items():
        matches=[f for f in fdes if f['start']==start]
        require(len(matches)==1 and matches[0]['end']==end,'Code owner FDE changed')
        require(hashlib.sha256(read(start,end-start)).hexdigest()==digest,'Code owner body changed')
        f=matches[0];owners.append({'start':hex(start),'end_exclusive':hex(end),'sha256':digest,'fde':hex(f['fde']),'cie':hex(f['cie'])})
    exceptional={r['code_u32']:r['tag'] for r in rows};exceptional.update({0xffff8044:0,0xffff82f9:1})
    require(len(exceptional)==6,'Exceptional code classes overlap')
    probes=sorted({0,MASK,1,0x7fffffff,0x80000000}|set(exceptional)|{(x+d)&MASK for x in exceptional for d in (-1,1)})
    require(all(classify(w,tuple(tags),bias)==exceptional.get(w,7) for w in probes),'Code partition differs')
    return {'target_sha256':SHA256,'owners':owners,'table_va':hex(table),'wrapping_add_u32':bias,'table_rows':rows,
            'special_rows':[{'code_i32':-32700,'tag':0},{'code_i32':-32007,'tag':1}],
            'default_tag':7,'emitted_tags':[0,1,2,3,5,6,7],
            'primitive_partition':{'total_u32_words':1<<32,'exceptional_singletons':6,'default_words':(1<<32)-6},
            'caller':{'call_va':'0x1614381','code_load_va':'0x161434b','code_operand':'dword [rsp+0xd0] -> ESI',
                      'out_operand':'rsp+0x70','message_operand':'rsp+0x748','data_operand':'rsp+0x770'},
            'result_stores':{'kind_u32_offset':'0x30','original_code_u32_offset':'0x34',
                             'copied_24_byte_input_offset':'0x18','data_words_offsets':['0','8','0x10'],
                             'first_word_formula':'1 + unsigned(R13 < 1)','return_register':'RAX = original output pointer'},
            'boundary_probes':[{'word':w,'tag':classify(w,tuple(tags),bias)} for w in probes],
            'limits':'Raw u32 code classifier and selected stores. JSON/wire number parsing, enum names/ABI, '
                     'optional-data serialization/allocation, error policy and caller state-machine closure unproved.',
            'captured_binaries_executed':False}


def build(data):
    require(hashlib.sha256(data).hexdigest()==SHA256,'Wrong node94 SHA-256')
    return observe(data)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,default=ROOT/BINARY)
    p.add_argument('--out',type=Path,default=ROOT/'work/rpc-code-94.json')
    args=p.parse_args();result=build(args.binary.read_bytes())
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf8',newline='\n')
    print([(r['code_i32'],r['tag']) for r in result['table_rows']])


if __name__=='__main__':main()
