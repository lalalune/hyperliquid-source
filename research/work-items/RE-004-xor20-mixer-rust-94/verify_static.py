"""Bind overlapping loads, complete multiplier leaf and runtime seed relocation."""
import argparse
import json
import re
import struct
import sys
from oracle import ROOT, PACKET, require, sha
sys.path.insert(0, str(ROOT / 'tools'))
from fde_extents import eh_frame_records
from libcore_fmt_correspondence import Elf
import capstone

TARGET='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BEGIN,END,SLOT,SEED=0x4b27620,0x4b27669,0x576e3e0,0x5788348
CALLER_BEGIN,CALLER_END,CALL=0x4dd6ea0,0x4dd839e,0x4dd768f
BODY='299a5c9f54001c3f32800a37423ac3f12ed6cb41569889ef9c8b9f51695aa222'


def listing(path,image,begin,end):
    rows,cursor=[],begin
    for line in path.read_text().splitlines():
        match=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(\S.*)$',line)
        if match:
            address,raw=int(match[1],16),bytes.fromhex(match[2])
            require(address==cursor and address+len(raw)<=end,'listing extent')
            require(image.va_bytes(address,len(raw),executable=True)[0]==raw,'listing bytes')
            rows.append((address,raw));cursor+=len(raw)
    require(cursor==end,'complete listing')
    return rows


def inspect(data):
    image=Elf(data,3);_,frames=eh_frame_records(data)
    decoder=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);decoder.detail=True
    bodies={}
    for name,begin,end in [('mixer',BEGIN,END),('caller',CALLER_BEGIN,CALLER_END)]:
        raw,where=image.va_bytes(begin,end-begin,executable=True)
        if name=='mixer':require(sha(raw)==BODY,'complete mixer body')
        overlapping=[f for f in frames if f['start']<end and begin<f['end']]
        require(len(overlapping)==1 and (overlapping[0]['start'],overlapping[0]['end'])==(begin,end),'unique complete FDE')
        frame,records=overlapping[0],{}
        for kind in ('fde','cie'):
            address=frame[kind];size=int.from_bytes(image.va_bytes(address,4)[0],'little')+4
            value,location=image.va_bytes(address,size)
            records[kind]={'va':address,'file_offset':location['file_offset'],'hex':value.hex()}
        rows=listing(PACKET/(name+'.gnu.txt'),image,begin,end)
        llvm=listing(PACKET/(name+'.llvm.txt'),image,begin,end)
        # Preserve raw exports. Apple's printer may separate a LOCK prefix.
        joined,prefixes,index=[],[],0
        while index<len(llvm):
            address,value=llvm[index]
            if value==b'\xf0':
                require(index+1<len(llvm) and llvm[index+1][0]==address+1,'LOCK printer adjacency')
                prefixes.append(address);value+=llvm[index+1][1];index+=1
            joined.append((address,value));index+=1
        require(rows==joined,'GNU/LLVM instruction boundaries')
        decoded=list(decoder.disasm(raw,begin))
        require([(i.address,bytes(i.bytes)) for i in decoded]==rows,'Capstone instruction boundaries')
        if name=='mixer':
            require(not any(i.mnemonic.startswith(('j','call')) for i in decoded),'unexpected control edge')
            require([i.address for i in decoded if i.mnemonic=='ret']==[end-1],'terminal return')
        else:
            hits=[i for i in decoded if i.mnemonic=='call' and i.op_str==hex(BEGIN)]
            require([i.address for i in hits]==[CALL],'direct caller boundary/target')
        bodies[name]={'begin':begin,'end':end,'bytes':len(raw),'hex':raw.hex(),'sha256':sha(raw),
                      'file_offset':where['file_offset'],'frame':frame,'records':records,'instructions':len(rows),
                      'llvm_raw_rows':len(llvm),'llvm_joined_lock_prefix_rows':prefixes}
    require(image.va_bytes(END,7)[0]==b'\xcc'*7,'padding')
    load=image.va_bytes(BEGIN,7,executable=True)[0]
    require(load[:3].hex()=='488b15' and BEGIN+7+struct.unpack('<i',load[3:])[0]==SLOT,'RIP seed pointer load')
    slot_bytes,slot_where=image.va_bytes(SLOT,8)
    require(slot_bytes==bytes(8),'pre-relocation slot file bytes')
    bss=[s for s in image.sections if s['type']==8 and s['flags']&3==3 and s['address']<=SEED and SEED+16<=s['address']+s['size']]
    loads=[s for s in image.segments if s['type']==1 and s['flags']&6==6 and s['address']<=SEED and SEED+16<=s['address']+s['memsz']]
    require(len(bss)==len(loads)==1 and bss[0]['name']=='.bss','runtime seed memory coverage')
    # NOBITS has no file bytes. Check its memory mapping, never use a file-only
    # relocation resolver or invent seed contents from an ELF file offset.
    relocations,count=[],0
    protected=[(BEGIN,END+7),(CALLER_BEGIN,CALLER_END),(SLOT,SLOT+8),(SEED,SEED+16)]
    for section in image.sections:
        require(section['type']!=9,'unsupported REL table')
        if section['type']!=4:continue
        require(section['entsize']==24 and section['size']%24==0,'RELA shape')
        for offset in range(section['offset'],section['offset']+section['size'],24):
            destination,info,addend=struct.unpack_from('<QQq',data,offset);count+=1
            require(addend!=BEGIN,'unexpected entry naming relocation')
            if any(destination<end and start<destination+8 for start,end in protected):
                require(destination==SLOT and info==8 and addend==SEED,'protected relocation')
                relocations.append({'slot':destination,'kind':info&0xffffffff,'symbol':info>>32,
                                    'addend':addend,'record_file_offset':offset})
    require(len(relocations)==1,'unique seed relocation')
    text=next(s for s in image.sections if s['name']=='.text');code=image.va_bytes(text['address'],text['size'],executable=True)[0]
    candidates,position=[],0
    while (position:=code.find(b'\xe8',position))>=0:
        if position+5<=len(code) and text['address']+position+5+struct.unpack_from('<i',code,position+1)[0]==BEGIN:candidates.append(text['address']+position)
        position+=1
    require(candidates==[CALL],'direct call candidate census')
    return {'target_sha256':sha(data),'target_bytes':len(data),'bodies':bodies,'padding_hex':'cc'*7,
            'seed':{'slot':SLOT,'slot_file_offset':slot_where['file_offset'],'slot_file_hex':slot_bytes.hex(),
                    'relocation':relocations[0],'memory_va':SEED,'bytes_read':16,'section':bss[0],'PT_LOAD':loads[0],
                    'file_backed':False,'runtime_contents':'unknown; supplied as explicit synthetic input values'},
            'direct_e8_candidates':candidates,'complete_xref_census':False,'rela_records_checked':count,
            'capstone_version':capstone.__version__,'captured_code_executed':False,'instruction_emulation':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--write',action='store_true');args=parser.parse_args()
    data=(ROOT/'artifacts/node/94/hl-node').read_bytes();require(sha(data)==TARGET,'target identity')
    record=inspect(data);mixer=record['bodies']['mixer'];caller=record['bodies']['caller']
    locations={'overlapping read':mixer['file_offset']+13,'product':mixer['file_offset']+30,
               'fold tag':mixer['file_offset']+65,'RIP seed load':mixer['file_offset']+3,
               'padding':mixer['file_offset']+END-BEGIN,'FDE extent':mixer['records']['fde']['file_offset']+12,
               'CIE encoding':mixer['records']['cie']['file_offset']+15,
               'caller edge':caller['file_offset']+CALL-CALLER_BEGIN+1,
               'seed addend':record['seed']['relocation']['record_file_offset']+16,
               'slot file word':record['seed']['slot_file_offset']}
    rejected={}
    for label,offset in locations.items():
        changed=bytearray(data);changed[offset]^=1
        try:
            other=inspect(bytes(changed));require(other==record,'structural record drift')
        except ValueError as error:rejected[label]=str(error)
        else:raise ValueError('accepted corruption '+label)
    record['corruption_controls']=rejected;text=json.dumps(record,indent=2,sort_keys=True)+'\n'
    if args.write:
        with (PACKET/'static.json').open('x') as f:f.write(text)
    else:require((PACKET/'static.json').read_text()==text,'retained static drift')
    print(json.dumps({'instructions':{k:v['instructions'] for k,v in record['bodies'].items()},
                      'llvm_prefixes':record['bodies']['caller']['llvm_joined_lock_prefix_rows'],
                      'controls':rejected},indent=2))

if __name__=='__main__':main()
