"""Bind complete dual-load leaf and every reachable relocated data word."""
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
BEGIN,END,SLOT=0x4e48600,0x4e4861d,0x57494c0
CALLERS={}
CALLS=[]
BODY='9dee705feb2353ad368c513ffe9b15d1f5b100fce4298d7a62479ad0aa9d8e74'

TABLES={'A': (8131576, '1bd9cc37fdd70de950daaef488b76e3b003b69b7436ad128dc30f91f282e6064'), 'B': (91528336, '4d01384ccabc9e5ddb623b40cc21cf8ea4cc824d45eb2946501c24ecd886d1c4')}
DATA_RELOC_SHA='2ec7b12321ec875e302f6d457d40d986fb6a941ebe8c7316784ee0856242a448'

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
    for name,begin,end in [('offset',BEGIN,END)]+[(name,a,b) for name,(a,b,_) in CALLERS.items()]:
        raw,where=image.va_bytes(begin,end-begin,executable=True)
        if name=='offset':require(sha(raw)==BODY,'complete dual-load body')
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
        if name=='offset':
            require(not any(i.mnemonic=='call' or i.mnemonic.startswith('j') for i in decoded),'unexpected call or branch')
            require([i.address for i in decoded if i.mnemonic=='ret']==[END-1],'return closure')
        else:
            hits=[i for i in decoded if i.mnemonic=='call' and i.op_str==hex(BEGIN)]
            require([i.address for i in hits]==[CALLERS[name][2]],'direct caller boundary/target')
        bodies[name]={'begin':begin,'end':end,'bytes':len(raw),'hex':raw.hex(),'sha256':sha(raw),
                      'file_offset':where['file_offset'],'frame':frame,'records':records,'instructions':len(rows),
                      'llvm_raw_rows':len(llvm),'llvm_joined_lock_prefix_rows':prefixes}
    require(image.va_bytes(END,3)[0]==b'\xcc'*3,'following padding')
    tables={}
    for name,(base,digest) in TABLES.items():
        raw,where=image.va_bytes(base,2048)
        require(sha(raw)==digest,'complete '+name+' reachable data window')
        tables[name]={'base':base,'bytes':2048,'hex':raw.hex(),'sha256':sha(raw),'mapping':where}
    count=0;names=[];data_records=[];destinations=set()
    protected=[(BEGIN,END+3)]+[(a,b) for a,b,_ in CALLERS.values()]
    for section in image.sections:
        require(section['type']!=9,'unsupported REL table')
        if section['type']!=4:continue
        require(section['entsize']==24 and section['size']%24==0,'RELA shape')
        for offset in range(section['offset'],section['offset']+section['size'],24):
            destination,info,addend=struct.unpack_from('<QQq',data,offset);count+=1
            require((info&0xffffffff) in (1,6,7,8,18),'unsupported relocation width')
            if addend==BEGIN:
                require(destination==SLOT and info==8,'naming relocation kind/slot')
                slot_raw,slot_where=image.va_bytes(SLOT,8)
                require(slot_raw==bytes(8),'zero initialized relocation slot')
                names.append({'record_file_offset':offset,'record_hex':data[offset:offset+24].hex(),'slot':SLOT,'slot_hex':slot_raw.hex(),'slot_mapping':slot_where})
            require(not any(destination<end and start<destination+8 for start,end in protected),'protected code relocation')
            a,b=TABLES['A'][0],TABLES['B'][0]
            require(not (destination<a+2048 and a<destination+8),'unexpected A data relocation')
            if destination<b+2048 and b<destination+8:
                require(b<=destination and destination+8<=b+2048 and (destination-b)%8==0,'whole B qword relocation')
                require(info==8 and destination not in destinations,'unique symbol-zero RELATIVE relocation')
                destinations.add(destination)
                data_records.append({'index':(destination-b)//8,'destination':destination,'info':info,'addend':addend,'file_offset':offset,'hex':data[offset:offset+24].hex()})
    require(len(names)==1,'unique naming relocation')
    require(len(data_records)==127,'all B relocation count')
    require(sha(b''.join(bytes.fromhex(r['hex']) for r in data_records))==DATA_RELOC_SHA,'complete B relocation records')
    text=next(s for s in image.sections if s['name']=='.text');code=image.va_bytes(text['address'],text['size'],executable=True)[0]
    candidates,position=[],0
    while (position:=code.find(b'\xe8',position))>=0:
        if position+5<=len(code) and text['address']+position+5+struct.unpack_from('<i',code,position+1)[0]==BEGIN:candidates.append(text['address']+position)
        position+=1
    require(candidates==CALLS,'direct call candidate census')
    return {'target_sha256':sha(data),'target_bytes':len(data),'bodies':bodies,'following_padding_hex':'cc'*3,
            'naming_relocations':names,'tables':tables,'data_relocations':data_records,
            'direct_e8_candidates':candidates,'complete_xref_census':False,'rela_records_checked':count,
            'capstone_version':capstone.__version__,'captured_code_executed':False,'instruction_emulation':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--write',action='store_true');args=parser.parse_args()
    data=(ROOT/'artifacts/node/94/hl-node').read_bytes();require(sha(data)==TARGET,'target identity')
    record=inspect(data);offset_body=record['bodies']['offset']
    locations={'index zero extension':offset_body['file_offset'],
               'scale':offset_body['file_offset']+5,
               'A RIP displacement':offset_body['file_offset']+9,
               'RDX load':offset_body['file_offset']+13,
               'B RIP displacement':offset_body['file_offset']+20,
               'RAX load':offset_body['file_offset']+24,
               'padding':offset_body['file_offset']+END-BEGIN,
               'FDE extent':offset_body['records']['fde']['file_offset']+12,
               'CIE encoding':offset_body['records']['cie']['file_offset']+15,
               'naming target':record['naming_relocations'][0]['record_file_offset']+16,
               'naming kind':record['naming_relocations'][0]['record_file_offset']+8,
               'naming slot bytes':record['naming_relocations'][0]['slot_mapping']['file_offset']}
    for name,table in record['tables'].items():
        for index in (0,127,255):locations[name+' data word '+str(index)]=table['mapping']['file_offset']+8*index
    for label,delta in [('target',0),('type',8),('symbol',12),('addend',16)]:
        for index in (0,63,126):locations['B relocation '+label+' '+str(index)]=record['data_relocations'][index]['file_offset']+delta
    rejected={}
    for label,offset in locations.items():
        changed=bytearray(data);changed[offset]^=1
        try:
            other=inspect(bytes(changed));require({k:v for k,v in other.items() if k!='target_sha256'}=={k:v for k,v in record.items() if k!='target_sha256'},'structural record drift')
        except ValueError as error:rejected[label]=str(error)
        else:raise ValueError('accepted corruption '+label)
    record['corruption_controls']=rejected;text=json.dumps(record,indent=2,sort_keys=True)+'\n'
    if args.write:
        with (PACKET/'static.json').open('x') as f:f.write(text)
    else:require((PACKET/'static.json').read_text()==text,'retained static drift')
    print(json.dumps({'instructions':{k:v['instructions'] for k,v in record['bodies'].items()},
                      'llvm_prefixes':{k:v['llvm_joined_lock_prefix_rows'] for k,v in record['bodies'].items()},
                      'controls':rejected},indent=2))

if __name__=='__main__':main()
