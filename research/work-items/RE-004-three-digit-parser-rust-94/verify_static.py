"""Bind complete strict three-digit parser, sole direct caller and reference scans."""
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
BEGIN,END=0x1683670,0x16836c5
CALLER_BEGIN,CALLER_END,CALL=0x1682220,0x1682735,0x1682606
BODY='90c7bd6c996890a0c04b23ee47ff7aa6bdb911997e320fdb6989e741a090abca'
CALLER_BODY='a1a34984f457e4413ab96820190afa549708a6c14a7eb9ca0715a5d65a7b078b'


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
    for name,begin,end in [('parser',BEGIN,END),('caller',CALLER_BEGIN,CALLER_END)]:
        raw,where=image.va_bytes(begin,end-begin,executable=True)
        require(sha(raw)==(BODY if name=='parser' else CALLER_BODY),'complete '+name+' body')
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
        if name=='parser':
            require(len(decoded)==30,'complete thirty-instruction parser')
            require([i.address for i in decoded if i.mnemonic=='ret']==[0x16836a8,0x16836c4],'both return boundaries')
            require(not any(i.mnemonic=='call' or 'rip' in i.op_str for i in decoded),'no outgoing data/control dependency')
            edges=[(i.address,int(i.op_str,16)) for i in decoded if i.mnemonic.startswith('j')]
            require(edges==[(0x1683674,0x16836a6),(0x16836a4,0x16836a9)],'closed branch destinations')
            starts={i.address for i in decoded};require(all(dst in starts for _,dst in edges),'branch boundaries')
        else:
            hits=[i for i in decoded if i.mnemonic=='call' and i.op_str==hex(BEGIN)]
            require([i.address for i in hits]==[CALL],'direct caller boundary/target')
        bodies[name]={'begin':begin,'end':end,'bytes':len(raw),'hex':raw.hex(),'sha256':sha(raw),
                      'file_offset':where['file_offset'],'frame':frame,'records':records,'instructions':len(rows),
                      'llvm_raw_rows':len(llvm),'llvm_joined_lock_prefix_rows':prefixes}
    require(image.va_bytes(END,11)[0]==b'\xcc'*11,'eleven padding bytes')
    count=0;protected=[(BEGIN,END+11),(CALLER_BEGIN,CALLER_END)]
    for section in image.sections:
        require(section['type']!=9,'unsupported REL table')
        if section['type']!=4:continue
        require(section['entsize']==24 and section['size']%24==0,'RELA shape')
        for offset in range(section['offset'],section['offset']+section['size'],24):
            destination,info,addend=struct.unpack_from('<QQq',data,offset);count+=1
            require(info&0xffffffff in (1,6,7,8,18),'known relocation width')
            require(addend!=BEGIN,'no entry naming relocation')
            require(not any(destination<end and start<destination+8 for start,end in protected),'no overlapping code writer')
    text=next(s for s in image.sections if s['name']=='.text');code=image.va_bytes(text['address'],text['size'],executable=True)[0]
    scans={}
    for op,label,want in [(b'\xe8','E8',[CALL]),(b'\xe9','E9',[])]:
        hits=[];position=0
        while (position:=code.find(op,position))>=0:
            if position+5<=len(code) and text['address']+position+5+struct.unpack_from('<i',code,position+1)[0]==BEGIN:hits.append(text['address']+position)
            position+=1
        require(hits==want,'complete direct '+label+' scan');scans[label]=hits
    return {'target_sha256':sha(data),'target_bytes':len(data),'bodies':bodies,'padding_hex':'cc'*11,
            'direct_candidates':scans,'complete_xref_census':False,'rela_records_checked':count,
            'naming_relocations':[], 'capstone_version':capstone.__version__,
            'captured_code_executed':False,'instruction_emulation':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--write',action='store_true');args=parser.parse_args()
    data=(ROOT/'artifacts/node/94/hl-node').read_bytes();require(sha(data)==TARGET,'target identity')
    record=inspect(data);parser=record['bodies']['parser'];caller=record['bodies']['caller']
    locations={name:parser['file_offset']+offset for name,offset in {
        'full length':3,'length branch':5,'first load':8,'second displacement':12,
        'second bias':14,'third displacement':18,'third bias':21,'leading bias':24,
        'leading gate':28,'second gate':34,'third gate':40,'first flag join':48,
        'second flag join':51,'valid branch':53,'invalid return':55,'hundreds bias':62,
        'hundreds scale':68,'tens scale':73,'tens truncation':77,'hundreds sum':79,
        'ones sum':81,'final return':84,'padding':85}.items()}
    locations.update({'parser FDE':parser['records']['fde']['file_offset']+12,
                      'caller FDE':caller['records']['fde']['file_offset']+12,
                      'parser CIE':parser['records']['cie']['file_offset']+15,
                      'caller edge':caller['file_offset']+CALL-CALLER_BEGIN+1})
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
                      'llvm_prefixes':record['bodies']['caller']['llvm_joined_lock_prefix_rows'],
                      'controls':rejected},indent=2))

if __name__=='__main__':main()
