"""Bind global clamp, complete tail helper and all global data ranges."""
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
BEGIN,END=0x55539e0,0x5553a36
HELPER,HELPER_END=0x552fa70,0x552fa82
INPUT,OUTPUT=0x57881e0,0x59afc98
CALLERS={'caller':(0x54b9b60,0x54b9f1d,[0x54b9c6b,0x54b9cc9])}
CALLS=[0x54b9c6b,0x54b9cc9]
BODY='fa05996ae0f8606c0a36969ce337aa49dbda9e19591975d7d7d33e96abdae29b'
HELPER_BODY='0205e2bef97ff423ddd93476570439d57fbb56605891459eee6b2c8d09fed112'


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
    for name,begin,end in [('offset',BEGIN,END),('helper',HELPER,HELPER_END)]+[(name,a,b) for name,(a,b,_) in CALLERS.items()]:
        raw,where=image.va_bytes(begin,end-begin,executable=True)
        if name=='offset':require(sha(raw)==BODY,'complete global-clamp body')
        if name=='helper':require(sha(raw)==HELPER_BODY,'complete tail helper body')
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
        if name in ('offset','helper'):
            require(not any(i.mnemonic=='call' for i in decoded),'unexpected call')
            if name=='offset':
                starts={i.address for i in decoded}
                require(all(int(i.op_str,16) in starts or int(i.op_str,16)==HELPER for i in decoded if i.mnemonic.startswith('j')),'closed main branches')
                require([i.address for i in decoded if i.mnemonic=='jmp' and i.op_str==hex(HELPER)]==[0x5553a23],'unique actual tail edge')
                require(not any(i.mnemonic=='ret' for i in decoded),'main leaves by tail only')
            else:
                require(not any(i.mnemonic.startswith('j') for i in decoded),'straight tail helper')
                require([i.address for i in decoded if i.mnemonic=='ret']==[HELPER_END-1],'helper return closure')
        else:
            hits=[i for i in decoded if i.mnemonic=='call' and i.op_str==hex(BEGIN)]
            require([i.address for i in hits]==CALLERS[name][2],'direct caller boundaries/targets')
        bodies[name]={'begin':begin,'end':end,'bytes':len(raw),'hex':raw.hex(),'sha256':sha(raw),
                      'file_offset':where['file_offset'],'frame':frame,'records':records,'instructions':len(rows),
                      'llvm_raw_rows':len(llvm),'llvm_joined_lock_prefix_rows':prefixes}
    require(image.va_bytes(END,10)[0]==b'\xcc'*10,'following padding')
    initial,input_where=image.va_bytes(INPUT,8)
    require(initial==b'\xff'*8,'initial global signed minus one')
    bss=[s for s in image.sections if s['type']==8 and s['address']<=OUTPUT and OUTPUT+24<=s['address']+s['size']]
    require(len(bss)==1 and bss[0]['name']=='.bss' and bss[0]['flags']&3==3,'complete allocated writable BSS outputs')
    loads=[s for s in image.segments if s['type']==1 and s['address']+s['filesz']<=OUTPUT and OUTPUT+24<=s['address']+s['memsz']]
    require(len(loads)==1 and loads[0]['flags']&6==6,'complete zero-filled output PT_LOAD')
    require(INPUT+8<=OUTPUT or OUTPUT+24<=INPUT,'fixed input/output ranges disjoint')
    globals_record={'input':INPUT,'input_hex':initial.hex(),'input_mapping':input_where,'output':OUTPUT,'output_bytes':24,'bss_section':bss[0],'zero_fill_segment':loads[0]}
    count=0;names=[]
    protected=[(BEGIN,END+10),(HELPER,HELPER_END),(INPUT,INPUT+8),(OUTPUT,OUTPUT+24)]+[(a,b) for a,b,_ in CALLERS.values()]
    for section in image.sections:
        require(section['type']!=9,'unsupported REL table')
        if section['type']!=4:continue
        require(section['entsize']==24 and section['size']%24==0,'RELA shape')
        for offset in range(section['offset'],section['offset']+section['size'],24):
            destination,info,addend=struct.unpack_from('<QQq',data,offset);count+=1
            require((info&0xffffffff) in (1,6,7,8,18),'unsupported relocation width')
            require(addend not in (BEGIN,HELPER),'unexpected entry naming relocation')
            require(not any(destination<end and start<destination+8 for start,end in protected),'protected code relocation')
    text=next(s for s in image.sections if s['name']=='.text');code=image.va_bytes(text['address'],text['size'],executable=True)[0]
    candidates,position=[],0
    while (position:=code.find(b'\xe8',position))>=0:
        if position+5<=len(code) and text['address']+position+5+struct.unpack_from('<i',code,position+1)[0]==BEGIN:candidates.append(text['address']+position)
        position+=1
    require(candidates==CALLS,'direct call candidate census')
    return {'target_sha256':sha(data),'target_bytes':len(data),'bodies':bodies,'following_padding_hex':'cc'*10,
            'naming_relocations':names,'globals':globals_record,
            'direct_e8_candidates':candidates,'complete_xref_census':False,'rela_records_checked':count,
            'capstone_version':capstone.__version__,'captured_code_executed':False,'instruction_emulation':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--write',action='store_true');args=parser.parse_args()
    data=(ROOT/'artifacts/node/94/hl-node').read_bytes();require(sha(data)==TARGET,'target identity')
    record=inspect(data);offset_body=record['bodies']['offset']
    locations={label:offset_body['file_offset']+offset for label,offset in {
        'global read':7,'sign branch':14,'minimum':17,'cap':27,'zero normalize':33,
        'shift':41,'lower clamp':44,'upper clamp':51,'global store':56,
        'tail argument':63,'tail destination':68,'negative normalize':81,'negative convergence':85,'padding':86}.items()}
    helper=record['bodies']['helper'];caller=record['bodies']['caller']
    locations.update({'helper zero store':helper['file_offset']+7,
                      'helper return zero':helper['file_offset']+11,
                      'helper RSI store':helper['file_offset']+16,
                      'input initializer':record['globals']['input_mapping']['file_offset'],
                      'main FDE extent':offset_body['records']['fde']['file_offset']+12,
                      'helper FDE extent':helper['records']['fde']['file_offset']+12,
                      'caller FDE extent':caller['records']['fde']['file_offset']+12,
                      'CIE encoding':offset_body['records']['cie']['file_offset']+15,
                      'first caller site':caller['file_offset']+0x54b9c6b-0x54b9b60+1,
                      'second caller site':caller['file_offset']+0x54b9cc9-0x54b9b60+1,
                      'BSS section type':struct.unpack_from('<Q',data,40)[0]+record['globals']['bss_section']['index']*struct.unpack_from('<H',data,58)[0]+4})
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
