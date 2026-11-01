"""Bind complete modulo-index wrapper, closed signed-tail hash helper and incoming caller."""
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
BEGIN,END=0x538c820,0x538c859
CALLEE,CALLEE_END=0x5422e70,0x5422ef5
CALLERS={'caller':(0x535be50,0x535c4ab,0x535bea9)}
CALLS=[0x535bea9]
BODY='a1e5647d12dde2d1607f29c5ddf0f8c60ef066d7d45ea11c21112c9c8d9e90df'
HASH_BODY='3ebe23ed28ea513252146f93fc7b3f9b29518d9f36b38747f2efc1ca29fda225'


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
    for name,begin,end in [('wrapper',BEGIN,END),('hash',CALLEE,CALLEE_END)]+[(name,a,b) for name,(a,b,_) in CALLERS.items()]:
        raw,where=image.va_bytes(begin,end-begin,executable=True)
        if name in ('wrapper','hash'):require(sha(raw)==({'wrapper':BODY,'hash':HASH_BODY}[name]),'complete '+name+' body')
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
        if name=='wrapper':
            require([(i.address,i.op_str) for i in decoded if i.mnemonic=='call']==[(0x538c83c,hex(CALLEE))], 'closed helper edge')
            require(not any(i.mnemonic.startswith('j') for i in decoded),'wrapper branch closure')
            require([i.address for i in decoded if i.mnemonic=='ret']==[END-1],'wrapper return')
        elif name=='hash':
            require(not any(i.mnemonic=='call' for i in decoded),'unexpected helper call')
            require([(i.address,i.op_str) for i in decoded if i.mnemonic.startswith('j')]==[
                (0x5422e87,'0x5422eb5'), (0x5422ea7,'0x5422e90'),
                (0x5422ebc,'0x5422ed9'), (0x5422ec2,'0x5422ed0'),
                (0x5422ec8,'0x5422ee2')], 'hash CFG closure')
            require([i.address for i in decoded if i.mnemonic=='ret']==[0x5422eca,0x5422ef4],'hash returns')
        else:
            hits=[i for i in decoded if i.mnemonic=='call' and i.op_str==hex(BEGIN)]
            require([i.address for i in hits]==[CALLERS[name][2]],'direct caller boundary/target')
        bodies[name]={'begin':begin,'end':end,'bytes':len(raw),'hex':raw.hex(),'sha256':sha(raw),
                      'file_offset':where['file_offset'],'frame':frame,'records':records,'instructions':len(rows),
                      'llvm_raw_rows':len(llvm),'llvm_joined_lock_prefix_rows':prefixes}
    require(image.va_bytes(END,7)[0]==b'\xcc'*7,'following padding')
    require(image.va_bytes(CALLEE_END,11)[0]==b'\xcc'*11,'helper padding')
    count=0
    protected=[(BEGIN,END+7),(CALLEE,CALLEE_END+11)]+[(a,b) for a,b,_ in CALLERS.values()]
    for section in image.sections:
        require(section['type']!=9,'unsupported REL table')
        if section['type']!=4:continue
        require(section['entsize']==24 and section['size']%24==0,'RELA shape')
        for offset in range(section['offset'],section['offset']+section['size'],24):
            destination,info,addend=struct.unpack_from('<QQq',data,offset);count+=1
            require((info&0xffffffff) in (1,6,7,8,18),'unsupported relocation width')
            require(addend!=BEGIN,'unexpected entry naming relocation')
            require(not any(destination<end and start<destination+8 for start,end in protected),'protected code relocation')
    text=next(s for s in image.sections if s['name']=='.text');code=image.va_bytes(text['address'],text['size'],executable=True)[0]
    candidates,position=[],0
    while (position:=code.find(b'\xe8',position))>=0:
        if position+5<=len(code) and text['address']+position+5+struct.unpack_from('<i',code,position+1)[0]==BEGIN:candidates.append(text['address']+position)
        position+=1
    require(candidates==CALLS,'direct call candidate census')
    return {'target_sha256':sha(data),'target_bytes':len(data),'bodies':bodies,'following_padding_hex':'cc'*7,
            'direct_e8_candidates':candidates,'complete_xref_census':False,'rela_records_checked':count,
            'capstone_version':capstone.__version__,'captured_code_executed':False,'instruction_emulation':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--write',action='store_true');args=parser.parse_args()
    data=(ROOT/'artifacts/node/94/hl-node').read_bytes();require(sha(data)==TARGET,'target identity')
    record=inspect(data);wrapper=record['bodies']['wrapper'];helper=record['bodies']['hash']
    locations={'wrapper seed':wrapper['file_offset']+21,
               'wrapper helper edge':wrapper['file_offset']+29,
               'divisor load':wrapper['file_offset']+35,
               'division width':wrapper['file_offset']+40,
               'index width':wrapper['file_offset']+18,
               'return byte load':wrapper['file_offset']+47,
               'length multiply':helper['file_offset']+6,
               'block shift':helper['file_offset']+49,
               'loop edge':helper['file_offset']+56,
               'tail signed load':helper['file_offset']+98,
               'tail shift':helper['file_offset']+129,
               'wrapper padding':wrapper['file_offset']+END-BEGIN,
               'helper padding':helper['file_offset']+CALLEE_END-CALLEE,
               'wrapper FDE':wrapper['records']['fde']['file_offset']+12,
               'helper FDE':helper['records']['fde']['file_offset']+12,
               'CIE':helper['records']['cie']['file_offset']+15}
    for name,(start,_,site) in CALLERS.items():
        locations[name+' call']=record['bodies'][name]['file_offset']+site-start+1
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
                      'llvm_prefixes':{k:v['llvm_joined_lock_prefix_rows'] for k,v in record['bodies'].items()},
                      'controls':rejected},indent=2))

if __name__=='__main__':main()
