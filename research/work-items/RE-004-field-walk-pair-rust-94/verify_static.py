"""Bind two complete field-derived store leaves; static parsing only."""
import argparse, hashlib, json, re, struct, sys
from pathlib import Path
import capstone
PACKET=Path(__file__).resolve().parent
ROOT=PACKET.parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from fde_extents import eh_frame_records
from libcore_fmt_correspondence import Elf
TARGET='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
STARTS=[0x514ab20,0x514ab50]
BODIES=['f30f1efa488b8788070000488b5030488b82200b0000482b82180b000048c1f804488906b801000000c3','f30f1efa48638238140000488906b801000000c3']
PADDING=[6,12]
def require(ok,message):
    if not ok:raise ValueError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return (json.dumps(value,indent=2,sort_keys=True)+'\n').encode()
def listing(path,image,start,end):
    rows=[];cursor=start
    for line in path.read_text().splitlines():
        match=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(\S.*)$',line)
        if match:
            address=int(match[1],16);raw=bytes.fromhex(match[2])
            require(address==cursor and address+len(raw)<=end,'listing extent')
            require(image.va_bytes(address,len(raw),executable=True)[0]==raw,'listing bytes')
            rows.append((address,raw));cursor+=len(raw)
    require(cursor==end,'complete listing');return rows

def inspect(data):
    image=Elf(data,3);cies,frames=eh_frame_records(data)
    def frame_record(begin,end):
        overlapping=[f for f in frames if f['start']<end and begin<f['end']]
        require(len(overlapping)==1 and (overlapping[0]['start'],overlapping[0]['end'])==(begin,end),'unique complete FDE')
        frame=overlapping[0];records={}
        for kind in ['fde','cie']:
            address=frame[kind];size=int.from_bytes(image.va_bytes(address,4)[0],'little')+4
            raw,where=image.va_bytes(address,size);records[kind]={'va':address,'file_offset':where['file_offset'],'hex':raw.hex()}
        return {'frame':frame,'cie':cies[frame['cie']],'records':records}
    decoder=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);members=[]
    for i,(start,body,padding) in enumerate(zip(STARTS,BODIES,PADDING)):
        end=start+len(bytes.fromhex(body));raw,where=image.va_bytes(start,end-start,executable=True)
        require(raw.hex()==body,'complete body identity')
        rows=listing(PACKET/f'member{i}.gnu.txt',image,start,end)
        require(rows==listing(PACKET/f'member{i}.llvm.txt',image,start,end),'GNU/LLVM boundaries')
        decoded=list(decoder.disasm(raw,start))
        require(rows==[(ins.address,bytes(ins.bytes)) for ins in decoded],'Capstone boundaries')
        require(not any(ins.mnemonic=='call' or ins.mnemonic.startswith('j') or 'rip' in ins.op_str for ins in decoded),'no calls/branches/RIP data')
        require([ins.address for ins in decoded if ins.mnemonic=='ret']==[end-1],'full return closure')
        require(image.va_bytes(end,padding)[0]==b'\xcc'*padding,'following padding')
        members.append({**frame_record(start,end),'begin':start,'end':end,'bytes':len(raw),'hex':raw.hex(),'sha256':sha(raw),'file_offset':where['file_offset'],'padding':padding,'instructions':[{'address':ins.address,'bytes':bytes(ins.bytes).hex(),'mnemonic':ins.mnemonic,'operands':ins.op_str} for ins in decoded]})
    neighbors=[frame_record(0x514aae0,0x514ab14),frame_record(0x514ab70,0x514ab84)]
    require(image.va_bytes(0x514ab14,12)[0]==b'\xcc'*12,'preceding padding')
    relocations=[]
    for section in image.sections:
        require(section['type']!=9,'unsupported REL table')
        if section['type']!=4:continue
        require(section['entsize']==24 and section['size']%24==0,'RELA shape')
        for at in range(section['offset'],section['offset']+section['size'],24):
            dest,info,addend=struct.unpack_from('<QQq',data,at)
            require(info&0xffffffff in [1,6,7,8,18],'unreviewed relocation width')
            require(not (dest<0x514ab70 and 0x514ab14<dest+8),'code/padding relocation')
            require(addend not in STARTS,'unexpected entry naming relocation')
            relocations.append((at,dest,info,addend))
    require(len(relocations)==80300,'complete RELA census')
    text=next(s for s in image.sections if s['name']=='.text');code=image.va_bytes(text['address'],text['size'],executable=True)[0];edges={}
    for opcode in [b'\xe8',b'\xe9']:
        hits=[];position=0
        while (position:=code.find(opcode,position))>=0:
            if position+5<=len(code):
                target=text['address']+position+5+struct.unpack_from('<i',code,position+1)[0]
                if target in STARTS:hits.append({'site':text['address']+position,'target':target})
            position+=1
        require(hits==[],'direct edge candidates');edges[opcode.hex()]=hits
    return {'target_sha256':sha(data),'target_bytes':len(data),'members':members,'neighbors':neighbors,'preceding_padding_hex':'cc'*12,'rela_records_checked':len(relocations),'entry_naming_relocations':[],'direct_encoding_candidates':edges,'complete_xref_census':False,'capstone_version':capstone.__version__,'captured_execution':False,'instruction_emulation':False}

def validate():
    data=(ROOT/'artifacts/node/94/hl-node').read_bytes();require(len(data)==91774280 and sha(data)==TARGET,'target identity');record=inspect(data);changes={}
    for index,member in enumerate(record['members']):
        for ins in member['instructions']:
            changes[f'member{index} instruction {ins["address"]:#x}']=member['file_offset']+ins['address']-member['begin']
            if len(bytes.fromhex(ins['bytes']))>1:changes[f'member{index} operand {ins["address"]:#x}']=member['file_offset']+ins['address']-member['begin']+len(bytes.fromhex(ins['bytes']))-1
        changes[f'member{index} FDE extent']=member['records']['fde']['file_offset']+12
        changes[f'member{index} padding']=member['file_offset']+member['bytes']
    changes['CIE encoding']=record['members'][0]['records']['cie']['file_offset']+15
    changes['preceding padding']=record['members'][0]['file_offset']-1
    for i,neighbor in enumerate(record['neighbors']):changes[f'neighbor{i} FDE']=neighbor['records']['fde']['file_offset']+12
    # Structural relocation controls reach the scan without relying on digest.
    image=Elf(data,3);section=next(s for s in image.sections if s['type']==4);rel=section['offset']
    special={'introduced naming relocation':(rel+16,struct.pack('<q',STARTS[0])),'partial code relocation':(rel,struct.pack('<Q',STARTS[1]-3))}
    rejected={}
    for label,at in changes.items():
        changed=bytearray(data);changed[at]^=1
        try:other=inspect(bytes(changed));require({k:v for k,v in other.items() if k!='target_sha256'}=={k:v for k,v in record.items() if k!='target_sha256'},'structural drift')
        except ValueError as error:rejected[label]=str(error)
        else:raise ValueError('accepted corruption '+label)
    for label,(at,replacement) in special.items():
        changed=bytearray(data);changed[at:at+len(replacement)]=replacement
        try:inspect(bytes(changed))
        except ValueError as error:rejected[label]=str(error)
        else:raise ValueError('accepted corruption '+label)
    record['corruption_controls']=rejected;return record

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--freeze',action='store_true');args=parser.parse_args();record=validate()
    if args.freeze:
        with (PACKET/'static.json').open('xb') as f:f.write(encoded(record))
    else:require((PACKET/'static.json').read_bytes()==encoded(record),'static drift')
    print(json.dumps({'members':len(record['members']),'instructions':sum(len(m['instructions']) for m in record['members']),'controls':len(record['corruption_controls'])}))
if __name__=='__main__':main()
