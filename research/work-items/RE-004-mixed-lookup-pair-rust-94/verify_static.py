"""Close two complete mixed-width byte-indexed leaves and all reachable data."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import capstone
PACKET=Path(__file__).resolve().parent
ROOT=PACKET.parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from fde_extents import eh_frame_records
from libcore_fmt_correspondence import Elf
TARGET='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
MEMBERS=[(0x299e280,0x299e29e,0x3f7918,'488d059196a5fd400fb6cf488b14c8488d350a99a5fd4863048e4801f0c3'),(0x29d7fc0,0x29d7fde,0x4024a0,'488d05d9a4a2fd400fb6cf488b14c8488d3552a7a2fd4863048e4801f0c3')]
CALLERS=[(0x16505b0,0x1652428),(0x1679980,0x167ac43),(0x1682090,0x1682217),(0x29d7fe0,0x29d8a0e)]
CALLS={0x16511cc:0,0x1651487:0,0x167a6d5:0,0x167a745:0,0x167a8f6:0,0x168214d:0,0x29d81b4:1}
DATA_HASHES=['2f4c56e67360015dd7c3a66c3017e3b7d8bb293dfce264d3a146414befb8e989','f45c2d78fb4a5baac96ce8fd86fa1f329ef199b3ffea34ead792c5861993939e']


def require(ok,message):
    if not ok:raise ValueError(message)


def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()


def listing(path,image,begin,end):
    rows,cursor=[],begin
    for line in path.read_text().splitlines():
        m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(\S.*)$',line)
        if m:
            address,raw=int(m[1],16),bytes.fromhex(m[2]);require(address==cursor and address+len(raw)<=end,'listing extent')
            require(image.va_bytes(address,len(raw),executable=True)[0]==raw,'listing bytes');rows.append((address,raw));cursor+=len(raw)
    require(cursor==end,'complete listing');return rows


def inspect(data):
    image=Elf(data,3);cies,frames=eh_frame_records(data);decoder=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
    def frame(begin,end):
        matches=[f for f in frames if f['start']<end and begin<f['end']]
        require(len(matches)==1 and (matches[0]['start'],matches[0]['end'])==(begin,end),'unique complete FDE')
        f=matches[0];records={}
        for kind in ['fde','cie']:
            address=f[kind];size=int.from_bytes(image.va_bytes(address,4)[0],'little')+4;raw,where=image.va_bytes(address,size)
            records[kind]={'va':address,'file_offset':where['file_offset'],'hex':raw.hex()}
        return {'frame':f,'cie':cies[f['cie']],'records':records}
    def region(begin,end,name):
        raw,where=image.va_bytes(begin,end-begin,executable=True);rows=listing(PACKET/(name+'.gnu.txt'),image,begin,end)
        llvm=listing(PACKET/(name+'.llvm.txt'),image,begin,end)
        # LLVM prints the LOCK prefix as a separate row at this one site.
        # Verify the exact two raw rows, then join only their display boundary.
        if name=='caller1':
            at=next(i for i,(address,_) in enumerate(llvm) if address==0x167aa04)
            require(llvm[at:at+2]==[(0x167aa04,bytes.fromhex('f0')),(0x167aa05,bytes.fromhex('48ff08'))],'exact LLVM LOCK display split')
            llvm[at:at+2]=[(0x167aa04,bytes.fromhex('f048ff08'))]
        require(rows==llvm,'GNU/LLVM boundaries after explicit display join');ins=list(decoder.disasm(raw,begin))
        require(rows==[(i.address,bytes(i.bytes)) for i in ins],'Capstone boundaries')
        return {**frame(begin,end),'begin':begin,'end':end,'bytes':len(raw),'hex':raw.hex(),'sha256':sha(raw),'file_offset':where['file_offset'],
                'instructions':[{'address':i.address,'bytes':bytes(i.bytes).hex(),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ins]}
    members=[];windows=[]
    for k,(a,b,base,body) in enumerate(MEMBERS):
        record=region(a,b,f'member{k}');require(record['hex']==body,'exact complete body')
        require([i['mnemonic'] for i in record['instructions']]==['lea','movzx','mov','lea','movsxd','add','ret'],'complete straight-line shape')
        raw=bytes.fromhex(body)
        require(a+7+struct.unpack_from('<i',raw,3)[0]==base and a+22+struct.unpack_from('<i',raw,18)[0]==base+0x288,'both RIP base bindings')
        require(image.va_bytes(b,2)[0]==b'\xcc'*2,'following padding');members.append(record)
        data_bytes,where=image.va_bytes(base,2048)
        require(sha(data_bytes)==DATA_HASHES[k] and (PACKET/f'data{k}.bin').read_bytes()==data_bytes,'complete reachable data window')
        require(where['section']['name']=='.rodata' and not where['PT_LOAD']['flags']&2,'read-only data mapping')
        windows.append({'qword_base':base,'signed_offset_base':base+0x288,'mapping':where,'sha256':sha(data_bytes),'bytes':2048,
                        'qwords':list(struct.unpack('<256Q',data_bytes)),'signed_offsets':list(struct.unpack_from('<256i',data_bytes,0x288)),
                        'signed_window_relative_range':[0x288,0x688],'logical_table_extent_claimed':False})
    callers=[region(a,b,f'caller{k}') for k,(a,b) in enumerate(CALLERS)]
    actual_calls={i['address']:int(i['operands'],16) for c in callers for i in c['instructions'] if i['mnemonic']=='call' and i['address'] in CALLS}
    require(actual_calls=={at:MEMBERS[k][0] for at,k in CALLS.items()},'all seven caller instruction boundaries')
    neighbors=[frame(0x299e2a0,0x299e473),frame(0x29d8a10,0x29d8bfd)]
    protected=[(a,b+2) for a,b,_,_ in MEMBERS]+CALLERS+[(base,base+2048) for _,_,base,_ in MEMBERS]
    count=0
    for s in image.sections:
        require(s['type']!=9,'unsupported REL')
        if s['type']!=4:continue
        require(s['entsize']==24 and s['size']%24==0,'RELA shape')
        for at in range(s['offset'],s['offset']+s['size'],24):
            dest,info,add=struct.unpack_from('<QQq',data,at);count+=1
            require(info&0xffffffff in [1,6,7,8,18],'unreviewed relocation width')
            require(not any(dest<end and begin<dest+8 for begin,end in protected),'code or partial data relocation')
            require(add not in [m[0] for m in MEMBERS],'unexpected naming relocation')
    tx=next(s for s in image.sections if s['name']=='.text');code=image.va_bytes(tx['address'],tx['size'],executable=True)[0];edges={}
    for opcode in [b'\xe8',b'\xe9']:
        hits={};pos=0
        while (pos:=code.find(opcode,pos))>=0:
            if pos+5<=len(code):
                target=tx['address']+pos+5+struct.unpack_from('<i',code,pos+1)[0]
                if target in [m[0] for m in MEMBERS]:hits[tx['address']+pos]=target
            pos+=1
        require(hits==(actual_calls if opcode==b'\xe8' else {}),'raw direct candidate closure');edges[opcode.hex()]=hits
    return {'target_sha256':sha(data),'target_bytes':len(data),'members':members,'data_windows':windows,'callers':callers,'next_records':neighbors,
            'rela_records_checked':count,'overlapping_data_relocations':[],'entry_naming_relocations':[],'direct_candidates':edges,
            'llvm_display_join':{'address':0x167aa04,'raw_rows':['f0','48ff08'],'joined':'f048ff08','code_byte_mask':'none'},'complete_xref_census':False,'capstone_version':capstone.__version__,'captured_execution':False,'instruction_emulation':False}


def validate():
    data=(ROOT/'artifacts/node/94/hl-node').read_bytes();require(len(data)==91774280 and sha(data)==TARGET,'target identity');record=inspect(data);changes={}
    for k,m in enumerate(record['members']):
        for n in [3,7,9,13,18,23,25,27,29,30]:changes[f'member{k} byte{n}']=m['file_offset']+n
        changes[f'member{k} FDE']=m['records']['fde']['file_offset']+12
        changes[f'member{k} CIE']=m['records']['cie']['file_offset']+15
    for k,w in enumerate(record['data_windows']):
        for n in [0,7,0x287,0x288,0x28b,0x687,0x688,2047]:changes[f'data{k} byte{n}']=w['mapping']['file_offset']+n
    for k,c in enumerate(record['callers']):
        for n in [0,c['bytes']-1]:changes[f'caller{k} byte{n}']=c['file_offset']+n
        changes[f'caller{k} FDE']=c['records']['fde']['file_offset']+12
    for at in CALLS:
        c=next(c for c in record['callers'] if c['begin']<=at<c['end']);changes[f'call {at:x}']=c['file_offset']+at-c['begin']+1
    rejected={}
    for name,at in changes.items():
        altered=bytearray(data);altered[at]^=1
        try:
            other=inspect(bytes(altered));require({k:v for k,v in other.items() if k!='target_sha256'}=={k:v for k,v in record.items() if k!='target_sha256'},'structural drift')
        except ValueError as error:rejected[name]=str(error)
        else:raise ValueError('accepted corruption '+name)
    record['corruption_controls']=rejected;return record


def main():
    p=argparse.ArgumentParser();p.add_argument('--freeze',action='store_true');args=p.parse_args();record=validate()
    if args.freeze:
        with (PACKET/'static.json').open('xb') as f:f.write(encoded(record))
    else:require(encoded(record)==(PACKET/'static.json').read_bytes(),'static drift')
    print(json.dumps({'member_instructions':[len(m['instructions']) for m in record['members']],'caller_bytes':sum(c['bytes'] for c in record['callers']),'caller_instructions':sum(len(c['instructions']) for c in record['callers']),'controls':len(record['corruption_controls'])}))


if __name__=='__main__':main()
