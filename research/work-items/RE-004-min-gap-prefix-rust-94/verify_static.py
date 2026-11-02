"""Bind the min-gap prefix helper, all eight callers and the actual memcmp import."""
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
START,END,PLT,GOT=0x5430db0,0x5430e07,0x5660150,0x5778dd0
SITES=[0x522d600,0x52464c1,0x52fa39e,0x531c27c,0x531f8f9,0x53218ee,0x54265c8,0x5426ebd]
RANGES=[
 ('window',START,END,'c2237fb5e818182069d033e6b98b0f2580ec59861c2b77d7434d8bda0d8463f5'),
 ('plt',PLT,PLT+16,'c55439d1b5e351f642c8f59101c7a97e5d8fdfc02e73eef8dab5ba398625bd5d'),
 ('caller0',0x522d4b0,0x522d933,'27aec370d780cdfa7c152e5580650fd1121ed235116ff67bbf78bb21f14252d5'),
 ('caller1',0x52462e0,0x5246a4e,'adbaae3bb009020db6dbdc11887bf929fbe8b73c7dd72624d871ff7b36d2ca7e'),
 ('caller2',0x52fa110,0x52fb0c3,'e7b8244c8bb5f9e94bbbd409369857cf101df83908bd3cf6d5419f87c9f10466'),
 ('caller3',0x531beb0,0x531c7a8,'c2aa2363f1a442f466f7a82a6bb99e96e8ad81e82c5db334264ba1c135826367'),
 ('caller4',0x531f770,0x531ff4f,'3cce3b9b77c55483400202753d590997ae577eb0de23762384c51d5d0abc7767'),
 ('caller5',0x5321720,0x53220a5,'cbd04b28b1e07d59f546898f229bb2bdc23fac65f9768440fa820706a2589d9d'),
 ('caller6',0x5426550,0x5426dff,'7837f88bb240ca1b0362d36a6f77c29ca0fa1056030b482fdf9d5906ecc5ba13'),
 ('caller7',0x5426e40,0x54276ff,'aa1ca0e30940e42ec81b6fced6282879fac25b93683918f7fc259b18c6088f0b'),
]


def require(ok,message):
    if not ok:raise ValueError(message)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()


def listing(path,image,begin,end):
    rows=[];cursor=begin
    for line in path.read_text().splitlines():
        match=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(\S.*)$',line)
        if match:
            address,raw=int(match[1],16),bytes.fromhex(match[2])
            require(address==cursor and address+len(raw)<=end,'listing extent')
            require(image.va_bytes(address,len(raw),executable=True)[0]==raw,'listing bytes')
            rows.append((address,raw));cursor+=len(raw)
    require(cursor==end,'complete listing');return rows


def import_record(data,image):
    sections={s['name']:s for s in image.sections}
    ds,st,vs,vr,dyn=[sections[n] for n in ['.dynsym','.dynstr','.gnu.version','.gnu.version_r','.dynamic']]
    require(ds['type']==11 and ds['entsize']==24 and ds['link']==st['index'],'dynamic symbol table')
    strings=data[st['offset']:st['offset']+st['size']]
    def string(at):
        require(0<=at<len(strings),'dynamic string bounds')
        end=strings.find(b'\0',at);require(end>=at,'terminated dynamic string')
        return strings[at:end].decode('ascii')
    symbol_at=ds['offset']+12*24;symbol=struct.unpack_from('<IBBHQQ',data,symbol_at)
    require(symbol==(152,18,0,0,0,0) and string(symbol[0])=='memcmp','undefined global memcmp FUNC symbol')
    version_at=vs['offset']+12*2
    require(struct.unpack_from('<H',data,version_at)[0]==3,'memcmp version index')
    matching=[];at=vr['offset'];seen=set();end=at+vr['size']
    while True:
        require(at not in seen and vr['offset']<=at and at+16<=end,'version need chain bounds');seen.add(at)
        version,count,file,aux,nxt=struct.unpack_from('<HHIII',data,at)
        require(version==1,'version need format');a=at+aux;seen_aux=set()
        for index in range(count):
            require(a not in seen_aux and vr['offset']<=a and a+16<=end,'version auxiliary bounds');seen_aux.add(a)
            h,flags,other,name,step=struct.unpack_from('<IHHII',data,a)
            if other==3:
                require(string(file)=='libc.so.6' and string(name)=='GLIBC_2.2.5' and flags==0 and h==0x09691a75,'memcmp libc version requirement')
                matching.append({'need_file_offset':at,'need_hex':data[at:at+16].hex(),
                    'aux_file_offset':a,'aux_hex':data[a:a+16].hex(),'library':string(file),'version':string(name),
                    'library_string_file_offset':st['offset']+file,'version_string_file_offset':st['offset']+name})
            if index+1<count:require(step!=0,'version auxiliary premature end')
            a+=step
        if nxt==0:break
        at+=nxt
    require(len(matching)==1,'unique memcmp version')
    needed=[]
    require(dyn['entsize']==16 and dyn['size']%16==0,'dynamic table shape')
    for at in range(dyn['offset'],dyn['offset']+dyn['size'],16):
        tag,value=struct.unpack_from('<qQ',data,at)
        if tag==1 and string(value)=='libc.so.6':needed.append({'file_offset':at,'hex':data[at:at+16].hex()})
    require(len(needed)==1,'libc DT_NEEDED')
    slot,where=image.va_bytes(GOT,8);require(slot==struct.pack('<Q',PLT+6),'file GOT resolver entry')
    plt=image.va_bytes(PLT,16,executable=True)[0]
    require(PLT+6+struct.unpack_from('<i',plt,2)[0]==GOT,'PLT GOT displacement')
    require(plt[6:11]==b'\x68\x06\x00\x00\x00','PLT relocation ordinal')
    require(PLT+16+struct.unpack_from('<i',plt,12)[0]==0x56600e0,'PLT0 target')
    return {'symbol_index':12,'symbol_file_offset':symbol_at,'symbol_hex':data[symbol_at:symbol_at+24].hex(),
        'name':'memcmp','name_file_offset':st['offset']+symbol[0],'version_index_file_offset':version_at,
        'version_index_hex':data[version_at:version_at+2].hex(),'requirement':matching[0],
        'needed':needed[0],'got_va':GOT,'got_file_offset':where['file_offset'],'got_file_hex':slot.hex(),
        'implementation':'external runtime resolution, not captured or reconstructed'}


def inspect(data):
    image=Elf(data,3);cies,frames=eh_frame_records(data);decoder=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
    def frame_record(begin,end):
        overlapping=[f for f in frames if f['start']<end and begin<f['end']]
        require(len(overlapping)==1 and (overlapping[0]['start'],overlapping[0]['end'])==(begin,end),'unique complete FDE')
        frame=overlapping[0];records={}
        for kind in ['fde','cie']:
            address=frame[kind];size=int.from_bytes(image.va_bytes(address,4)[0],'little')+4
            raw,mapping=image.va_bytes(address,size);records[kind]={'va':address,'file_offset':mapping['file_offset'],'hex':raw.hex()}
        return {'frame':frame,'cie':cies[frame['cie']],'records':records}
    bodies={}
    for name,begin,end,digest in RANGES:
        raw,mapping=image.va_bytes(begin,end-begin,executable=True);require(sha(raw)==digest,name+' full body')
        rows=listing(PACKET/(name+'.gnu.txt'),image,begin,end);llvm=listing(PACKET/(name+'.llvm.txt'),image,begin,end)
        joined=[];prefixes=[];index=0
        while index<len(llvm):
            address,value=llvm[index]
            if value==b'\xf0':
                require(index+1<len(llvm) and llvm[index+1][0]==address+1,'LOCK adjacency')
                prefixes.append(address);index+=1;value+=llvm[index][1]
            joined.append((address,value));index+=1
        require(rows==joined,'GNU/LLVM boundaries');decoded=list(decoder.disasm(raw,begin))
        require(rows==[(i.address,bytes(i.bytes)) for i in decoded],'Capstone boundaries')
        if name=='window':
            require([(i.address,i.op_str) for i in decoded if i.mnemonic=='call']==[(0x5430dd7,hex(PLT))],'only memcmp call')
            starts={i.address for i in decoded}
            require(all(int(i.op_str,16) in starts for i in decoded if i.mnemonic.startswith('j')),'branch closure')
            require([i.address for i in decoded if i.mnemonic=='ret']==[END-1],'single return')
        elif name.startswith('caller'):
            require([i.address for i in decoded if i.mnemonic=='call' and i.op_str==hex(START)]==[SITES[int(name[6:])]],'caller target boundary')
        if name=='plt':
            require(not any(f['start']<end and begin<f['end'] for f in frames),'PLT has no FDE');frame={}
        else:frame=frame_record(begin,end)
        bodies[name]={**frame,'begin':begin,'end':end,'bytes':len(raw),'hex':raw.hex(),'sha256':sha(raw),
            'file_offset':mapping['file_offset'],'instruction_starts':[i.address for i in decoded],
            'llvm_joined_lock_prefix_rows':prefixes}
    require(image.va_bytes(START-5,5)[0]==b'\xcc'*5,'leading padding')
    neighbors=[frame_record(0x5430d60,START-5),frame_record(END,0x5430e4c)]
    imported=import_record(data,image);count=0;names=[];got_relocations=[]
    for section in image.sections:
        require(section['type']!=9,'unsupported REL table')
        if section['type']!=4:continue
        require(section['entsize']==24 and section['size']%24==0,'RELA shape')
        for at in range(section['offset'],section['offset']+section['size'],24):
            dest,info,addend=struct.unpack_from('<QQq',data,at);kind=info&0xffffffff;count+=1
            require(kind in [1,6,7,8,18],'unreviewed relocation width')
            require(not any(dest<b and a<dest+8 for _,a,b,_ in RANGES),'code relocation')
            if addend==START:names.append(dest)
            if dest==GOT:
                require(section['name']=='.rela.plt' and info==(12<<32)|7 and addend==0,'memcmp JUMP_SLOT binding')
                got_relocations.append({'file_offset':at,'hex':data[at:at+24].hex(),'symbol':12,'kind':7,'addend':0})
    require(not names and len(got_relocations)==1,'entry names/unique GOT relocation');imported['relocation']=got_relocations[0]
    text=next(s for s in image.sections if s['name']=='.text');code=image.va_bytes(text['address'],text['size'],executable=True)[0];edges={}
    for opcode in [b'\xe8',b'\xe9']:
        hits=[];position=0
        while (position:=code.find(opcode,position))>=0:
            if position+5<=len(code) and text['address']+position+5+struct.unpack_from('<i',code,position+1)[0]==START:hits.append(text['address']+position)
            position+=1
        edges[opcode.hex()]=hits
    require(edges=={'e8':SITES,'e9':[]},'direct candidate census')
    return {'target_sha256':sha(data),'target_bytes':len(data),'bodies':bodies,'neighbors':neighbors,
        'leading_padding_hex':'cc'*5,'following_padding_hex':'','import':imported,'rela_records_checked':count,
        'naming_relocations':names,'direct_encoding_candidates':edges,'complete_xref_census':False,
        'capstone_version':capstone.__version__,'external_semantic_premise':'standard normal-return readonly memcmp, zero iff all selected bytes equal',
        'captured_execution':False,'instruction_emulation':False}


def validate():
    data=(ROOT/'artifacts/node/94/hl-node').read_bytes();require(len(data)==91774280 and sha(data)==TARGET,'target identity')
    record=inspect(data);leaf=record['bodies']['window'];base=leaf['file_offset'];i=record['import']
    changes={f'leaf operand+{n}':base+n for n in [13,17,20,24,29,32,35,38,40,45,49,54,60,64,71,75,79]}
    changes.update({'leaf FDE':leaf['records']['fde']['file_offset']+12,'leaf CIE':leaf['records']['cie']['file_offset']+15,
        'leading padding':base-1,'next FDE':record['neighbors'][1]['records']['fde']['file_offset']+8,
        'PLT operand':record['bodies']['plt']['file_offset']+2,'GOT resolver':i['got_file_offset'],
        'JUMP_SLOT symbol':i['relocation']['file_offset']+12,'symbol name':i['name_file_offset'],
        'symbol type':i['symbol_file_offset']+4,'version index':i['version_index_file_offset'],
        'version string':i['requirement']['version_string_file_offset'],'libc library string':i['requirement']['library_string_file_offset'],
        'version auxiliary':i['requirement']['aux_file_offset'],'DT_NEEDED':i['needed']['file_offset']+8})
    for index,site in enumerate(SITES):
        caller=record['bodies'][f'caller{index}']
        changes[f'caller{index} call']=caller['file_offset']+site-caller['begin']+1
        changes[f'caller{index} FDE']=caller['records']['fde']['file_offset']+12
    rejected={}
    for name,offset in changes.items():
        changed=bytearray(data);changed[offset]^=1
        try:inspect(bytes(changed))
        except (ValueError,UnicodeError) as error:rejected[name]=str(error)
        else:raise ValueError('accepted corruption '+name)
    record['corruption_controls']=rejected;return record


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--freeze',action='store_true');args=parser.parse_args()
    record=validate();raw=encoded(record)
    if args.freeze:
        with (PACKET/'static.json').open('xb') as file:file.write(raw)
    else:require((PACKET/'static.json').read_bytes()==raw,'static drift')
    print(json.dumps({'instructions':{k:len(v['instruction_starts']) for k,v in record['bodies'].items()},'controls':len(record['corruption_controls'])}))


if __name__=='__main__':main()
