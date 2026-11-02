#!/usr/bin/env python3
"""Full-target-bound static leaf/caller/FDE evidence; no target execution."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
sys.path.insert(0,str(ROOT/"tools"))
from elf_index import sections
from fde_extents import eh_frame_records

TARGET=ROOT/"artifacts/node/94/hl-node"
SHA="3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
WINDOWS={'select':(0x15d65b0,0x15d65f3,'f8548c0db5a25d2029154e8376b5552643221c8cc6cbab4e7b719fd502ea745e')}
CALLS={}
ENTRIES=(0x15d65b0,)
FDE_BYTES={'select':'1000000064d8010030788d004300000000000000'}
CIE_BYTES={13505816:'1400000000000000017a5200017810011b0c070890010000'}
NEXT_FDE=(13626764,0x15d6600,0x15d6603,'1000000078d801006c788d000300000000000000')
SLOTS={0x5676ba8:(134960,0x15d3e70),0x5676c20:(135224,0x15d44e0),0x5678ee8:(145424,0x15d65b0)}

def require(ok,message):
    if not ok: raise ValueError(message)


def sha(data): return hashlib.sha256(data).hexdigest()


def read(data,secs,va,size):
    found=[s for s in secs if s['type']!=8 and s['address']<=va and va+size<=s['address']+s['size']]
    require(len(found)==1,"file mapping")
    offset=found[0]['offset']+va-found[0]['address']
    return bytes(data[offset:offset+size]),offset


def inspect(data,authenticate=True):
    if authenticate:
        require(len(data)==91774280,"target size")
        require(sha(data)==SHA,"target SHA-256")
    secs=sections(data)
    require(len({s['name'] for s in secs})==len(secs),"duplicate section names")
    eh=next(s for s in secs if s['name']=='.eh_frame')
    require(bytes(data[eh['offset']:eh['offset']+24])==bytes.fromhex('1400000000000000017a5200017810011b0c070890010000'),'CIE bytes')
    for va,expected in CIE_BYTES.items():
        require(read(data,secs,va,len(bytes.fromhex(expected)))[0].hex()==expected,'bound CIE bytes')
    cies,fdes=eh_frame_records(data,secs)
    require((len(cies),len(fdes))==(3,121299),"complete CIE/FDE count")
    records={}
    for name,(start,end,digest) in WINDOWS.items():
        raw,off=read(data,secs,start,end-start)
        require(sha(raw)==digest,f"{name} body")
        overlaps=[f for f in fdes if f['start']<end and start<f['end']]
        require(len(overlaps)==1 and (overlaps[0]['start'],overlaps[0]['end'])==(start,end),f"{name} FDE overlap")
        fde=overlaps[0]
        record_off=read(data,secs,fde['fde'],4)[1]
        record_len=struct.unpack_from('<I',data,record_off)[0]+4
        require(bytes(data[record_off:record_off+record_len]).hex()==FDE_BYTES[name],f'{name} FDE bytes')
        records[name]={"start":hex(start),"end":hex(end),"file_offset":hex(off),"bytes":len(raw),
                       "sha256":digest,"hex":raw.hex(),"overlaps":[{k:hex(v) if isinstance(v,int) else v for k,v in fde.items()}],
                       "fde_section_offset":hex(fde['fde']-eh['address']),
                       "fde_hex":bytes(data[record_off:record_off+record_len]).hex()}
    padding=[]
    for va,raw in ((0x15d65f3,b"\xcc"*13),):
        require(read(data,secs,va,len(raw))[0]==raw,"alignment padding")
        padding.append({"va":hex(va),"hex":raw.hex()})
    nva,nstart,nend,nhex=NEXT_FDE
    require(read(data,secs,nva,len(bytes.fromhex(nhex)))[0].hex()==nhex,'next FDE bytes')
    next_frame=[f for f in fdes if f['fde']==nva]
    require(len(next_frame)==1 and (next_frame[0]['start'],next_frame[0]['end'])==(nstart,nend),'next FDE extent')
    require(nstart==WINDOWS['select'][1]+13,'adjacent padding boundary')
    calls=[]
    for site,target in CALLS.items():
        raw,_=read(data,secs,site,5)
        require(raw[0]==0xe8 and site+5+struct.unpack_from('<i',raw,1)[0]==target,"shared-caller call")
        calls.append({"site":hex(site),"target":hex(target),"hex":raw.hex()})
    text=next(s for s in secs if s['name']=='.text')
    code=bytes(data[text['offset']:text['offset']+text['size']]);direct={};pos=0
    while (pos:=code.find(b'\xe8',pos))>=0:
        if pos+5<=len(code) and text['address']+pos+5+struct.unpack_from('<i',code,pos+1)[0] in ENTRIES:
            direct[text['address']+pos]=text['address']+pos+5+struct.unpack_from('<i',code,pos+1)[0]
        pos+=1
    require(direct==CALLS,'direct call census')
    jumps=[];pos=0
    while (pos:=code.find(b'\xe9',pos))>=0:
        if pos+5<=len(code) and text['address']+pos+5+struct.unpack_from('<i',code,pos+1)[0] in ENTRIES:
            jumps.append(text['address']+pos)
        pos+=1
    require(not jumps,'direct jump census')
    naming=[];count=0;writers={slot:[] for slot in SLOTS}
    for sec in secs:
        if sec['type']!=4: continue
        require(sec['size']%24==0,"RELA size")
        for off in range(sec['offset'],sec['offset']+sec['size'],24):
            slot,info,addend=struct.unpack_from('<QQq',data,off);count+=1
            require((info & 0xffffffff) in (1,6,7,8,18),'relocation width/type')
            require(not any(slot<end and start<slot+8 for start,end,_ in WINDOWS.values()),'protected code relocation')
            if addend in ENTRIES: naming.append([slot,info,addend])
            for address in SLOTS:
                if slot<address+8 and address<slot+8:
                    writers[address].append({'file_offset':off,'destination':slot,'info':info,'addend':addend,'raw':bytes(data[off:off+24]).hex()})
    require(count==80300,'RELA count')
    require(naming==[[0x5678ee8,8,0x15d65b0]],"naming relocation")
    slots={}
    phoff=struct.unpack_from('<Q',data,32)[0]
    phsize,phcount=struct.unpack_from('<HH',data,54)
    require(phsize==56,'program header size')
    segments=[struct.unpack_from('<IIQQQQQQ',data,phoff+i*phsize) for i in range(phcount)]
    for address,(rela_off,addend) in SLOTS.items():
        raw,off=read(data,secs,address,8)
        require(raw==bytes(8),'slot raw bytes')
        section=next(s for s in secs if s['name']=='.data.rel.ro')
        require(section['address']<=address and address+8<=section['address']+section['size'],'slot section')
        mapped=[s for s in segments if s[0]==1 and s[3]<=address and address+8<=s[3]+s[5]]
        require(len(mapped)==1 and mapped[0][2]+address-mapped[0][3]==off,'slot load segment')
        expected=struct.pack('<QQq',address,8,addend).hex()
        require(writers[address]==[{'file_offset':rela_off,'destination':address,'info':8,'addend':addend,'raw':expected}],'slot relocation closure')
        slots[hex(address)]={'raw_hex':raw.hex(),'file_offset':hex(off),'section':section,'load_segment':mapped[0],'writers':writers[address]}
    for site,address in ((0x15d65e3,0x5676ba8),(0x15d65eb,0x5676c20)):
        raw,_=read(data,secs,site,7)
        require(raw[:3]==b'\x48\x8d\x15' and site+7+struct.unpack_from('<i',raw,3)[0]==address,'LEA numeric address')
    return {"target_sha256":SHA,"target_size":len(data),"coordinate_system":"linked ELF VA; file offsets resolved from sections",
            "windows":records,"padding":padding,"direct_calls":calls,"direct_e9_candidates":jumps,
            "adjacent_fde_boundary_only":{"record_va":hex(nva),"start":hex(nstart),"end":hex(nend),"hex":nhex},"text_bytes_scanned":len(code),
            "unwind":{"shared_cie_hex":bytes(data[eh['offset']:eh['offset']+24]).hex(),"cies":len(cies),"fdes":len(fdes),"complete_fde_records_sha256":sha(json.dumps(fdes,sort_keys=True,separators=(',',':')).encode())},
            "address_slots":slots,"rela_entries_scanned":count,"naming_relocations":naming,"captured_execution":False,"instruction_emulation":False}


def decode_rows(raw,start,end):
    rows=[]
    for line in raw.splitlines():
        m=re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(.*)$',line)
        if not m: continue
        va,encoded,asm=int(m[1],16),bytes.fromhex(m[2]),m[3].strip()
        if asm: rows.append([va,encoded,asm])
        else:
            require(rows and rows[-1][0]+len(rows[-1][1])==va,"decoder continuation")
            rows[-1][1]+=encoded
    cursor=start
    for va,encoded,_ in rows:
        require(va==cursor,"decoder gap");cursor+=len(encoded)
    require(cursor==end,"decoder endpoint")
    return rows


def collect(out):
    data=TARGET.read_bytes();record=inspect(data);out.mkdir(parents=True,exist_ok=True)
    gnu=os.environ.get('GNU_OBJDUMP','/opt/homebrew/opt/binutils/bin/objdump')
    llvm=os.environ.get('LLVM_OBJDUMP','/usr/bin/objdump')
    for name,(start,end,_) in WINDOWS.items():
        partitions=[]
        for flavor,tool in (('gnu',gnu),('llvm',llvm)):
            raw=subprocess.check_output([tool,'-d',f'--start-address={start:#x}',f'--stop-address={end:#x}','artifacts/node/94/hl-node'],cwd=ROOT,text=True)
            rows=decode_rows(raw,start,end)
            require(b''.join(row[1] for row in rows).hex()==record['windows'][name]['hex'],'decoder bytes')
            partitions.append([(va,b.hex()) for va,b,_ in rows])
            (out/f'{name}-{flavor}.txt').write_text(raw)
        require(partitions[0]==partitions[1],'decoder partition disagreement')
        if any(start<=site<end for site in CALLS):
            starts={va for va,_ in partitions[0]}
            require({v for v in CALLS if start<=v<end}<=starts,'caller call boundaries')
        record['windows'][name]['instructions']=len(partitions[0])
    process=subprocess.Popen([gnu,'--dwarf=frames','artifacts/node/94/hl-node'],cwd=ROOT,stdout=subprocess.PIPE,text=True)
    kept=[];keep=False
    for line in process.stdout:
        if re.match(r'^[0-9a-f]{8} ',line):
            keep=line.startswith(('00000000 ', '0001d860 ', '0001d874 '))
        if keep: kept.append(line)
    require(process.wait()==0,'GNU frames')
    frames=''.join(kept)
    for _,(start,end,_) in WINDOWS.items():
        require(f'pc={start:016x}..{end:016x}' in frames,'GNU FDE extent')
    (out/'frames.txt').write_text(frames)
    (out/'records.json').write_text(json.dumps(record,sort_keys=True,indent=2)+'\n')
    print('PASS static: complete 67-byte selector; dual decoders; 121299-FDE overlap scan; 13-byte padding; zero E8/E9 candidates; one entry slot and two numeric LEA addresses with complete RELA writers')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',type=Path,required=True)
    collect(parser.parse_args().out)
