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
WINDOWS={'gate':(0x50a90a0,0x50a910d,'72fec1b3a3c1f9303b45408ee5fadd30441760773151ea8f28b8dffdaf5f5f67'),
         'helper':(0x5334d60,0x5334d65,'7d404f20c563df12c54c5be5bd63f49759a02ed5507df5d1b4f512735dc1e703')}
CALLS={0x50a90fb:0x5334d60}
ENTRIES=(0x50a90a0,0x5334d60)
FDE_BYTES={'gate':'18000000cc572900b82313046d00000000024d0e1083025f0e080000',
           'helper':'10000000c8fd2a007c3a3a040500000000000000'}
CIE_BYTES={13505816:'1400000000000000017a5200017810011b0c070890010000'}
HELPER_CANDIDATES=[83531319, 83563689, 83566994, 83567058, 83568039, 83568343, 83568463, 83575248, 83637447, 83638659, 83658701, 83661381, 83695296, 83720943, 83734572, 83749063, 83766904, 83828243, 84072685, 84103890, 84104883, 84105535, 84106904, 84106951, 84107736, 84108900, 84117672, 84122438, 84125707, 84144658, 84152515, 84158951, 84159064, 84159883, 84164337, 84180013, 84180056, 84193232, 84194287, 84207530, 84221390, 84228106, 84228269, 84228983, 84236985, 84318614, 84323401, 84578555, 84586310, 84586375, 84600932, 84605514, 84616305, 84634479, 84646895, 84648646, 84673519, 84677848, 84687374, 84690519, 84697301, 84707846, 84718930, 84813532, 84820197, 84822796, 84831097, 84833088, 84834119, 84840253, 84844260, 84845231, 84852732, 84855505, 84983209, 84984215, 84985007, 84985108, 84985521, 84987157, 84999653, 85001057, 85113947, 85114287, 85125050, 85130266, 85136896, 85139043, 85153793, 85241255, 85255361, 85409149, 85412100, 85419008, 85459108, 85459163, 85460346, 85460429, 85460483, 85467481, 85779876, 85810738, 85939630, 85952530, 86076771, 86088497, 86102881, 86103646, 86134958, 86170480, 86171651, 86731785, 86731919, 88286904, 88286977, 88287223]

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
    for va,raw in ((0x50a910d,b'\xcc'*3),):
        require(read(data,secs,va,len(raw))[0]==raw,"alignment padding")
        padding.append({"va":hex(va),"hex":raw.hex()})
    calls=[]
    for site,target in CALLS.items():
        raw,_=read(data,secs,site,5)
        require(raw[0]==0xe8 and site+5+struct.unpack_from('<i',raw,1)[0]==target,"closed helper call")
        calls.append({"site":hex(site),"target":hex(target),"hex":raw.hex()})
    text=next(s for s in secs if s['name']=='.text')
    code=bytes(data[text['offset']:text['offset']+text['size']]);direct={};pos=0
    while (pos:=code.find(b'\xe8',pos))>=0:
        if pos+5<=len(code) and text['address']+pos+5+struct.unpack_from('<i',code,pos+1)[0] in ENTRIES:
            direct[text['address']+pos]=text['address']+pos+5+struct.unpack_from('<i',code,pos+1)[0]
        pos+=1
    require(not any(t==0x50a90a0 for t in direct.values()),'primary direct call census')
    require(sorted(site for site,t in direct.items() if t==0x5334d60)==HELPER_CANDIDATES,'helper E8 candidate census')
    naming=[];count=0
    for sec in secs:
        if sec['type']!=4: continue
        require(sec['size']%24==0,"RELA size")
        for off in range(sec['offset'],sec['offset']+sec['size'],24):
            slot,info,addend=struct.unpack_from('<QQq',data,off);count+=1
            require((info & 0xffffffff) in (1,6,7,8,18),'relocation width/type')
            require(not any(slot<end and start<slot+8 for start,end,_ in WINDOWS.values()),'protected code relocation')
            if addend in ENTRIES: naming.append([slot,info,addend])
    require(count==80300,'RELA count')
    require(not naming,"naming relocation")
    return {"target_sha256":SHA,"target_size":len(data),"coordinate_system":"linked ELF VA; file offsets resolved from sections",
            "windows":records,"padding":padding,"closed_calls":calls,"primary_direct_e8_candidates":[],
            "helper_direct_e8_candidates":[hex(v) for v in HELPER_CANDIDATES],
            "helper_candidate_scope":"Only the internal call boundary is decoded here; other candidate users are not reconstructed.","text_bytes_scanned":len(code),
            "unwind":{"shared_cie_hex":bytes(data[eh['offset']:eh['offset']+24]).hex(),"cies":len(cies),"fdes":len(fdes),"complete_fde_records_sha256":sha(json.dumps(fdes,sort_keys=True,separators=(',',':')).encode())},
            "rela_entries_scanned":count,"naming_relocations":naming,"captured_execution":False,"instruction_emulation":False}


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
            keep=line.startswith(('00000000 ', '002957c8 ', '002afdc4 '))
        if keep: kept.append(line)
    require(process.wait()==0,'GNU frames')
    frames=''.join(kept)
    for _,(start,end,_) in WINDOWS.items():
        require(f'pc={start:016x}..{end:016x}' in frames,'GNU FDE extent')
    (out/'frames.txt').write_text(frames)
    (out/'records.json').write_text(json.dumps(record,sort_keys=True,indent=2)+'\n')
    print('PASS static: complete 109-byte gate plus actual 5-byte helper; dual decoders; 121299-FDE overlap scan; sole closed call; zero primary E8 candidates and zero naming relocations')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',type=Path,required=True)
    collect(parser.parse_args().out)
