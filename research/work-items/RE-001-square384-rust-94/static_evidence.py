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
WINDOWS={'square': (90552320, 90552848, 'be01d04ac9e19b01b6e569c1c2e73584596b002c614c1e3f25c599e440781556'), 'caller_0': (90552224, 90552300, 'd63c7c79397579c6316c51a5bf6c3a22a7c776eb1ee946ba03d832a224fcbdc6'), 'caller_1': (90552864, 90552986, '5b98e1b9ccc99b60b015939af80c8396f9226e602da3e563acb2ee4a68c2add2'), 'caller_2': (90556704, 90556878, '45d2a6108184da1eb3cd8416b5819809d0611e3575a1db527c4d10882bf88bb8'), 'caller_3': (90556896, 90557112, '0f3a74d3c66bd51adfbd6c0ef5e1c13fc219d2413f60c1ee00bc82b80992e80c')}
CALLS={90552258: 90552320, 90552916: 90552320, 90556774: 90552320, 90556966: 90552320}
JUMPS={}
ENTRIES=(0x565b800,)
FDE_BYTES={'square': '1000000028be2d00bce469041002000000000000', 'caller_0': '40000000e4bd2d00a0e469044c00000000550e108602410e188303420e208c04420e288d05420e308e06420e388f07440e404acf45ce45cd45cc45c345c6450e08000000', 'caller_1': '400000003cbe2d00c8e669047a00000000550e108602410e188303420e208c04420e288d05420e308e06420e388f07440eb0017ecf44ce44cd44cc44c344c6440e080000', 'caller_2': '4000000010c02d00f4f36904ae00000000550e108602410e188303420e208c04420e288d05420e308e06420e388f07470ec001026fcf44ce44cd44cc44c344c6440e0800', 'caller_3': '4000000054c02d0070f46904d800000000550e108602410e188303420e208c04420e288d05420e308e06420e388f07470ec0010299cf44ce44cd44cc44c344c6440e0800'}
CIE_BYTES={13505816:'1400000000000000017a5200017810011b0c070890010000'}
NEXT_FDE=(16503632, 90552864, 90552986, '400000003cbe2d00c8e669047a00000000550e108602410e188303420e208c04420e288d05420e308e06420e388f07440eb0017ecf44ce44cd44cc44c344c6440e080000')

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
    for va,raw in ((0x565ba10,bytes.fromhex('9066662e0f1f8400000000000f1f4000')),):
        require(read(data,secs,va,len(raw))[0]==raw,"alignment padding")
        padding.append({"va":hex(va),"hex":raw.hex()})
    nva,nstart,nend,nhex=NEXT_FDE
    require(read(data,secs,nva,len(bytes.fromhex(nhex)))[0].hex()==nhex,'next FDE bytes')
    next_frame=[f for f in fdes if f['fde']==nva]
    require(len(next_frame)==1 and (next_frame[0]['start'],next_frame[0]['end'])==(nstart,nend),'next FDE extent')
    require(nstart==WINDOWS['square'][1]+16,'adjacent padding boundary')
    calls=[]
    for site,target in CALLS.items():
        raw,_=read(data,secs,site,5)
        require(raw[0]==0xe8 and site+5+struct.unpack_from('<i',raw,1)[0]==target,"shared-caller call")
        calls.append({"site":hex(site),"target":hex(target),"hex":raw.hex()})
    text=next(s for s in secs if s['name']=='.text')
    code=bytes(data[text['offset']:text['offset']+text['size']]);direct={};pos=0
    while (pos:=code.find(b'\xe8',pos))>=0:
        if pos+5<=len(code) and 0x565b800<=text['address']+pos+5+struct.unpack_from('<i',code,pos+1)[0]<0x565ba10:
            direct[text['address']+pos]=text['address']+pos+5+struct.unpack_from('<i',code,pos+1)[0]
        pos+=1
    require(direct==CALLS,'direct call census')
    jumps={};pos=0
    while (pos:=code.find(b'\xe9',pos))>=0:
        if pos+5<=len(code) and 0x565b800<=text['address']+pos+5+struct.unpack_from('<i',code,pos+1)[0]<0x565ba10:
            jumps[text['address']+pos]=text['address']+pos+5+struct.unpack_from('<i',code,pos+1)[0]
        pos+=1
    require(jumps==JUMPS,'direct jump census')
    naming=[];count=0
    for sec in secs:
        if sec['type']!=4: continue
        require(sec['size']%24==0,"RELA size")
        for off in range(sec['offset'],sec['offset']+sec['size'],24):
            slot,info,addend=struct.unpack_from('<QQq',data,off);count+=1
            require((info & 0xffffffff) in (1,6,7,8,18),'relocation width/type')
            require(not any(slot<end and start<slot+8 for start,end,_ in WINDOWS.values()),'protected code relocation')
            if 0x565b800<=addend<0x565ba10: naming.append([slot,info,addend])
    require(count==80300,'RELA count')
    require(not naming,"naming relocation")
    return {"target_sha256":SHA,"target_size":len(data),"coordinate_system":"linked ELF VA; file offsets resolved from sections",
            "windows":records,"padding":padding,"direct_calls":calls,"direct_e9_candidates":jumps,
            "adjacent_fde_boundary_only":{"record_va":hex(nva),"start":hex(nstart),"end":hex(nend),"hex":nhex},"text_bytes_scanned":len(code),
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
        if any(start<=site<end for site in {**CALLS,**JUMPS}):
            starts={va for va,_ in partitions[0]}
            require({v for v in {**CALLS,**JUMPS} if start<=v<end}<=starts,'caller call boundaries')
        record['windows'][name]['instructions']=len(partitions[0])
    process=subprocess.Popen([gnu,'--dwarf=frames','artifacts/node/94/hl-node'],cwd=ROOT,stdout=subprocess.PIPE,text=True)
    kept=[];keep=False
    for line in process.stdout:
        if re.match(r'^[0-9a-f]{8} ',line):
            keep=line.startswith(('00000000 ', '002dbde0 ', '002dbe24 ', '002dbe38 ', '002dc00c ', '002dc050 '))
        if keep: kept.append(line)
    require(process.wait()==0,'GNU frames')
    frames=''.join(kept)
    for _,(start,end,_) in WINDOWS.items():
        require(f'pc={start:016x}..{end:016x}' in frames,'GNU FDE extent')
    (out/'frames.txt').write_text(frames)
    (out/'records.json').write_text(json.dumps(record,sort_keys=True,indent=2)+'\n')
    print('PASS static: complete528-byte scalar square; four full caller contexts/four E8; full CIE/FDE/RELA binding')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',type=Path,required=True)
    collect(parser.parse_args().out)
