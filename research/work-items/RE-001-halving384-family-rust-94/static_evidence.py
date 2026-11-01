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
WINDOWS={'core': (90532640, 90532793, 'ac1a4de7d7393314de866969bf7c157b0ec76317aa8e178f861641e9dd99dd5f'), 'single': (90532800, 90532906, '3023249399a1b9f302ab5d74c577e1e4916e94be87aaa53cd7d57d289f170447'), 'repeated': (90532512, 90532619, '26d219092674442e62a753c2f74084a7a1d36e0da4c724c938b2a027d941737d'), 'caller_a': (90466816, 90467170, '6bbcc26a1275eee84aed2e634748a648c8a1112f023e0a96a0a27cdbd6530aeb'), 'caller_b': (90491456, 90492862, '4b9557688c901fb9b995273136ad925492d0fd08be2a42c2cf4a7fd3d02c10e1')}
CALLS={0x5656ac6:0x5656b20,0x5656be9:0x5656b20,0x5646ad4:0x5656bc0,0x5646af7:0x5656bc0,0x564ce07:0x5656bc0,0x564ce31:0x5656bc0}
ENTRIES=(0x5656b20,0x5656bc0,0x5656aa0)
FDE_BYTES={'core': '1000000018b22d00eca369049900000000000000', 'single': '400000002cb22d0078a469046a00000000450e108602410e188303420e208c04420e288d05420e308e06420e388f07410e407bcf45ce45cd45cc45c345c6450e08000000', 'repeated': '40000000d4b12d00b0a369046b00000000450e108602410e188303420e208c04420e288d05420e308e06420e388f07410e407ccf45ce45cd45cc45c345c6450e08000000', 'caller_a': '4c000000d8972d000cbd68046201000000420e108f02420e188e034c0e208d04450e288c05440e308606460e388307470ea002032c010a0e38410e30410e28420e20420e18420e10420e08410b000000', 'caller_b': '4c00000030a32d00f41169047e05000000420e108f02450e188e03420e208d04490e288c05410e3086064b0e3883074a0ec0080346050a0e38410e30410e28420e20420e18420e10420e08410b000000'}
CIE_BYTES={13505816:'1400000000000000017a5200017810011b0c070890010000'}
NEXT_FDE=(16500612, 90532928, 90533124, '4000000070b22d00b4a46904c400000000450e108602410e188303420e208c04420e288d05420e308e06420e388f07410e400295cf45ce45cd45cc45c345c6450e080000')

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
    for va,raw in ((90532619,bytes.fromhex('9066662e0f1f840000000000660f1f840000000000')),(90532793,bytes.fromhex('90660f1f440000')),(90532906,bytes.fromhex('9066662e0f1f840000000000662e0f1f840000000000')),):
        require(read(data,secs,va,len(raw))[0]==raw,"alignment padding")
        padding.append({"va":hex(va),"hex":raw.hex()})
    nva,nstart,nend,nhex=NEXT_FDE
    require(read(data,secs,nva,len(bytes.fromhex(nhex)))[0].hex()==nhex,'next FDE bytes')
    next_frame=[f for f in fdes if f['fde']==nva]
    require(len(next_frame)==1 and (next_frame[0]['start'],next_frame[0]['end'])==(nstart,nend),'next FDE extent')
    require(nstart==WINDOWS['single'][1]+22,'adjacent padding boundary')
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
        if any(start<=site<end for site in CALLS):
            starts={va for va,_ in partitions[0]}
            require({v for v in CALLS if start<=v<end}<=starts,'caller call boundaries')
        record['windows'][name]['instructions']=len(partitions[0])
    process=subprocess.Popen([gnu,'--dwarf=frames','artifacts/node/94/hl-node'],cwd=ROOT,stdout=subprocess.PIPE,text=True)
    kept=[];keep=False
    for line in process.stdout:
        if re.match(r'^[0-9a-f]{8} ',line):
            keep=line.startswith(('00000000 ', '002d97d4 ', '002da32c ', '002db1d0 ', '002db214 ', '002db228 ', '002db26c '))
        if keep: kept.append(line)
    require(process.wait()==0,'GNU frames')
    frames=''.join(kept)
    for _,(start,end,_) in WINDOWS.items():
        require(f'pc={start:016x}..{end:016x}' in frames,'GNU FDE extent')
    (out/'frames.txt').write_text(frames)
    (out/'records.json').write_text(json.dumps(record,sort_keys=True,indent=2)+'\n')
    print('PASS static: complete 366-byte halving family and two callers; dual decoders; all FDE/CIE and RELA records; six E8 calls; zero E9/naming relocations')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',type=Path,required=True)
    collect(parser.parse_args().out)
