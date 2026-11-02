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
WINDOWS={'helper': (90561920, 90561989, '5fdf7149a0b8f4b6f350f26651c2b5363ea63d4ffd6d461b8baf7244407afa82'), 'wrapper': (90512976, 90513080, '2a4bfc093eb4f0e2e3481512ef84ba762d2e82822806d8bbef66d2362cc13d7b'), 'caller_a': (90507200, 90507601, 'c0a780b952fbef66271feaaf65448e06cbbcc698aaa15c0309fa881971495c3d'), 'caller_b': (90508192, 90508593, '52fcebbdf98fec78b28b8c6599cd829f33fe7bf533d3160211cf7dd7a530125a'), 'caller_wrapper': (90443424, 90443782, 'f75cf43d17e7717f2b5f1c81f4516f55cd48cd465829f26ddc9593b37e697cd6')}
CALLS={0x56508a6:0x565dd80,0x5650c86:0x565dd80,0x5651e5f:0x565dd80,0x5640f59:0x5651e50,0x5640f80:0x5651e50}
ENTRIES=(0x565dd80,0x5651e50)
FDE_BYTES={'helper': '1000000038c32d002c056a044500000000000000', 'wrapper': '180000002cae2d00085b69046800000000450e10830202620e080000', 'caller_a': '6c00000030a92d00744969049101000000460e108e02450e188d03420e208c04440e288605440e308306470e60025c0a0e30410e28410e20420e18420e10420e08480b02cc0a0e30410e28410e20420e18420e10420e084c0b540a0e30440e28410e20420e18420e10420e08450b0000', 'caller_b': '6c00000004ab2d00804b69049101000000460e108e02450e188d03420e208c04440e288605440e308306470e60025c0a0e30410e28410e20420e18420e10420e08480b02cc0a0e30410e28410e20420e18420e10420e084c0b540a0e30440e28410e20420e18420e10420e08450b0000', 'caller_wrapper': '48000000a48c2d00e06c68046601000000460e108f02420e188e03450e208d04450e288c05440e308606440e388307470ea00402510a0e38410e30410e28420e20420e18420e10420e08440b'}
CIE_BYTES={13505816:'1400000000000000017a5200017810011b0c070890010000'}
NEXT_FDE=(16504928, 90562016, 90562158, '240000004cc32d0078056a048e00000000450e108602410e188303440e200278c345c6450e080000')
BOUND_VA=0x9186a0
BOUND_HEX="01000000fffffffffe5bfeff02a4bd5305d8a10908d83933487d9d2953a7ed73"
LEAS=(0x565089c,0x5650c7c,0x5651e55)

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
    for va,raw in ((0x565ddc5,bytes.fromhex('9066662e0f1f84000000000066662e0f1f8400000000000f1f4000')),):
        require(read(data,secs,va,len(raw))[0]==raw,"alignment padding")
        padding.append({"va":hex(va),"hex":raw.hex()})
    nva,nstart,nend,nhex=NEXT_FDE
    require(read(data,secs,nva,len(bytes.fromhex(nhex)))[0].hex()==nhex,'next FDE bytes')
    next_frame=[f for f in fdes if f['fde']==nva]
    require(len(next_frame)==1 and (next_frame[0]['start'],next_frame[0]['end'])==(nstart,nend),'next FDE extent')
    require(nstart==WINDOWS['helper'][1]+27,'adjacent padding boundary')
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
    naming=[];count=0;writers=[]
    for sec in secs:
        if sec['type']!=4: continue
        require(sec['size']%24==0,"RELA size")
        for off in range(sec['offset'],sec['offset']+sec['size'],24):
            slot,info,addend=struct.unpack_from('<QQq',data,off);count+=1
            require((info & 0xffffffff) in (1,6,7,8,18),'relocation width/type')
            require(not any(slot<end and start<slot+8 for start,end,_ in WINDOWS.values()),'protected code relocation')
            if addend in ENTRIES: naming.append([slot,info,addend])
            if slot<BOUND_VA+32 and BOUND_VA<slot+8: writers.append([slot,info,addend])
    require(count==80300,'RELA count')
    require(not naming,"naming relocation")
    require(not writers,'constant relocation writers')
    raw,off=read(data,secs,BOUND_VA,32)
    require(raw.hex()==BOUND_HEX,'bound bytes')
    section=next(s for s in secs if s['name']=='.rodata')
    require(section['address']<=BOUND_VA and BOUND_VA+32<=section['address']+section['size'],'bound section')
    phoff=struct.unpack_from('<Q',data,32)[0];phsize,phcount=struct.unpack_from('<HH',data,54)
    require(phsize==56,'program header size')
    segments=[struct.unpack_from('<IIQQQQQQ',data,phoff+i*phsize) for i in range(phcount)]
    mapped=[s for s in segments if s[0]==1 and s[3]<=BOUND_VA and BOUND_VA+32<=s[3]+s[5]]
    require(len(mapped)==1 and mapped[0][2]+BOUND_VA-mapped[0][3]==off and mapped[0][1]==4,'bound load segment')
    leas=[]
    for site in LEAS:
        encoded,_=read(data,secs,site,7)
        require(encoded[:3]==b'\x48\x8d\x35' and site+7+struct.unpack_from('<i',encoded,3)[0]==BOUND_VA,'bound LEA')
        leas.append({'site':hex(site),'hex':encoded.hex(),'target':hex(BOUND_VA)})
    bound={'va':hex(BOUND_VA),'file_offset':hex(off),'hex':raw.hex(),'section':section,'load_segment':mapped[0],'writers':writers,'leas':leas}
    return {"target_sha256":SHA,"target_size":len(data),"coordinate_system":"linked ELF VA; file offsets resolved from sections",
            "bound":bound,"windows":records,"padding":padding,"direct_calls":calls,"direct_e9_candidates":jumps,
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
            keep=line.startswith(('00000000 ', '002d8ca0 ', '002da92c ', '002dab00 ', '002dae28 ', '002dc334 ', '002dc348 '))
        if keep: kept.append(line)
    require(process.wait()==0,'GNU frames')
    frames=''.join(kept)
    for _,(start,end,_) in WINDOWS.items():
        require(f'pc={start:016x}..{end:016x}' in frames,'GNU FDE extent')
    (out/'frames.txt').write_text(frames)
    (out/'records.json').write_text(json.dumps(record,sort_keys=True,indent=2)+'\n')
    print('PASS static: 173-byte helper/wrapper closure; three other complete callers; bound constant and 5 E8 sites; dual decoders; complete FDE/RELA inventories')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',type=Path,required=True)
    collect(parser.parse_args().out)
