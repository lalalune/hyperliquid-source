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
WINDOWS={'copy': (83856176, 83856284, '09f5cffe7baf43280ecc81d78940ee5785fb2424db042b4a1b01842d63136657'), 'caller0': (83895088, 83896524, 'd878073e68f8d1b70d784b17f6551d1f9349cf9cf75647ed7bd7f463a96d57e6'), 'caller1': (83896880, 83903164, '6a44218fa2403719934f913776ca0e55a75b8c71c0458383ddbc14c31410c29e'), 'caller2': (84016512, 84024722, '8bf61b6d42a78c62fafa81b37bc0bc310679b9a40f656bf1b81676fe90074799'), 'caller3': (84027440, 84030222, 'bc9bdb9514af9cb02032b2a5a136d1e47788ae64c527935dfe4c3fa185954026'), 'caller4': (84030352, 84034471, 'ce603efb05ef3295703e811522ae0f3aa93c4127431f9060259985c1ad5f7614'), 'caller5': (84034752, 84041590, '8fb2d84f48f50687240042ca3f2a881ee516b7c66e114688e355c0754e62534d'), 'caller6': (84042016, 84052238, '3bb1d3565d4655d0244ceb4e94c4214ad39f3011f0e7359757bfb892f37515f4')}
CALLS={83895288: 83856176, 83901012: 83856176, 83902043: 83856176, 84019143: 83856176, 84029163: 83856176, 84033183: 83856176, 84039921: 83856176, 84049838: 83856176}
FDE_BYTES={'copy': '1000000058f72800bc7e08046c00000000000000', 'caller0': '3800000090640000b4a3cf039c05000004cf6e8cff450e108602430d06428f03458e04488d058c0683070346032ea00102e70a0c0708440b02b32e00', 'caller1': '54000000f464000050aacf038c18000004cb6e8cff450e108602430d06508f038e048d058c06830702e02e2003db032e0002ab2e2002cd0a0c0708450b024f2e0003b90a2ea00102a92e000382032ea00102b12e00000000', 'caller2': '54000000bc7f0000d862d1031220000004b35f8cff450e108602530d06508f038e048d058c06830703bb022e200347010a0c0708460b025e2e0003e1072ea00102c22e000335022e20027c2e0003fa052e207f2e00000000', 'caller3': '3c0000003c800000088dd103de0a00000457608cff410e108602430d06428f03498e048d058c064b830703c6072ea0010350010a0c0708480b02452e00000000', 'caller4': '38000000a08000000498d10317100000044b608cff410e108602430d06488f038e048d058c064b8307033e0c2ea0010364010a0c0708470b702e0000', 'caller5': '4800000000810000d4a8d103b61a00000434608cff410e108602430d06508f038e048d058c06830703420c0a0c07084a0b02e12e20026f2e00028c2e1002812e0003bb062ea00103e0012e00', 'caller6': '5400000070810000c4c4d103ee2700000459608cff410e108602430d06428f03518e048d058c0683070349070a0c0708410b03b2062e2003da032e00037e012e20672e00033a022e2002862e000381092ea00103f7012e00'}
CIE_BYTES={13505816: '1400000000000000017a5200017810011b0c070890010000', 19929832: '1c00000000000000017a504c5200017810079b3d5848041b1b0c070890010000'}

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
    for va,raw in ((0x4ff8b9c,b'\xcc'*4),):
        require(read(data,secs,va,len(raw))[0]==raw,"alignment padding")
        padding.append({"va":hex(va),"hex":raw.hex()})
    calls=[]
    for site,target in CALLS.items():
        raw,_=read(data,secs,site,5)
        require(raw[0]==0xe8 and site+5+struct.unpack_from('<i',raw,1)[0]==target,"shared-caller call")
        calls.append({"site":hex(site),"target":hex(target),"hex":raw.hex()})
    text=next(s for s in secs if s['name']=='.text')
    code=bytes(data[text['offset']:text['offset']+text['size']]);direct=[];pos=0
    while (pos:=code.find(b'\xe8',pos))>=0:
        if pos+5<=len(code) and text['address']+pos+5+struct.unpack_from('<i',code,pos+1)[0]==0x4ff8b30:
            direct.append(text['address']+pos)
        pos+=1
    require(direct==list(CALLS),'direct call census')
    naming=[];count=0
    for sec in secs:
        if sec['type']!=4: continue
        require(sec['size']%24==0,"RELA size")
        for off in range(sec['offset'],sec['offset']+sec['size'],24):
            slot,info,addend=struct.unpack_from('<QQq',data,off);count+=1
            if addend == 0x4ff8b30: naming.append([slot,info,addend])
    require(count==80300,'RELA count')
    require(not naming,"naming relocation")
    return {"target_sha256":SHA,"target_size":len(data),"coordinate_system":"linked ELF VA; file offsets resolved from sections",
            "windows":records,"padding":padding,"direct_calls":calls,"text_bytes_scanned":len(code),
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
        if name.startswith('caller'):
            starts={va for va,_ in partitions[0]}
            require({v for v in CALLS if start<=v<end}<=starts,'caller call boundaries')
        record['windows'][name]['instructions']=len(partitions[0])
    process=subprocess.Popen([gnu,'--dwarf=frames','artifacts/node/94/hl-node'],cwd=ROOT,stdout=subprocess.PIPE,text=True)
    kept=[];keep=False
    for line in process.stdout:
        if re.match(r'^[0-9a-f]{8} ',line):
            keep=line.startswith(('00000000 ', '0028f754 ', '006205d0 ', '00626a5c ', '00626ac0 ', '00628588 ', '00628608 ', '0062866c ', '006286cc ', '0062873c '))
        if keep: kept.append(line)
    require(process.wait()==0,'GNU frames')
    frames=''.join(kept)
    for _,(start,end,_) in WINDOWS.items():
        require(f'pc={start:016x}..{end:016x}' in frames,'GNU FDE extent')
    (out/'frames.txt').write_text(frames)
    (out/'records.json').write_text(json.dumps(record,sort_keys=True,indent=2)+'\n')
    print('PASS static: complete gated block copy and seven callers; dual decoders; 121299-FDE overlap scan; eight direct calls; zero naming relocations')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',type=Path,required=True)
    collect(parser.parse_args().out)
