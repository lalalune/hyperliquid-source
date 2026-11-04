#!/usr/bin/env python3
"""Static Node115 flag/two-word evidence, never executes the capture."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research/work-items/RE-005-node115-rlp-flag-pair"
TARGET = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
# Root and complete scalar helper are the reconstruction question.
# Four containing callers are context only, not additional implementation credit.
FUNCTIONS = (
 ("flag-pair",0x298f160,0x298f422,"d5718c7c8b9fca5b5da9b61642dafbf3ee92fc8f66e7f78f3152079b15d0dc36"),
 ("word256",0x2a00700,0x2a009a9,"5a0aa38c70cc676c16e85bb670f0a6d28e179e04c3c5e3e83b2562a02a15bc21"),
 ("caller-a",0x2986c90,0x2987130,"4dfb999efe71b512f0dcfe020102cd6ede6d8b6b066fcf943311a7420202d6d9"),
 ("caller-b",0x2987130,0x29875dc,"ecbf083f20ce7f42e3f71c5db7b98c3f98595e60cf99c0d4db1e342f6c8bbdd0"),
 ("caller-c",0x29875e0,0x29879f6,"43d7dcd661ef2bb3c582a8ce273291589e300d75860c878a3c82742ec3dcfa59"),
 ("caller-d",0x2987a00,0x2987e8e,"be331e1a57fdc0faf118b2c83d25cc15ae6315accf472b86daedc1e94bf1130b"),
)
CALLS = ((0x2986efd,0x298f160),(0x298737d,0x298f160),
         (0x29877f5,0x298f160),(0x2987c3d,0x298f160),
         (0x298f1c1,0x2a00700),(0x298f1e7,0x2a00700))
SLOTS = {0x64df508:(6,"memcpy",0),0x64df520:(8,None,0x1681da0),
         0x64df848:(8,None,0x1681e40)}

def body(data, secs, start, end):
    matches=[s for s in secs if s["type"]!=8 and s["flags"]&4
             and s["address"]<=start<end<=s["address"]+s["size"]]
    if len(matches)!=1: raise ValueError("Ambiguous executable extent")
    s=matches[0];off=s["offset"]+start-s["address"]
    return data[off:off+end-start]

def decoded(data, secs, start, end):
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    raw=body(data,secs,start,end)
    instructions=list(Cs(CS_ARCH_X86,CS_MODE_64).disasm(raw,start))
    if sum(i.size for i in instructions)!=len(raw):
        raise ValueError("Incomplete Capstone partition")
    return [{"address":hex(i.address),"bytes":i.bytes.hex(),
             "mnemonic":i.mnemonic,"operands":i.op_str} for i in instructions]

def gnu_rows(text):
    rows=[]
    for line in text.splitlines():
        parts=line.split("\t")
        if len(parts)>=3 and re.fullmatch(r"\s*[0-9a-f]+:",parts[0]):
            if not re.fullmatch(r"(?:[0-9a-f]{2} +)+",parts[1]+" "):
                raise ValueError("Malformed GNU byte row")
            raw=bytes.fromhex(parts[1])
            if not raw: raise ValueError("Empty GNU instruction")
            rows.append((int(parts[0].strip()[:-1],16),raw.hex()))
    return rows

def relocations(data):
    sh=struct.unpack_from("<Q",data,40)[0]
    size,n,ni=struct.unpack_from("<HHH",data,58)
    rows=[struct.unpack_from("<IIQQQQIIQQ",data,sh+i*size) for i in range(n)]
    result={}
    for s in rows:
        if s[1]!=4: continue
        if s[5]%24: raise ValueError("Invalid RELA section extent")
        for off in range(s[4],s[4]+s[5],24):
            slot,info,addend=struct.unpack_from("<QQq",data,off)
            if slot not in SLOTS: continue
            if slot in result: raise ValueError("Duplicate relevant relocation")
            name=None
            if info>>32:
                sym=rows[s[6]];strings=rows[sym[6]]
                no=struct.unpack_from("<I",data,sym[4]+(info>>32)*24)[0]
                at=strings[4]+no
                name=data[at:data.index(b"\0",at)].decode()
            result[slot]=(info&0xffffffff,name,addend)
    if result!=SLOTS: raise ValueError("Indirect helper relocation changed")
    return {hex(k):list(v) for k,v in sorted(result.items())}

def facts(data):
    if len(data)!=105896032 or hashlib.sha256(data).hexdigest()!=TARGET:
        raise ValueError("Wrong complete Node115 artifact")
    secs,table=unwind_index(data)
    _,fdes=eh_frame_records(data,secs)
    by_start={f["start"]:f for f in fdes}
    indexed={f["start"]:f["fde"] for f in table}
    for _,start,end,digest in FUNCTIONS:
        f=by_start.get(start)
        if f is None or f["end"]!=end or indexed.get(start)!=f["fde"]:
            raise ValueError("FDE/header boundary changed")
        if hashlib.sha256(body(data,secs,start,end)).hexdigest()!=digest:
            raise ValueError("Complete body changed")
    for address,target in CALLS:
        owner=next((f for _,s,e,_ in FUNCTIONS for f in [by_start[s]]
                    if s<=address<e),None)
        if owner is None: raise ValueError("Caller outside declared owners")
        rows=decoded(data,secs,owner["start"],owner["end"])
        ins=next((r for r in rows if int(r["address"],16)==address),None)
        if ins is None or ins["mnemonic"]!="call" or ins["operands"]!=hex(target):
            raise ValueError("Unqualified direct call")
    literal=b"invalid bool value, must be 0 or 1"
    s=next(s for s in secs if s["type"]!=8 and
           s["address"]<=0x602150<0x602150+len(literal)<=s["address"]+s["size"])
    off=s["offset"]+0x602150-s["address"]
    if data[off:off+len(literal)]!=literal:raise ValueError("Diagnostic changed")
    return secs,relocations(data)

def verify(data, packet=PACKET):
    secs,slots=facts(data)
    total=0
    for label,start,end,_ in FUNCTIONS:
        expected=decoded(data,secs,start,end)
        stored=json.loads((packet/(label+".capstone.json")).read_text())
        if stored!=expected: raise ValueError("Capstone rows changed: "+label)
        native=gnu_rows((packet/(label+".objdump")).read_text(encoding="utf-8"))
        if native!=[(int(r["address"],16),r["bytes"]) for r in expected]:
            raise ValueError("Independent GNU partition mismatch: "+label)
        total+=len(expected)
    recorded=json.loads((packet/"records.json").read_text())
    if (recorded["targetSha256"]!=TARGET or recorded["relocations"]!=slots
        or recorded["directCalls"]!=[[hex(a),hex(t)] for a,t in CALLS]
        or recorded["sourceBase"]!="05bc2de303c05525b71e7e257426e741bc66a390"
        or recorded["coordinates"]!="linked ELF VA before load bias"
        or recorded["normalizationMasks"]!=[]
        or recorded["capturedCodeExecuted"] is not False):
        raise ValueError("Recorded identity/helper closure changed")
    return {"targetSha256":TARGET,"rootAndScalarBytes":1387,
            "callerContextBytes":4592,"functions":6,"instructions":total,
            "capturedCodeExecuted":False,"componentGatesChanged":False}

def collect(artifact, packet, objdump):
    data=artifact.read_bytes()
    secs,slots=facts(data)
    if not objdump.is_absolute() or not objdump.is_file():
        raise ValueError("Use an explicit installed GNU objdump executable")
    version=subprocess.check_output([str(objdump),"--version"],timeout=10).decode()
    if "GNU objdump" not in version: raise ValueError("GNU objdump required")
    packet.mkdir(parents=True,exist_ok=False)
    # A relative artifact argument preserves unredacted original stdout
    # without publishing this operator's absolute filesystem path.
    relative=artifact.resolve().relative_to(ROOT.resolve())
    import capstone
    for label,start,end,_ in FUNCTIONS:
        rows=decoded(data,secs,start,end)
        (packet/(label+".capstone.json")).write_bytes(
            (json.dumps(rows,indent=2)+"\n").encode())
        command=[str(objdump),"-d","-Mintel","--insn-width=16",
                 "--start-address="+hex(start),"--stop-address="+hex(end),str(relative)]
        p=subprocess.run(command,cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                         check=True,timeout=30)
        (packet/(label+".objdump")).write_bytes(p.stdout)
        if p.stderr: raise ValueError("Unexpected GNU stderr")
    records={"targetSha256":TARGET,"coordinates":"linked ELF VA before load bias",
             "relocations":slots,"directCalls":[[hex(a),hex(t)] for a,t in CALLS],
             "gnuVersion":version.splitlines()[0],"capstoneBindingVersion":capstone.__version__,
             "sourceBase":"05bc2de303c05525b71e7e257426e741bc66a390",
             "normalizationMasks":[],"capturedCodeExecuted":False}
    (packet/"records.json").write_bytes((json.dumps(records,indent=2)+"\n").encode())
    return verify(data,packet)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--artifact",type=Path,default=ROOT/"artifacts/node/115/hl-node")
    p.add_argument("--packet",type=Path,default=PACKET)
    p.add_argument("--collect",action="store_true")
    p.add_argument("--objdump",type=Path)
    a=p.parse_args()
    if a.collect:
        if a.objdump is None: p.error("--collect requires --objdump")
        result=collect(a.artifact,a.packet,a.objdump)
    else: result=verify(a.artifact.read_bytes(),a.packet)
    print(json.dumps(result,sort_keys=True))
if __name__=="__main__": main()
