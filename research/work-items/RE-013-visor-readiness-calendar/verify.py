#!/usr/bin/env python3
"""Regenerate static records and exercise named controls below image identity.

Only the collector's GNU/LLVM/readelf subprocesses run. No target execution,
register-machine interpreter, emulation or arbitrary repository test discovery.
"""
from __future__ import annotations
import argparse
import copy
import json
from pathlib import Path
from arithmetic import certificate
from collect import (ANCHORS, Image, RANGES, bind, collect, digest, encoded,
                     fde_record, partition, require)

def verify(binary, retained, objdump, readelf, llvm):
    image=Image(binary.read_bytes())
    fresh=collect(binary,objdump,readelf,llvm)
    fresh["arithmetic.json"]=encoded(certificate(image))
    for name,data in fresh.items():
        require((retained/name).read_bytes()==data,"retained regeneration: "+name)
    results=[]
    def refuse(name,kind,fn,expected,**detail):
        try:
            fn()
        except ValueError as e:
            require(expected in str(e),"unexpected control failure: "+name+": "+str(e))
            results.append({"name":name,"kind":kind,"rejectedBy":str(e),**detail})
        else:
            raise ValueError("control was accepted: "+name)
    refuse("truncated-input","identity",lambda:Image(image.data[:-1]),"capture identity")
    refuse("LFS-pointer","identity",lambda:Image(b"version https://git-lfs.github.com/spec/v1\n"),"capture identity")
    changed=bytearray(image.data); changed[image.offset(0x445859)]^=1
    refuse("changed-image","identity",lambda:Image(bytes(changed)),"capture identity")
    def changed_image(va):
        fixture=copy.copy(image)
        payload=bytearray(image.data)
        off=image.offset(va)
        payload[off]^=1
        fixture.data=bytes(payload)
        return fixture,off
    # Every named instruction binding is tested without Image()/body SHA checks.
    for label,(va,_) in ANCHORS.items():
        fixture,off=changed_image(va)
        refuse("changed-"+label,"below-image-hash exact instruction binding",
               lambda fixture=fixture:bind(fixture),"anchor: "+label,
               va=hex(va),fileOffset=hex(off))
    for label,va,error in (
            ("leap-prefix-interior",0x7d692+100,"Gregorian leap-prefix table"),
            ("leap-prefix-sentinel",0x7d692+400,"Gregorian leap-prefix table"),
            ("year-flags",0x7d823+142,"Gregorian year-flag table"),
            ("fixed-duration",0x6e748,"fixed binary64 duration"),
            ("fallback-date",0x7c7e4,"maximum ordinary-time fallback"),
            ("fallback-nano",0x7c7ec,"maximum ordinary-time fallback")):
        fixture,off=changed_image(va)
        refuse("changed-"+label,"below-image-hash data/formula binding",
               lambda fixture=fixture:bind(fixture),error,va=hex(va),fileOffset=hex(off))
    for slot in (0x7e53c8,0x7e5390,0x7e5398):
        fixture=copy.copy(image)
        payload=bytearray(image.data)
        off=image.relocations()[slot][2]+16
        payload[off]^=1
        fixture.data=bytes(payload)
        refuse("changed-relocation-"+hex(slot),"below-image-hash RELA binding",
               lambda fixture=fixture:bind(fixture),"relocation: "+hex(slot),
               slotVA=hex(slot),fileOffset=hex(off))
    start,end=RANGES["time"]
    text=fresh["time.objdump.txt"].decode()
    # Alter original row bytes, not just an arbitrary sidecar checksum.
    corrupted=text.replace("44 8b 06","44 8b 07",1)
    require(corrupted!=text,"row mutation applied")
    refuse("changed-native-row","native row binding",
           lambda:partition(image,corrupted,start,end),"row bytes")
    shortened="\n".join(line for line in text.splitlines()
                         if not line.lstrip().startswith("44598c:"))
    refuse("missing-final-native-row","native completeness",
           lambda:partition(image,shortened,start,end),"row completeness")
    frames=fresh["time.fde.txt"].decode()
    eh=image.by_name[".eh_frame"]
    for label,off,error in (
            ("FDE-CIE-back-reference",eh[4]+0x11010+4,"FDE CIE back-reference"),
            ("CIE-record-ID",eh[4]+4,"CIE record ID")):
        fixture=copy.copy(image)
        payload=bytearray(image.data); payload[off]^=1; fixture.data=bytes(payload)
        refuse("changed-"+label,"below-image-hash FDE/CIE provenance",
               lambda fixture=fixture:fde_record(fixture,frames,"time"),error,
               fileOffset=hex(off))
    wrong_end=frames.replace("pc=0000000000445830..0000000000445992",
                             "pc=0000000000445830..0000000000445993")
    require(wrong_end!=frames,"FDE end mutation applied")
    refuse("changed-retained-FDE-end","FDE record binding",
           lambda:fde_record(image,wrong_end,"time"),"unique exact FDE")
    duplicate=frames+"\n"+frames
    refuse("duplicate-FDE","FDE uniqueness",
           lambda:fde_record(image,duplicate,"time"),"unique exact FDE")
    return {"regeneratedFiles":len(fresh),"allRetainedBytesMatch":True,
            "controls":results,"controlCount":len(results),
            "identityControls":sum(x["kind"]=="identity" for x in results),
            "belowImageHashControls":sum(x["kind"].startswith("below-image-hash") for x in results),
            "recordControls":sum(x["kind"] in ("native row binding","native completeness",
                                               "FDE record binding","FDE uniqueness") for x in results),
            "sourceSha256":{name:digest((Path(__file__).parent/name).read_bytes())
                            for name in ("collect.py","arithmetic.py","verify.py")},
            "executionScope":"Native parsers/decoders and finite scalar arithmetic only.",
            "limits":"Exact binding controls do not establish changed-program semantics. Identity controls are separately counted and do not mask lower-level controls. Arithmetic/native correspondence and storage/ABI premises are manual proof obligations."}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary",required=True,type=Path)
    p.add_argument("--retained",type=Path,default=Path(__file__).parent/"observed")
    p.add_argument("--output",required=True,type=Path)
    p.add_argument("--objdump",default="objdump")
    p.add_argument("--readelf",default="readelf")
    p.add_argument("--llvm",default="llvm-objdump")
    a=p.parse_args()
    require(not a.output.exists(),"output already exists; preserve receipts")
    result=verify(a.binary,a.retained,a.objdump,a.readelf,a.llvm)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_bytes(encoded(result))
    print(f"Regeneration matched; {result['controlCount']} controls rejected; no target execution.")

if __name__=="__main__":
    main()
