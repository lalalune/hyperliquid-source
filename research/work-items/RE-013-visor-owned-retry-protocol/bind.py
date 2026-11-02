#!/usr/bin/env python3
"""Pure static field binding, independently callable below the image hash gate.

This parses file records and displacement fields; it does not evaluate captured
instructions. Raw controls establish evidence admission, not the manual theorem.
"""
import json
from pathlib import Path
import struct
from collect import Image, relas, require, sha, slot_binding, unwind_index

HERE=Path(__file__).resolve().parent


def check(image,pins,controls,body_identity=True):
    all_relas=relas(image)
    require(len(all_relas)==15595,"all RELA count")
    for literal in pins["literals"]:
        a=int(literal["va"],16)
        require(image.at(a,literal["bytes"]).hex()==literal["raw"],"literal: "+literal["name"])
    for fact in pins["facts"]:
        value=int.from_bytes(image.at(int(fact["va"],16),fact["bytes"]),"little")
        require(value==fact["value"],"fact: "+fact["name"])
    for item in controls["instructions"]:
        a=int(item["va"],16);raw=bytes.fromhex(item["raw"])
        require(image.at(a,len(raw))==raw,"instruction: "+item["va"])
        if "branch_target" in item:
            if raw[0] in (0xeb,*range(0x70,0x80)):
                target=a+2+struct.unpack_from("<b",raw,1)[0]
            elif raw[0]==0xe9:
                target=a+5+struct.unpack_from("<i",raw,1)[0]
            elif raw[0]==0x0f and 0x80<=raw[1]<=0x8f:
                target=a+6+struct.unpack_from("<i",raw,2)[0]
            else:raise ValueError("branch encoding")
            require(target==int(item["branch_target"],16),"branch displacement: "+item["va"])
    protected=[]
    personalities=set()
    for body in pins["bodies"]:
        start,end=int(body["start"],16),int(body["end"],16)
        f=body["frame"];fv,cv=int(f["fde_va"],16),int(f["cie_va"],16)
        fr=image.record(fv);cr=image.record(cv)
        require(fr.hex()==f["fde_raw"],"FDE: "+body["name"])
        require(cr.hex()==f["cie_raw"],"CIE: "+body["name"])
        require(fv+4-struct.unpack_from("<I",fr,4)[0]==cv,"FDE backward CIE")
        require(fv+8+struct.unpack_from("<i",fr,8)[0]==start,"FDE start")
        require(struct.unpack_from("<I",fr,12)[0]==end-start,"FDE extent")
        protected.extend([(start,end),(fv,fv+len(fr)),(cv,cv+len(cr))])
        if f["lsda"] is not None:
            lv=int(f["lsda"]["va"],16);raw=bytes.fromhex(f["lsda"]["header_and_table_raw"])
            require(image.at(lv,len(raw))==raw,"LSDA: "+body["name"])
            require(fv+17+struct.unpack_from("<i",fr,17)[0]==lv,"FDE LSDA displacement")
            ps=cv+19+struct.unpack_from("<i",cr,19)[0]
            require(ps==int(f["personality_slot"],16),"CIE personality displacement")
            personalities.add(ps);protected.append((lv,lv+len(raw)))
    selected_slots={int(p["slot"],16) for p in pins["slots"]}
    require(personalities<=selected_slots,"all personalities bound")
    for pin in pins["slots"]:
        slot=int(pin["slot"],16);r=slot_binding(image,all_relas,slot)
        require([r["type"],r["symbol"],r["addend"]]==pin["binding"],"slot: "+pin["slot"])
        require(r.get("symbol_name")==pin["name"],"symbol: "+pin["slot"])
    index=unwind_index(image,pins["bodies"])
    h=image.sections[".eh_frame_hdr"];protected.append((h[3],h[3]+h[5]))
    require(not any(r["destination"]<z and a<r["destination"]+8 for r in all_relas for a,z in protected),"relocation overlaps protected bytes")
    for pin in pins["literals"]:
        a=int(pin["va"],16);z=a+pin["bytes"]
        writers=[r for r in all_relas if r["destination"]<z and a<r["destination"]+8]
        require(all(r["destination"] in selected_slots for r in writers),"unbound literal relocation")
    if body_identity:
        for body in pins["bodies"]:
            a,z=int(body["start"],16),int(body["end"],16)
            require(sha(image.at(a,z-a))==body["sha256"],"body identity: "+body["name"])
    return dict(bodies=len(pins["bodies"]),instructions=len(controls["instructions"]),
                slots=len(pins["slots"]),relas=len(all_relas),unwind_index=index,
                body_identity_checked=body_identity)


def defaults():
    return (json.loads((HERE/"BASIS-PINS.json").read_text()),
            json.loads((HERE/"CONTROL-PINS.json").read_text()))
