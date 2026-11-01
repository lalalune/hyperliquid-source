#!/usr/bin/env python3
"""Verify immutable static evidence; never execute captured instructions."""
import argparse
import gzip
import json
from pathlib import Path
import struct
import tempfile

import corpus
import evidence as e

def freeze():
    receipt=json.loads((e.HERE/"PRE-RUST-FREEZE.json").read_text())
    amendments=json.loads((e.HERE/"POST-FREEZE-NORMALIZATION.json").read_text())
    for name,sha in receipt["files"].items():
        current=(e.HERE/name).read_bytes()
        if name in amendments["files"]:
            row=amendments["files"][name]
            e.require(row["old_sha256"]==sha and e.digest(current)==row["new_sha256"]
                      and e.digest(current+b"\n")==sha,"reversible EOF normalization:"+name)
        else:
            e.require(e.digest(current)==sha,"freeze:"+name)
    raw=gzip.decompress((e.HERE/"vectors.tsv.gz").read_bytes())
    e.require(raw==corpus.rows(),"fresh fixture derivation differs")
    e.require(e.digest(raw)==receipt["vectors_uncompressed_sha256"],"fixture content hash")
    return receipt

def extra_contract(data):
    # Explicit data dependencies supplement (and do not alter) the frozen receipt.
    e.require(e.read(data,0x209f84,4)==b"\x01\x00\x00\x00","tag1 literal")
    expected=b"".join(x.to_bytes(8,"little") for x in corpus.constants())
    e.require(e.read(data,0x7d04c8,len(expected))==expected,"credited round constants")

def native(text,data,start,end):
    rows=e.parse(text,start,end)
    e.require(b"".join(b for _,b,_ in rows)==e.read(data,start,end-start),"native bytes differ")
    return e.partition(rows)

def tree(path):
    return {p.name:p.read_bytes() for p in path.iterdir() if p.is_file()}

def verify(gnu,llvm):
    receipt=freeze()
    data=(e.ROOT/e.BINARY).read_bytes()
    e.require(len(data)==e.SIZE and e.digest(data)==e.SHA,"target identity")
    relocs=e.contract(data); fs=e.fdes(data); extra_contract(data)
    pins=json.loads((e.HERE/"pins.json").read_text())
    records=json.loads((e.HERE/"observed/records.json").read_text())
    failures=[]
    def rejects(name,fn,reason):
        try:
            fn()
        except (ValueError,FileExistsError) as exc:
            e.require(reason in str(exc),name+": unexpected rejection "+str(exc))
            failures.append({"control":name,"rejection":reason})
        else:
            raise ValueError(name+": accepted corruption")
    mutable=bytearray(data)
    def flip(off,fn):
        mutable[off]^=1
        try: return fn(mutable)
        finally: mutable[off]^=1
    for name,row in pins["instructions"].items():
        rejects("witness/"+name,lambda row=row:flip(e.offset(data,int(row["control_va"],16)),e.contract),"pin:")
    for row in pins["literals"]:
        rejects("literal/"+row["va"],lambda row=row:flip(e.offset(data,int(row["va"],16)),e.contract),"literal:")
    for row in pins["tables"]:
        rejects("dispatch/"+row["va"],lambda row=row:flip(e.offset(data,int(row["va"],16)),e.contract),"dispatch:")
    for row in relocs:
        for delta,label in [(16,"addend"),(12,"symbol"),(8,"type")]:
            rejects("relocation-"+label+"/"+row["slot"],
                    lambda row=row,delta=delta:flip(row["record_file_offset"]+delta,e.contract),"relocation:")
    for name,f in fs.items():
        rejects("fde-size/"+name,lambda f=f:flip(e.offset(data,f["fde"])+12,e.fdes),"FDE extent:")
    for va,label in [(0x209f84,"tag1 literal"),(0x7d04c8,"credited round constants")]:
        rejects(label,lambda va=va:flip(e.offset(data,va),extra_contract),label)
    rows=0
    for name,(start,end) in e.RANGES.items():
        meta=records["ranges"][name]
        e.require(meta["start"]==hex(start) and meta["end"]==hex(end) and meta["bytes"]==end-start,"range scope")
        e.require(meta["sha256"]==e.digest(e.read(data,start,end-start)),"range hash")
        decoded={}
        for provider in ("gnu","llvm"):
            file=meta["exports"][provider]
            stored=(e.HERE/"observed"/file["file"]).read_bytes()
            raw=stored if provider=="gnu" else gzip.decompress(stored)
            e.require(e.digest(stored)==file["stored_sha256"] and e.digest(raw)==file["raw_sha256"],"native export hash")
            decoded[provider]=native(raw.decode(),data,start,end)
        e.require([(v,b) for v,b,_ in decoded["gnu"]]==[(v,b) for v,b,_ in decoded["llvm"]],"native partition")
        e.require(len(decoded["gnu"])==meta["rows"],"native row count")
        rows+=len(decoded["gnu"])
    start,end=e.RANGES["digest"]
    text=(e.HERE/"observed/digest.gnu.txt").read_text()
    lines=text.splitlines()
    missing="\n".join(line for line in lines if not line.lstrip().startswith("454c050:"))
    rejects("missing-native-row",lambda:native(missing,data,start,end),"decode gap or overlap")
    wrong=text.replace("41 57","41 56",1)
    e.require(wrong!=text,"native mutation setup")
    rejects("wrong-native-byte",lambda:native(wrong,data,start,end),"native bytes differ")
    rejects("dangling-lock",lambda:e.partition([(start,b"\xf0","lock")]),"dangling LOCK")
    # Show that selected witnesses are only a subset; full-range bytes catch the rest.
    unselected=e.RANGES["permutation-context"][0]
    def probe(d):
        e.contract(d); extra_contract(d)
        begin,finish=e.RANGES["permutation-context"]
        raw=(e.HERE/"observed/permutation-context.gnu.txt").read_text()
        rejects("unselected-byte-full-export",lambda:native(raw,d,begin,finish),"native bytes differ")
    flip(e.offset(data,unselected),probe)
    with tempfile.TemporaryDirectory(prefix="qc-vote-static-") as tmp:
        tmp=Path(tmp)
        for name in ("one","two"):
            e.collect(e.ROOT/e.BINARY,tmp/name,gnu,llvm)
            e.require(tree(tmp/name)==tree(e.HERE/"observed"),"fresh native exports differ")
        wrong=tmp/"wrong-target";wrong.write_bytes(b"not target")
        rejects("wrong-target-before-output",lambda:e.collect(wrong,tmp/"absent",gnu,llvm),"target identity")
        e.require(not (tmp/"absent").exists(),"wrong target created outputs")
        rejects("existing-output-preserved",lambda:e.collect(e.ROOT/e.BINARY,tmp/"one",gnu,llvm),"File exists")
        e.require(tree(tmp/"one")==tree(e.HERE/"observed"),"existing output changed")
    return {"target_sha256":e.SHA,"full_fde_ranges":18,"bytes":10532,"rows":rows,
            "frozen_cases":receipt["cases"],"fresh_native_regenerations":2,
            "negative_control_count":len(failures),"negative_controls":failures,
            "supplemental_data_checks":"tag1 u32 at209f84; credited24 round constants at7d04c8. Added in verifier without altering pre-Rust derivation receipt.",
            "limits":"Static integrity/sensitivity only, with manual conditional proof. No target execution, symbolic x86 evaluator or full permutation equivalence proof."}

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--gnu",default=e.GNU);p.add_argument("--llvm",default=e.LLVM)
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    result=verify(a.gnu,a.llvm)
    a.out.write_text(json.dumps(result,sort_keys=True,separators=(",",":"))+"\n")
    print(json.dumps({k:v for k,v in result.items() if k not in ("negative_controls","supplemental_data_checks","limits")}))
