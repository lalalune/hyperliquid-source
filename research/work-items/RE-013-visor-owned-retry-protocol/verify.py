#!/usr/bin/env python3
"""Pre-code static/value reproducibility and corruption controls only.

Never execute/emulate captured code. This is not a Rust qualification harness.
The explicit source-absence check means final post-source replay must use an
exact isolated pre-code packet rather than silently weaken this frozen guard.
"""
import argparse
import copy
import gzip
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
from arithmetic import certificates
from bind import check,defaults
from collect import Image,admit_identity,relas,require,sha
from corpus import compact,expected,frame,generate_cases
from protocol import decode,lines

HERE=Path(__file__).resolve().parent
REPO=HERE.parents[2]


def identity(path,pin):
    require(path.is_file() and not path.is_symlink(),"regular file: "+path.name)
    raw=path.read_bytes()
    require(len(raw)==pin["bytes"] and sha(raw)==pin["sha256"],"file identity: "+path.name)


def packet_admission(root,freeze_sha):
    freeze_path=root/"PRE-RUST-FREEZE.json"
    if not freeze_path.exists():
        require(freeze_sha is None,"missing requested freeze")
        return "draft before freeze"
    require(freeze_sha is not None and sha(freeze_path.read_bytes())==freeze_sha,"externally pinned freeze")
    freeze=json.loads(freeze_path.read_text());entries=freeze["files"]
    require(isinstance(entries,dict) and entries,"freeze files")
    present=set()
    for path in root.rglob("*"):
        require(not path.is_symlink(),"packet symlink")
        relative=path.relative_to(root).as_posix()
        if path.is_file():present.add(relative)
        elif path.is_dir():
            require(any(name.startswith(relative+"/") for name in entries),"unexpected packet directory")
        else:raise ValueError("nonregular packet entry")
    require(present==set(entries)|{"PRE-RUST-FREEZE.json"},"exact physical freeze set")
    for relative,pin in entries.items():
        require(not Path(relative).is_absolute() and ".." not in Path(relative).parts,"safe manifest path")
        identity(root/relative,pin)
    manifest=json.loads((root/"MANIFEST.json").read_text())
    require(set(manifest["files"])==set(entries)-{"MANIFEST.json"},"manifest/freeze set")
    for relative,pin in manifest["files"].items():require(entries[relative]==pin,"manifest/freeze pin")
    return dict(freeze_sha256=freeze_sha,files=len(entries),exact_physical_set=True)


def compare(expected_bytes,actual):
    def parse(data):
        require(data and data.endswith(b"\n"),"output completion")
        rows=[];seen=set()
        for line in data.splitlines():
            fields=line.split(b"\t");require(len(fields)==2,"output fields")
            key,value=fields;require(key not in seen,"output duplicate ID");seen.add(key)
            rows.append((key,json.loads(value)))
        return rows
    require(parse(actual)==parse(expected_bytes),"complete output values")


def run_checks(binary,dependency_root,output,freeze_sha):
    require(not output.exists(),"fresh report")
    require(not (REPO/"src/visor-retry-protocol").exists(),"retry source must be absent")
    require(not (HERE/"rust-validation").exists(),"client/harness must be absent")
    admission=packet_admission(HERE,freeze_sha)
    raw=binary.read_bytes();admit_identity(raw);image=Image(raw)
    pins,controls=defaults();baseline=check(image,pins,controls)
    results=[]

    def reject(name,fn,fragment=None,detail=None):
        try:fn()
        except (ValueError,UnicodeDecodeError,struct.error,json.JSONDecodeError) as e:
            diagnostic=str(e)
            require(fragment is None or fragment in diagnostic,"wrong rejection: "+name+" / "+diagnostic)
            results.append(dict(name=name,status="REJECTED",diagnostic=diagnostic,detail=detail))
            return
        raise ValueError("control accepted: "+name)

    mutated=bytearray(raw);mutated[0]^=1
    reject("whole-image-identity",lambda:admit_identity(mutated),"target identity",
           "Identity-only control; not a semantic corruption test.")
    with tempfile.TemporaryDirectory(prefix="hl-retry-admission-control-") as temp:
        miniature=Path(temp)/"packet";miniature.mkdir()
        payload=miniature/"payload.txt";payload.write_bytes(b"static admission witness\n")
        pin=dict(bytes=payload.stat().st_size,sha256=sha(payload.read_bytes()))
        manifest=miniature/"MANIFEST.json"
        manifest.write_text(json.dumps(dict(files={"payload.txt":pin})))
        freeze=miniature/"PRE-RUST-FREEZE.json"
        freeze.write_text(json.dumps(dict(files={"payload.txt":pin,"MANIFEST.json":
            dict(bytes=manifest.stat().st_size,sha256=sha(manifest.read_bytes()))})))
        freeze_hash=sha(freeze.read_bytes());packet_admission(miniature,freeze_hash)
        reject("admission-wrong-external-freeze",lambda:packet_admission(miniature,"0"*64),"externally pinned freeze")
        extra=miniature/"unlisted.txt";extra.write_text("not admitted")
        reject("admission-extra-file",lambda:packet_admission(miniature,freeze_hash),"exact physical freeze set");extra.unlink()
        extra=miniature/"unlisted-dir";extra.mkdir()
        reject("admission-extra-empty-dir",lambda:packet_admission(miniature,freeze_hash),"unexpected packet directory");extra.rmdir()
        old=payload.read_bytes();payload.write_bytes(b"changed")
        reject("admission-changed-file",lambda:packet_admission(miniature,freeze_hash),"file identity:");payload.unlink()
        reject("admission-missing-file",lambda:packet_admission(miniature,freeze_hash),"exact physical freeze set")
        outside=Path(temp)/"same.txt";outside.write_bytes(old);payload.symlink_to(outside)
        reject("admission-symlink",lambda:packet_admission(miniature,freeze_hash),"packet symlink")

    def mutate(name,va,fragment,mask=1):
        offset=image.offset(va,1);changed=bytearray(raw);changed[offset]^=mask
        require(changed[offset] != image.at(va,1)[0],"mutation applied")
        reject(name,lambda:check(Image(changed),pins,controls,body_identity=False),fragment,
               dict(va=hex(va),file_offset=offset,whole_image_hash_gate=False,body_hash_gate=False,
                    scope="Raw field/graph admission, not execution or semantic validation of a changed program."))

    for p in pins["literals"]:mutate("literal-"+p["name"],int(p["va"],16),"literal: ")
    for p in pins["facts"]:mutate("operand-"+p["name"],int(p["va"],16),"fact: ")
    fact_ranges=[(int(p["va"],16),int(p["va"],16)+p["bytes"]) for p in pins["facts"]]
    for p in controls["instructions"]:
        # Opcode bytes are outside the immediate-field controls above.
        a=int(p["va"],16)
        require(not any(x<=a<z for x,z in fact_ranges),"instruction control overlaps fact")
        mutate("instruction-"+p["va"],a,"instruction: ")
        if "branch_target" in p:
            changed=copy.deepcopy(controls)
            item=next(x for x in changed["instructions"] if x["va"]==p["va"])
            item["branch_target"]=hex(int(item["branch_target"],16)+1)
            reject("branch-target-"+p["va"],lambda:check(image,pins,changed,False),"branch displacement:",
                   "Changed claimed destination with original instruction bytes; no image/body hash gate.")
    seen=set()
    for p in pins["bodies"]:
        f=p["frame"]
        mutate("fde-extent-"+p["name"],int(f["fde_va"],16)+12,"FDE: ")
        cv=int(f["cie_va"],16)
        if cv not in seen:
            seen.add(cv);mutate("cie-encoding-"+hex(cv),cv+9,"CIE: ")
        if f["lsda"]:
            mutate("lsda-call-table-"+p["name"],int(f["lsda"]["table_start"],16),"LSDA: ")
    for entry in baseline["unwind_index"]["selected"]:
        mutate("unwind-index-"+entry["name"],int(entry["va"],16)+4,"unwind index body/FDE binding")
    all_relas=relas(image)
    for p in pins["slots"]:
        r=next(x for x in all_relas if x["destination"]==int(p["slot"],16))
        changed=bytearray(raw);changed[r["file_offset"]+16]^=1
        reject("relocation-addend-"+p["slot"],lambda:check(Image(changed),pins,controls,False),"slot: ",
               dict(file_offset=r["file_offset"]+16,whole_image_hash_gate=False,body_hash_gate=False))
    # An unrelated relocation writer redirected into protected code is detected
    # even though no body or selected-slot byte changes.
    r=next(x for x in all_relas if x["destination"] not in {int(p["slot"],16) for p in pins["slots"]})
    changed=bytearray(raw);struct.pack_into("<Q",changed,r["file_offset"],0x42a290)
    reject("new-overlapping-code-relocation",lambda:check(Image(changed),pins,controls,False),"relocation overlaps protected bytes")

    dep=json.loads((HERE/"DEPENDENCY-PINS.json").read_text())
    for relative,pin in {**dep["source"],**dep["credited_evidence"]}.items():identity(dependency_root/relative,pin)
    identity(dependency_root/dep["license"]["path"],dep["license"])
    old_manifest=json.loads((dependency_root/"research/work-items/RE-013-visor-duration-value-rust/PUBLIC-MANIFEST.json").read_text())
    require(len(old_manifest["files"])==dep["actual_prior_public_manifest_entries_rehashed"],"old full manifest count")
    for relative,pin in old_manifest["files"].items():identity(dependency_root/relative,pin)
    arithmetic=certificates()
    require(json.loads((HERE/"arithmetic.json").read_text())==arithmetic,"mathematical certificate")
    cases=generate_cases();summary=json.loads((HERE/"corpus/summary.json").read_text())
    streams={}
    for name,pin in summary["files"].items():
        packed=(HERE/"corpus"/(name+".gz")).read_bytes();data=gzip.decompress(packed)
        require(len(packed)==pin["gzip_bytes"] and sha(packed)==pin["gzip_sha256"],"packed corpus identity")
        require(len(data)==pin["bytes"] and sha(data)==pin["sha256"],"raw corpus identity")
        streams[name]=data
    parsed=lines(streams["inputs.tsv"])
    require(len(parsed)==len(cases)==summary["cases"],"case count")
    replay=bytearray()
    for i,((key,c),original) in enumerate(zip(parsed,cases,strict=True)):
        require(key==f"C{i:06d}"==original["id"],"opaque sequential identity")
        require(frame(c)==frame(original),"transport roundtrip")
        require(expected(c)==expected(original),"transport does not change supplied callback values")
        replay+=(key+"\t"+compact(expected(c))+"\n").encode()
    require(bytes(replay)==streams["expected.tsv"],"oracle/transport expected stream")
    compare(streams["expected.tsv"],bytes(replay))

    minimal=frame(dict(mode="retry",request=dict(tag=0,bytes=""),terminal=0,
                       description="",delays=[],attempts=[],sleeps=[]))
    malformed=[("empty",b""),("magic",b"XX"+minimal[2:]),("mode",minimal[:4]+b"\x02"+minimal[5:]),
               ("truncated",minimal[:-1]),("trailing",minimal+b"\0"),
               ("field-limit",minimal[:13]+struct.pack("<I",65537)+minimal[17:]),
               ("delay-option",minimal[:29]+b"\x02"+minimal[30:]),
               ("delay-count-limit",minimal[:30]+struct.pack("<I",257)+minimal[34:]),
               ("attempt-count-limit",minimal[:34]+struct.pack("<I",257)+minimal[38:]),
               ("sleep-count-limit",minimal[:38]+struct.pack("<I",1025)+minimal[42:]),
               ("description-utf8",minimal[:25]+struct.pack("<I",1)+b"\xff"+minimal[29:])]
    for name,value in malformed:reject("transport-"+name,lambda:decode(value))
    valid_line=b"C000000\t"+minimal.hex().encode()+b"\n"
    for name,value in [("no-LF",valid_line[:-1]),("CRLF",valid_line[:-1]+b"\r\n"),
                       ("duplicate-ID",valid_line*2),("semantic-ID",valid_line.replace(b"C000000",b"initial-success")),
                       ("uppercase-hex",valid_line.replace(b"5652",b"ABCD",1)),
                       ("odd-hex",valid_line[:-1]+b"0\n"),("extra-field",valid_line[:-1]+b"\textra\n")]:
        reject("batch-"+name,lambda:lines(value))
    out_lines=streams["expected.tsv"].splitlines(keepends=True)
    for name,value in [("truncated",b"".join(out_lines[:-1])),("duplicate",b"".join(out_lines+[out_lines[-1]])),
                       ("swapped",b"".join([out_lines[1],out_lines[0],*out_lines[2:]])),
                       ("no-LF",streams["expected.tsv"][:-1])]:
        reject("comparator-"+name,lambda:compare(streams["expected.tsv"],value))
    for event in ("attempt","sleep","terminal","drop_error","cleanup","drop_cleanup_error"):
        values=[json.loads(x.split(b"\t",1)[1]) for x in out_lines]
        j=next(i for i,v in enumerate(values) if any(e[0]==event for e in v["trace"]))
        k=next(i for i,e in enumerate(values[j]["trace"]) if e[0]==event)
        del values[j]["trace"][k]
        modified=list(out_lines);modified[j]=out_lines[j].split(b"\t",1)[0]+b"\t"+compact(values[j]).encode()+b"\n"
        reject("comparator-missing-"+event,lambda:compare(streams["expected.tsv"],b"".join(modified)))

    # These are explicitly specification-sensitivity controls, not source
    # mutants or evidence of running the captured program.
    source=(HERE/"corpus.py").read_text()
    mutations=[("initial-attempt-omitted","current=attempt(None)","current=None"),
               ("none-becomes-empty","list(DEFAULT_BITS) if case[\"delays\"] is None","[] if case[\"delays\"] is None"),
               ("zero-delay-skips-attempt","new=attempt(current)","new=None if duration_total(bits)==0 else attempt(current)"),
               ("old-drop-before-attempt","new=attempt(current)\n            drop(current)","drop(current)\n            new=attempt(current)"),
               ("code0-loads-remainder","remaining-=request_total","remaining=remaining-request_total+max(0,r)*BILLION+max(0,rn)"),
               ("clock2","trace.append([\"sleep\",q,nanos,1,0])","trace.append([\"sleep\",q,nanos,2,0])"),
               ("terminal-tail-only","[f\"{b:016x}\" for b in selected]","[f\"{b:016x}\" for b in selected[-1:]]"),
               ("skip-empty-cleanup","if cleanup is not None:","if cleanup is not None and cleanup[\"bytes\"]:"),
               ("cleanup-error-drop-omitted","trace.append([\"drop_cleanup_error\",case[\"cleanup_error\"]])","pass"),
               ("terminal-identity-false","terminal_identity=None if terminal is None else True","terminal_identity=None if terminal is None else False")]
    sensitivity=[]
    for name,old,new in mutations:
        require(source.count(old)==1,"unique specification mutant: "+name)
        namespace={"__name__":"specification_mutant","__file__":str(HERE/"corpus.py")}
        exec(compile(source.replace(old,new),"specification_mutant","exec"),namespace)
        mismatches=sum(namespace["expected"](c)!=expected(c) for c in cases)
        require(mismatches>0,"undetected specification mutant: "+name)
        sensitivity.append(dict(name=name,mismatches=mismatches,complete_cases=len(cases),scope="Python abstract specification sensitivity only"))

    regeneration=[]
    with tempfile.TemporaryDirectory(prefix="hl-retry-precode-") as temp:
        root=Path(temp)
        for tree in ("one","two"):
            destination=root/tree;destination.mkdir()
            tasks=[("collect.py",["--binary",str(binary),"--out",str(destination/"observed")]),
                   ("arithmetic.py",["--out",str(destination/"arithmetic.json")]),
                   ("corpus.py",["--out",str(destination/"corpus")])]
            for script,args in tasks:
                cmd=[sys.executable,"-B",str(HERE/script),*args]
                done=subprocess.run(cmd,capture_output=True,env=dict(os.environ,PYTHONDONTWRITEBYTECODE="1"),timeout=120)
                require(done.returncode==0,"regeneration failed: "+script+" "+done.stderr.decode(errors="replace"))
                regeneration.append(dict(tree=tree,script=script,exit=done.returncode,
                                         stdout=done.stdout.decode(),stderr=done.stderr.decode()))
            for generated in sorted(destination.rglob("*")):
                if generated.is_file():
                    rel=generated.relative_to(destination)
                    require(generated.read_bytes()==(HERE/rel).read_bytes(),"regeneration mismatch: "+str(rel))
    require(binary.read_bytes()==raw,"target changed")
    report=dict(status="PASS pre-code static/value qualification only",target_sha256=sha(raw),
                bodies=baseline["bodies"],rows=sum(x["rows"] for x in pins["bodies"]),
                bytes=sum(int(x["end"],16)-int(x["start"],16) for x in pins["bodies"]),
                cases=summary["cases"],domains=summary["domains"],expected_events=summary["expected_events"],
                rejected_controls=results,specification_sensitivity=sensitivity,regenerations=regeneration,
                source_absent=True,client_absent=True,
                packet_admission=admission,
                unchanged_prior_manifest_entries=len(old_manifest["files"]),
                limits=["Conditional manual theorem is not machine-verified by byte controls.",
                        "Two decoders and peer math are independent methods, not independent target provenance.",
                        "No captured execution, Rust compilation, shell command or sleep.",
                        "Finite corpus controls do not establish all callback histories.",
                        "Specification mutations are not production mutant kills."])
    output.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps(dict(status=report["status"],controls=len(results),sensitivity=len(sensitivity),
                          cases=summary["cases"],regenerations=len(regeneration))))


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--binary",type=Path,default=REPO/"artifacts/visor/captured/hl-visor")
    p.add_argument("--dependency-root",type=Path,default=REPO)
    p.add_argument("--out",type=Path,required=True)
    p.add_argument("--freeze-sha")
    a=p.parse_args();run_checks(a.binary.resolve(),a.dependency_root.resolve(),a.out,a.freeze_sha)


if __name__=="__main__":main()
