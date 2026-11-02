#!/usr/bin/env python3
"""Build only independent source components and behavioral mutants; never target code."""
import argparse
import csv
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib

import evidence as e
from verify import freeze

CRATES=("node94-consensus-admission","bincode-varint","node94-action-signable")
WRAPPERS=("RUSTC_WRAPPER","RUSTC_WORKSPACE_WRAPPER","CARGO_BUILD_RUSTC_WRAPPER","RUSTFLAGS","RUSTDOCFLAGS")

def audit(root):
    found=[]
    for name in CRATES:
        crate=root/"src"/name
        manifest=tomllib.loads((crate/"Cargo.toml").read_text())
        e.require(manifest["package"].get("publish") is False and manifest["package"].get("license")=="MIT","component scope")
        e.require("build" not in manifest["package"] and not list(crate.rglob("build.rs")),"build hook")
        if name=="node94-consensus-admission":
            e.require(manifest["dependencies"]=={
                "hl-bincode-varint":{"path":"../bincode-varint"},
                "node94-action-signable":{"path":"../node94-action-signable"}},"local dependency graph")
        else:
            e.require(not manifest.get("dependencies"),"unexpected dependency")
        for ancestor in (crate,*crate.parents):
            for suffix in (".cargo/config",".cargo/config.toml"):
                if (ancestor/suffix).is_file(): found.append(str(ancestor/suffix))
    home=Path(os.environ.get("CARGO_HOME",str(Path.home()/".cargo")))
    found.extend(str(home/n) for n in ("config","config.toml") if (home/n).is_file())
    e.require(not found,"unreviewed Cargo config: "+repr(sorted(set(found))))
    e.require(not any(os.environ.get(k) for k in WRAPPERS),"compiler wrapper/flags")
    return {"real_local_components":list(CRATES),"registry_dependencies":0,"build_hooks":0,"cargo_configs":0}

def run(cargo,rustc,rustdoc,out):
    receipt=freeze()
    audited=audit(e.ROOT)
    for tool in (cargo,rustc,rustdoc):
        e.require(tool.is_file(),"missing pinned tool")
    versions={name:subprocess.check_output([str(tool),"--version"],text=True).strip()
              for name,tool in (("cargo",cargo),("rustc",rustc),("rustdoc",rustdoc))}
    e.require(all("1.94.1" in v for v in versions.values()),"toolchain version")
    out.mkdir(parents=True,exist_ok=False)
    raw=gzip.decompress((e.HERE/"vectors.tsv.gz").read_bytes())
    cases=list(csv.DictReader(io.StringIO(raw.decode()),delimiter="\t"))
    protocol="".join("\t".join(r[k] for k in ("case","version","start_round","round","signer20","hash32"))+"\n" for r in cases)
    expected=[(r["case"],r["preimage"],r["digest32"]) for r in cases]
    env=os.environ.copy()
    env["RUSTC"]=str(rustc);env["RUSTDOC"]=str(rustdoc)
    env["PATH"]=str(cargo.parent)+os.pathsep+env.get("PATH","")
    logs=[]
    def command(args,cwd,inp=None):
        done=subprocess.run([str(a) for a in args],cwd=cwd,env=env,input=inp,text=True,capture_output=True)
        logs.append({"command":[str(a) for a in args],"cwd":str(cwd),"returncode":done.returncode,
                     "stdout":done.stdout,"stderr":done.stderr})
        if done.returncode:
            raise ValueError("own-source command failed: "+done.stderr)
        return done.stdout
    def compile_driver(root,target,profile,exe):
        manifest=root/"src/node94-consensus-admission/Cargo.toml"
        flag=["--release"] if profile=="release" else []
        command([cargo,"build","--lib","--manifest-path",manifest,"--target-dir",target,"--offline","--locked",*flag],root)
        lib=target/profile/"libnode94_consensus_admission.rlib"
        command([rustc,"--edition=2021",e.HERE/"driver.rs","--extern",f"node94_consensus_admission={lib}",
                 "-L",f"dependency={target/profile/'deps'}","-C","opt-level="+("3" if profile=="release" else "0"),"-o",exe],root)
    def compare(exe,label):
        output=command([exe],e.ROOT,protocol)
        actual=[tuple(line.split("\t")) for line in output.splitlines()]
        e.require(len(actual)==len(expected) and all(len(row)==3 for row in actual),"driver protocol")
        different=[expected[i][0] for i,row in enumerate(actual) if row!=expected[i]]
        e.require(all(a[0]==b[0] for a,b in zip(actual,expected)),"case IDs")
        stored=gzip.compress(output.encode(),mtime=0)
        (out/(label+".tsv.gz")).write_bytes(stored)
        # The exact driver stdout already has its own retained raw output file.
        logs[-1]["stdout"]=None
        logs[-1]["stdout_file"]=label+".tsv.gz"
        logs[-1]["stdout_raw_sha256"]=e.digest(output.encode())
        return {"cases":len(cases),"mismatches":len(different),"first_mismatch":different[0] if different else None,
                "raw_sha256":e.digest(output.encode()),"stored_sha256":e.digest(stored)}
    results={}
    with tempfile.TemporaryDirectory(prefix="qc-vote-rust-") as tmp:
        tmp=Path(tmp)
        for profile in ("debug","release"):
            target=tmp/("target-"+profile)
            flag=["--release"] if profile=="release" else []
            manifest=e.ROOT/"src/node94-consensus-admission/Cargo.toml"
            command([cargo,"test","--manifest-path",manifest,"--target-dir",target,"--offline","--locked",*flag],e.ROOT)
            exe=tmp/("driver-"+profile)
            compile_driver(e.ROOT,target,profile,exe)
            results[profile]=compare(exe,profile)
            e.require(results[profile]["mismatches"]==0,"baseline mismatched frozen bytes")
        source=(e.ROOT/"src/node94-consensus-admission/src/digest.rs").read_text()
        mutations={
            "omit-signer":source.replace("    bytes.extend_from_slice(&signer.0);","    let _ = signer;"),
            "hash-before-integers":source.replace("    for word in [","    bytes.extend_from_slice(&qc.block_hash.0);\n    for word in [").replace("    }\n    bytes.extend_from_slice(&qc.block_hash.0);","    }"),
            "big-endian":source.replace("PayloadOrder::Little","PayloadOrder::Big"),
            "extra-label":source.replace("    bytes.extend_from_slice(PREFIX);","    bytes.extend_from_slice(PREFIX);\n    bytes.extend_from_slice(b\"consensus msg\");"),
            "tag-zero":source.replace("    bytes.push(1);","    bytes.push(0);"),
            "250-marker":source.replace("        encode_u64(word, PayloadOrder::Little, &mut bytes);",
                "        if word == 250 { bytes.extend_from_slice(&[251, 250, 0]); } else { encode_u64(word, PayloadOrder::Little, &mut bytes); }"),
        }
        for name,mutant in mutations.items():
            e.require(mutant!=source,"mutant setup:"+name)
            root=tmp/name
            for crate in CRATES:
                shutil.copytree(e.ROOT/"src"/crate,root/"src"/crate,ignore=shutil.ignore_patterns("target"))
            audit(root)
            (root/"src/node94-consensus-admission/src/digest.rs").write_text(mutant)
            target=root/"target";exe=root/"driver"
            compile_driver(root,target,"release",exe)
            result=compare(exe,"mutant-"+name)
            e.require(result["mismatches"]>0,"surviving compiled mutant:"+name)
            result["source_sha256"]=e.digest(mutant.encode())
            results["mutant-"+name]=result
        # Capture real source compiler logs; ephemeral paths are the only normalization.
        normalized=json.dumps(logs,sort_keys=True,separators=(",",":"))
        normalized=normalized.replace(str(e.ROOT),"<repo>").replace(str(tmp),"<scratch>").replace(str(cargo.parent),"<toolchain>")
        (out/"commands.json.gz").write_bytes(gzip.compress(normalized.encode(),mtime=0))
    files={}
    for crate in CRATES:
        root=e.ROOT/"src"/crate
        for path in sorted(root.rglob("*")):
            if path.is_file() and "target" not in path.parts and path.suffix in (".rs",".toml",".lock"):
                files[str(path.relative_to(e.ROOT))]=e.digest(path.read_bytes())
    result={"tool_versions":versions,"build_audit":audited,"frozen_cases":receipt["cases"],
            "profiles_and_compiled_mutants":results,"source_sha256":files,
            "baseline_before_source_change":{"unit_tests":36,"integration_tests":9,"doctests":0,
              "first_attempt":"45 tests passed; doctest launcher absent because only RUSTC was pinned",
              "corrected_attempt":"Explicit pinned RUSTDOC; full baseline command exited0"},
            "scope":"Only newly authored/credited independent MIT Rust components execute. Native target never executes. Digest fixtures are mathematical Keccak, native correspondence conditional as PROOF."}
    (out/"results.json").write_text(json.dumps(result,sort_keys=True,separators=(",",":"))+"\n")
    return result

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--cargo",type=Path,required=True);p.add_argument("--rustc",type=Path,required=True)
    p.add_argument("--rustdoc",type=Path,required=True);p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    r=run(a.cargo,a.rustc,a.rustdoc,a.out)
    print(json.dumps(r["profiles_and_compiled_mutants"],sort_keys=True))
