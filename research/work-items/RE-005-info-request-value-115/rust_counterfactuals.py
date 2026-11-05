"""Build four deliberately wrong copies of our Rust; never run captured code."""
from pathlib import Path
import argparse,hashlib,json,os,shutil,subprocess
p=argparse.ArgumentParser();p.add_argument("--cargo",required=True);p.add_argument("--output",required=True,type=Path);a=p.parse_args()
W=Path(__file__).resolve().parents[3];E=Path(__file__).resolve().parent
C=W/"src/node115-info-request-value";O=a.output
O.mkdir(parents=True,exist_ok=False)
source=(C/"src/lib.rs").read_text(encoding="utf-8")
sha=hashlib.sha256((C/"src/lib.rs").read_bytes()).hexdigest()
assert sha=="d3ff06540da7ea2e961f8d0725d5edb506a4e0a5dab90f9e1f50f4764988f0a2"
changes={
 "omit-false":("members.extend(fields);",'members.extend(fields.into_iter().filter(|(_, value)| !matches!(value, RequestValue::Bool(false))));'),
 "none-to-empty-string":("value.as_ref().map_or(RequestValue::Null, address)","value.as_ref().map_or(RequestValue::String(String::new()), address)"),
 "truncate-uint64":("RequestValue::Unsigned(value)","RequestValue::Unsigned(u64::from(value as u32))"),
 "inferred-name-instead-of-native-tag":('"borrowLendUserState"','"boleUserState"'),
}
records=[]
for name,(old,new) in changes.items():
    assert source.count(old)==1,name
    dest=O/"copies"/name;crate=dest/"src/node115-info-request-value"
    shutil.copytree(C,crate)
    fixture=dest/"research/work-items/RE-005-info-request-value-115";fixture.mkdir(parents=True)
    (fixture/"frozen-cases.tsv").write_bytes((E/"frozen-cases.tsv").read_bytes())
    (crate/"src/lib.rs").write_text(source.replace(old,new),encoding="utf-8",newline="\n")
    command=[a.cargo,"test","--offline","--locked","--manifest-path",str(crate/"Cargo.toml"),
      "--test","frozen_values","--target-dir",str(O/"target"/name)]
    print("Own Rust counterfactual "+name,flush=True)
    r=subprocess.run(command,cwd=dest,env=os.environ,capture_output=True,timeout=300)
    (O/(name+".stdout")).write_bytes(r.stdout);(O/(name+".stderr")).write_bytes(r.stderr)
    detected=r.returncode==101 and b"frozen_whole_values ... FAILED" in r.stdout
    records.append({"name":name,"exitCode":r.returncode,"compiledAndWholeValueTestFailed":detected,
      "sourceSha256":hashlib.sha256((crate/"src/lib.rs").read_bytes()).hexdigest()})
    assert detected,name
assert hashlib.sha256((C/"src/lib.rs").read_bytes()).hexdigest()==sha
(O/"results.json").write_text(json.dumps({"records":records,"productionSourceUnchanged":True,
  "targetExecuted":False,"targetEmulated":False},indent=2)+"\n",encoding="utf-8",newline="\n")
print("All four wrong own-Rust implementations compiled and failed the value comparison.")
