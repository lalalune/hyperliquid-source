"""Build only authored Rust; compare with pre-existing and pre-extension freezes."""
from pathlib import Path
import argparse,hashlib,json,re,subprocess,sys
ap=argparse.ArgumentParser()
for name in ["repo","out","vectors","freeze","rustc","linker"]:ap.add_argument("--"+name,type=Path,required=True)
ap.add_argument("--rustc-sha256",required=True);ap.add_argument("--linker-sha256",required=True)
args=ap.parse_args();W=args.repo.resolve();B=args.out.resolve();P=W/"src/node115-bootstrap-range"
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
for tool,want in [(args.rustc,args.rustc_sha256),(args.linker,args.linker_sha256)]:
 if not tool.is_absolute():raise ValueError("absolute trusted tool path required")
 tool=tool.resolve();digest=sha(tool)
 if tool.is_relative_to(W/"artifacts") or digest in ["a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301","89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31"]:raise ValueError("captured executable cannot be a tool")
 if not tool.is_absolute() or digest!=want:raise ValueError("tool identity")
if B.is_relative_to(W) and not B.is_relative_to(W/"work"):raise ValueError("use ignored work or external output")
if B.exists():raise ValueError("fresh build directory required")
B.mkdir(parents=True)
freeze=json.loads(args.freeze.read_text(encoding="utf-8-sig"))
if freeze["vectorsSha256"]!="5400acd3ab3a11f288871062367c37b297f10d9a91e64059197e70014c748b70" or freeze["rows"]!=307232 or sha(args.vectors)!=freeze["vectorsSha256"]:raise ValueError("extension freeze")
if sha(W/"artifacts/node/115/hl-node")!="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301":raise ValueError("target identity")
if sha(P/"lib.rs")!="7ec10846ed318722fb505ce5b042756c7f3d68ccd2406d06c17cd39854491862":raise ValueError("base library changed")
# Reproduce the licensed old case generator, never its captured-instruction evaluator.
# Original pre-Rust hashes bind every generated input and expected output byte.
U=(1<<64)-1;values=list(range(111))+[29999,30000,30001,30002,(1<<63)-1,1<<63]+[U-j for j in range(111)]
legacy={(l,t) for l in values for t in values};state=0x115b007
for _ in range(1024):
 state=(state*6364136223846793005+1442695040888963407)&U;l=state
 state=(state*6364136223846793005+1442695040888963407)&U;legacy.add((l,state))
for l in [0,1,100,1<<63,U-30001,U-30000,U]:
 for d in [-1,0,1,98,99,100,29999,30000,30001]:
  if 0<=l+d<=U:legacy.add((l,l+d))
inp=[];out=[]
for l,t in sorted(legacy):
 inp.append(f"{l}\t{t}\n")
 result="S" if t>=l and t-l>30000 else "R" if l>t else f"W\t{l}\t{min(t,l+99,U)}"
 out.append(result+"\n")
legacy_in="".join(inp).encode();legacy_out="".join(out).encode()
if len(legacy)!=53038 or hashlib.sha256(legacy_in).hexdigest()!="df540604564f0170091dad0d33f8320f872f8d502ac443f2d4be432df3b811ee" or hashlib.sha256(legacy_out).hexdigest()!="fab6185bf2936aa8b25e87950282f7bb6332074ff404f636efe9b45b26ef0089":raise ValueError("original pre-Rust freeze mismatch")
(B/"legacy-inputs.tsv").write_bytes(legacy_in);(B/"legacy-expected.tsv").write_bytes(legacy_out)
results=[];artifacts={}
def run(label,cmd,stdin=None,expected=0):
 print("$ "+label,flush=True)
 with (stdin.open("rb") if stdin else open(B/"empty-input","a+b")) as stream:
  p=subprocess.run([str(x) for x in cmd],cwd=W,stdin=stream,capture_output=True,timeout=180)
 (B/(label+".stdout")).write_bytes(p.stdout);(B/(label+".stderr")).write_bytes(p.stderr)
 command=[str(x).replace(str(W),"<repo>").replace(str(B),"<build>").replace(str(args.vectors),"<frozen-vectors>").replace(str(args.rustc),"<rustc>").replace(str(args.linker),"<linker>") for x in cmd]
 results.append({"label":label,"command":command,"exitCode":p.returncode,"stdoutSha256":hashlib.sha256(p.stdout).hexdigest(),"stderrSha256":hashlib.sha256(p.stderr).hexdigest()})
 if p.returncode!=expected:raise ValueError(label+" failed; retained original output")
 return p.stdout
version=run("rustc-version",[args.rustc,"-Vv"]).decode()
if not version.startswith("rustc 1.95.0 "):raise ValueError("qualified research compiler version")
def lib(src,name,folder,opt,target=None,dependency=None):
 folder.mkdir(parents=True,exist_ok=True);dest=folder/("lib"+name+".rlib")
 cmd=[args.rustc,"--edition=2021","--crate-name",name,"--crate-type","rlib",src,"-Copt-level="+str(opt),"-Coverflow-checks=on","-Ccodegen-units=1","-D","warnings","-o",dest]
 if target:cmd+=["--target",target]
 if dependency:cmd+=["--extern","node115_bootstrap_range="+str(dependency),"-Ldependency="+str(dependency.parent)]
 run(folder.name+"-"+name,cmd)
 return dest
def exe(src,folder,dependency,name):
 dest=folder/(name+".exe")
 crate="node115_bootstrap_progress" if "progress" in name else "node115_bootstrap_range"
 extra=[] if (folder/"libnode115_bootstrap_range.rlib").exists() else ["-Ldependency="+str(B/"host-o3")]
 run(folder.name+"-"+name,[args.rustc,*extra,"--edition=2021",src,"-Coverflow-checks=on","-Copt-level=3","-D","warnings","--extern",crate+"="+str(dependency),"-Ldependency="+str(dependency.parent),"-Clinker="+str(args.linker),"-o",dest])
 return dest
source=P/"progress.rs";driver=P/"progress_driver.rs"
source_hash=sha(source);driver_hash=sha(driver)
for opt in [0,3]:
 folder=B/("host-o"+str(opt));base=lib(P/"lib.rs","node115_bootstrap_range",folder,opt)
 base_driver=exe(P/"input_only_driver.rs",folder,base,"legacy-driver")
 if run(folder.name+"-legacy-compare",[base_driver],B/"legacy-inputs.tsv")!=legacy_out:raise ValueError("original53038 outputs changed")
 extension=lib(source,"node115_bootstrap_progress",folder,opt,dependency=base)
 probe=exe(driver,folder,extension,"progress-driver")
 text=run(folder.name+"-extension-compare",[probe],args.vectors).decode()
 if "rows=307232 mismatches=0" not in text:raise ValueError("extension comparison denominator")
 artifacts[folder.name]={"baseLibrarySha256":sha(base),"progressLibrarySha256":sha(extension),"legacyRows":53038,"newRows":307232}
 for label,test_source,dependency in [("legacy",P/"lib.rs",None),("progress",source,base)]:
  test=folder/(label+"-tests.exe");cmd=[args.rustc,"--edition=2021","--test",test_source,"-Copt-level="+str(opt),"-Coverflow-checks=on","-D","warnings","-Clinker="+str(args.linker),"-o",test]
  if dependency:cmd+=["--extern","node115_bootstrap_range="+str(dependency),"-Ldependency="+str(dependency.parent)]
  run(folder.name+"-"+label+"-test-build",cmd);run(folder.name+"-"+label+"-unit-tests",[test])
for target,folder in [(None,"host-repeat"),("x86_64-unknown-linux-gnu","linux-first"),("x86_64-unknown-linux-gnu","linux-repeat")]:
 d=B/folder;base=lib(P/"lib.rs","node115_bootstrap_range",d,3,target=target);extension=lib(source,"node115_bootstrap_progress",d,3,target=target,dependency=base)
 artifacts[folder]={"baseLibrarySha256":sha(base),"progressLibrarySha256":sha(extension)}
if artifacts["host-o3"]["baseLibrarySha256"]!=artifacts["host-repeat"]["baseLibrarySha256"] or artifacts["host-o3"]["progressLibrarySha256"]!=artifacts["host-repeat"]["progressLibrarySha256"]:raise ValueError("host repeated library bytes")
if artifacts["linux-first"]!=artifacts["linux-repeat"]:raise ValueError("Linux repeated library bytes")
src=source.read_text();prefix=src.split("#[cfg(test)]",1)[0]
a=src.index("    let plan = if lower > target {");b=src.index("    Step { lower, plan }",a);next_block=src[a:b]
mutants=[
 ("fresh-wrap","predecessor.saturating_add(1)","predecessor.wrapping_add(1)"),
 ("loop-no-increment","endpoint.saturating_add(1)","endpoint"),
 ("loop-reuses-initial-guard",next_block,"    let plan = node115_bootstrap_range::plan(lower, target);\n"),
 ("wrong-tag","0x8000_0000_0000_0001","0x8000_0000_0000_0000"),
 ("record-wrap","value.saturating_add(1)","value.wrapping_add(1)"),
 ("increment-fallback","None => fallback,","None => fallback.saturating_add(1),"),
 ("invert-comparison","matches_target: expected == target","matches_target: expected != target")]
for name,before,after in mutants:
 if prefix.count(before)!=1:raise ValueError("mutant binding "+name)
 changed=src.replace(before,after,1);path=B/(name+".rs");path.write_text(changed,encoding="utf-8",newline="\n")
 folder=B/("mutant-"+name)
 # The authenticated base dependency is shared; add its directory for transitive metadata.
 folder.mkdir();base=B/"host-o3/libnode115_bootstrap_range.rlib";dest=lib(path,"node115_bootstrap_progress",folder,3,dependency=base)
 probe=exe(driver,folder,dest,"progress-driver")
 # Extension metadata depends on the base in a different directory.
 # Copying is unnecessary: supply the original dependency search path to rustc above.
 text=run(folder.name+"-compare",[probe],args.vectors,expected=1).decode()
 m=re.search(r"rows=(\d+) mismatches=(\d+)",text)
 if not m or int(m[1])!=307232 or int(m[2])<=0:raise ValueError("ineffective compiled mutant")
 artifacts[folder.name]={"sourceSha256":sha(path),"mismatches":int(m[2])}
if sha(source)!=source_hash or sha(driver)!=driver_hash:raise ValueError("source changed during build")
record={"referenceMain":"05bc2de303c05525b71e7e257426e741bc66a390","scope":"Source-hash-qualified own Rust, not native ABI or captured execution; operator records committed final head separately.","sourceSha256":source_hash,"driverSha256":driver_hash,"baseSourceSha256":sha(P/"lib.rs"),"compiler":version,"compilerSha256":sha(args.rustc),"linkerSha256":sha(args.linker),"rowsPerOptimization":{"legacy":53038,"extension":307232},"vectorsSha256":freeze["vectorsSha256"],"artifacts":artifacts,"commands":results,"capturedTargetExecutedOrEmulated":False,"linuxLibrariesExecuted":False}
(B/"qualification.json").write_text(json.dumps(record,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps({"status":"passed","legacyRows":53038,"extensionRows":307232,"optimizations":[0,3],"compiledMutants":len(mutants),"hostAndLinuxRepeatedLibrariesEqual":True}),flush=True)
