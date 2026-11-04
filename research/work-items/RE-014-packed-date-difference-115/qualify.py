from pathlib import Path
import hashlib,json,re,subprocess,sys
import argparse
ROOT=Path(__file__).resolve().parents[3]
ap=argparse.ArgumentParser(description="Compile only authored Rust; compare with authenticated derived vectors.")
ap.add_argument("--vectors-dir",type=Path,required=True)
ap.add_argument("--out",type=Path,required=True)
ap.add_argument("--rustc",type=Path,required=True)
ap.add_argument("--rustc-sha256",required=True)
ap.add_argument("--linker",type=Path,required=True)
ap.add_argument("--linker-sha256",required=True)
args=ap.parse_args()
O=args.vectors_dir.resolve();B=args.out.resolve();W=ROOT
P=ROOT/"src/node115-packed-date-difference"
if B.is_relative_to(ROOT) and not B.is_relative_to(ROOT/"work"):
 raise ValueError("Use ignored work/ or external scratch output.")
if B.exists():raise ValueError("qualification output already exists")
B.mkdir()
freeze=json.loads((O/"pre-rust-freeze.json").read_text(encoding="utf-8"))
vectors=O/freeze["vectors"]
def sha(p):
 h=hashlib.sha256()
 with p.open("rb") as f:
  for b in iter(lambda:f.read(1048576),b""):h.update(b)
 return h.hexdigest()
if sha(vectors)!=freeze["sha256"]:raise ValueError("fixture content identity")
native=json.loads((O/"native-intake.json").read_text(encoding="utf-8"))
target=W/"artifacts/node/115/hl-node"
if sha(target)!=native["targetSha256"]:raise ValueError("target drift")
rawgnu=(W/"research/work-items/RE-008-node115-heartbeat-query-static/0x162a290.objdump.txt").read_text(encoding="utf-8")
got=[]
for line in rawgnu.splitlines():
 m=re.fullmatch(r"\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)\s*(.*)",line)
 if m:got.append((hex(int(m[1],16)),bytes.fromhex(m[2]).hex()))
if got!=[(i["address"],i["bytes"]) for i in native["instructions"]]:raise ValueError("reused GNU/Capstone bytes/partition")
rustc=args.rustc.resolve();linker=args.linker.resolve()
for tool,expected in [(rustc,args.rustc_sha256),(linker,args.linker_sha256)]:
 if not tool.is_absolute() or tool.is_relative_to(ROOT/"artifacts"):raise ValueError("tool path is not trusted external compiler/linker")
 digest=sha(tool)
 if digest in [native["targetSha256"],"89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31"]:raise ValueError("captured executable forbidden")
 if digest!=expected:raise ValueError("compiler/linker hash drift")
if freeze["sha256"]!="6a8671ad7d0188c6529135f4395d5b1957d306a243fc0413aad7921f4f791eaf" or freeze["rows"]!=1071744:raise ValueError("frozen initial fixture identity")
results=[]
def run(cmd,label,expected=0,stdin=None):
 print("$ "+label,flush=True)
 with (stdin.open("rb") if stdin else open(B/"empty-input","a+b")) as inp:
  p=subprocess.run([str(x) for x in cmd],cwd=W,stdin=inp,capture_output=True,timeout=180)
 (B/(label+".stdout")).write_bytes(p.stdout);(B/(label+".stderr")).write_bytes(p.stderr)
 results.append({"label":label,"command":[str(x).replace(str(ROOT),"<repo>").replace(str(B),"<build>").replace(str(O),"<vectors>").replace(str(rustc),"<rustc>").replace(str(linker),"<linker>") for x in cmd],"exitCode":p.returncode,"stdoutSha256":hashlib.sha256(p.stdout).hexdigest(),"stderrSha256":hashlib.sha256(p.stderr).hexdigest()})
 if p.returncode!=expected:raise ValueError(label+" exit "+str(p.returncode)+"; see retained stderr")
 return p.stdout
version=run([rustc,"-Vv"],"rustc-version").decode("utf-8")
source=P/"src/lib.rs";driver=P/"src/probe.rs"
sourcehash=sha(source);driverhash=sha(driver)
def compile_lib(src,folder,opt,target=None):
 folder.mkdir()
 lib=folder/"libnode115_packed_date_difference.rlib"
 cmd=[rustc,"--edition=2021","--crate-type=rlib","--crate-name","node115_packed_date_difference",src,"-Copt-level="+str(opt),"-Coverflow-checks=yes","-Ccodegen-units=1","-Cdebuginfo=0","-o",lib]
 if target:cmd+=["--target",target]
 run(cmd,folder.name+"-library")
 return lib
def compile_probe(lib,folder):
 exe=folder/"frozen-probe.exe"
 run([rustc,"--edition=2021",driver,"--extern","node115_packed_date_difference="+str(lib),"-Copt-level=3","-Coverflow-checks=yes","-Clinker="+str(linker),"-o",exe],folder.name+"-probe")
 return exe
artifacts={}
for opt in [0,3]:
 folder=B/("host-o"+str(opt));lib=compile_lib(source,folder,opt)
 exe=compile_probe(lib,folder)
 output=run([exe],folder.name+"-compare",stdin=vectors).decode("ascii")
 if "rows="+str(freeze["rows"])+" mismatches=0" not in output:raise ValueError("comparison denominator")
 artifacts[folder.name]={"librarySha256":sha(lib),"probeSha256":sha(exe)}
unit=B/"unit-tests.exe"
run([rustc,"--edition=2021","--test",source,"-Coverflow-checks=yes","-Clinker="+str(linker),"-o",unit],"compile-unit-tests")
run([unit],"unit-tests")
repeat=compile_lib(source,B/"host-o3-repeat",3)
if sha(repeat)!=artifacts["host-o3"]["librarySha256"]:raise ValueError("host library repeat differs")
linux=compile_lib(source,B/"linux-o3",3,"x86_64-unknown-linux-gnu")
linux2=compile_lib(source,B/"linux-o3-repeat",3,"x86_64-unknown-linux-gnu")
if sha(linux)!=sha(linux2):raise ValueError("Linux library repeat differs")
src=source.read_text(encoding="utf-8")
mutants=[
 ("unsigned-year","i64::from((word as i32) >> 13)","i64::from((word >> 13) as i32)"),
 ("drop-leap-days","year * 365 + leap_days + ordinal","year * 365 + ordinal"),
 ("truncate-negative-nanos","nanos.div_euclid(1_000_000_000)","nanos / 1_000_000_000"),
 ("remove-zero-boundary","year.rem_euclid(400) == 0 && ordinal == 0","false"),
 ("equal-second-leap","left.seconds_word < right.seconds_word","left.seconds_word <= right.seconds_word")
]
for name,before,after in mutants:
 if src.count(before)!=1:raise ValueError("mutant pattern "+name)
 path=B/(name+".rs");path.write_text(src.replace(before,after),encoding="utf-8")
 folder=B/("mutant-"+name);lib=compile_lib(path,folder,3);exe=compile_probe(lib,folder)
 output=run([exe],folder.name+"-compare",expected=1,stdin=vectors).decode("ascii")
 m=re.search(r"rows=(\d+) mismatches=(\d+)",output)
 if not m or int(m[1])!=freeze["rows"] or int(m[2])<=0:raise ValueError("ineffective compiled mutant "+name)
 artifacts[folder.name]={"sourceSha256":sha(path),"mismatches":int(m[2])}
if sha(source)!=sourcehash or sha(driver)!=driverhash:raise ValueError("source changed during qualification")
record={"referenceCommit":"05bc2de303c05525b71e7e257426e741bc66a390","sourceHeadInterpretation":"Reproduction bound to explicit source hashes; operator records exact committed head separately.","targetSha256":native["targetSha256"],"nativeBodySha256":native["bodySha256"],"sourceSha256":sourcehash,"driverSha256":driverhash,"frozenVectorsSha256":freeze["sha256"],"rowsPerOptimization":freeze["rows"],"rustcVersion":version,"results":results,"artifacts":artifacts,"linuxLibrarySha256":sha(linux),"linuxExecuted":False,"hostTestsExecuted":True,"capturedTargetExecuted":False,"runtimeTargetEquivalenceClaimed":False}
(B/"rust-qualification.json").write_text(json.dumps(record,indent=2)+"\n",encoding="utf-8")
print(json.dumps({"rowsPerOptimization":freeze["rows"],"sourceSha256":sourcehash,"mutants":{k:v for k,v in artifacts.items() if k.startswith("mutant")},"repeatHostAndLinuxLibrariesEqual":True,"capturedTargetExecuted":False}),flush=True)
