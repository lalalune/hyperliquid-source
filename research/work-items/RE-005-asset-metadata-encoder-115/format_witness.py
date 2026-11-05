"""Compile independent format specifications and compare only COFF data bytes."""
from pathlib import Path
import argparse,hashlib,json,struct,subprocess,sys
O=Path(__file__).resolve().parent
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument("--rustc",type=Path,required=True)
parser.add_argument("--out-dir",type=Path,required=True)
args=parser.parse_args()
OUT=args.out_dir;OUT.mkdir(parents=True,exist_ok=True)
RUST=args.rustc
assert hashlib.sha256(RUST.read_bytes()).hexdigest()=="0b7e1e79d7b3c7322d8e4bf71dacfae2f64c1279bcbaf7d6060fb1b21bd8129e"
version=subprocess.run([str(RUST),"-vV"],capture_output=True,timeout=15,check=True).stdout.decode()
(OUT/"rustc-version.txt").write_text(version,encoding="utf-8",newline="\n")
frames=json.loads((O/"native.json").read_text(encoding="utf-8"))["records"]
frame=next(x for x in frames if x["start"]=="0x44a61d0")
reference=next(x for x in frame["ripReferences"] if x["target"]=="0x459898")
patterns={"fee":{"va":"0x459898","bytes":reference["raw64"][:16]}}
cases=[("precision10","f64","{value:.10}","fee",True),("precision9","f64","{value:.9}","fee",False),("precision11","f64","{value:.11}","fee",False),("default","f64","{value}","fee",False),("plus_precision10","f64","{value:+.10}","fee",False),("lower_exp10","f64","{value:.10e}","fee",True),("upper_exp10","f64","{value:.10E}","fee",True)]
def rdata_sections(data):
 machine,count,_,symbols,nsyms,optional,_=struct.unpack_from("<HHIIIHH",data)
 assert machine==0x8664 and optional==0,"expected native AMD64 COFF object"
 stringbase=symbols+nsyms*18
 result=[]
 for index in range(count):
  base=20+index*40;name=data[base:base+8].rstrip(b"\0")
  if name.startswith(b"/"):
   pos=stringbase+int(name[1:]);end=data.find(b"\0",pos);assert end>=pos;name=data[pos:end]
  name=name.decode("utf-8")
  size,pos=struct.unpack_from("<II",data,base+16)
  assert pos+size<=len(data)
  if name.startswith(".rdata"):result.append((name,pos,data[pos:pos+size]))
 return result
results=[]
for name,typ,fmt,key,expected in cases:
 print("$ compile independent formatting witness "+name,flush=True)
 src=OUT/(name+".rs");obj=OUT/(name+".obj")
 text='#![crate_type="lib"]\n#[unsafe(no_mangle)]\n#[inline(never)]\npub fn witness(value: '+typ+') -> String { format!("'+fmt+'") }\n'
 src.write_text(text,encoding="utf-8",newline="\n")
 command=[str(RUST),"--crate-type=lib","--edition=2024","--crate-name","metadata_witness_"+name,"--target","x86_64-pc-windows-gnullvm","-C","opt-level=2","-C","debuginfo=0","--emit=obj","--remap-path-prefix",O.as_posix()+"=/research-operator",src.as_posix(),"-o",obj.as_posix()]
 p=subprocess.run(command,capture_output=True,timeout=90)
 (OUT/(name+".stdout")).write_bytes(p.stdout);(OUT/(name+".stderr")).write_bytes(p.stderr)
 if p.returncode:raise ValueError("independent witness compilation failed "+name)
 data=obj.read_bytes();wanted=bytes.fromhex(patterns[key]["bytes"]);matches=[];short=[]
 for section,pos,raw in rdata_sections(data):
  cursor=0
  while True:
   at=raw.find(wanted,cursor)
   if at<0:break
   matches.append({"section":section,"sectionOffset":at,"objectFileOffset":pos+at,"sectionSize":len(raw),"entireSection":raw==wanted});cursor=at+1
  if 0<len(raw)<=32:short.append({"section":section,"objectFileOffset":pos,"raw":raw.hex()})
 observed=bool(matches)
 results.append({"name":name,"inputType":typ,"formatSpecification":fmt,"sourceSha256":hashlib.sha256(src.read_bytes()).hexdigest(),"objectSha256":hashlib.sha256(data).hexdigest(),"capturePattern":patterns[key],"expectedMatch":expected,"observedMatch":observed,"controlPassed":observed==expected,"matches":matches,"smallRdata":short})
 print(json.dumps({"name":name,"expected":expected,"observed":observed,"controlsPassed":observed==expected}),flush=True)
result={"rustcVersion":version,"rustcSha256":hashlib.sha256(RUST.read_bytes()).hexdigest(),"targetObject":"x86_64-pc-windows-gnullvm COFF","targetCapture":"Node115 Linux x86-64 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301","comparison":"Static precision/flags descriptor data only. Display/LowerExp/UpperExp callback identity remains a separate native evidence obligation. No machine-code/ELF equivalence claim.","cases":results,"allControlsPassed":all(x["controlPassed"] for x in results),"capturedCodeExecuted":False,"capturedCodeEmulated":False,"ownWitnessCodeExecuted":False,"witnessIsNotProductionMetadataCode":True}
(OUT/"fee-format-descriptor-witness.json").write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8",newline="\n")
if not result["allControlsPassed"]:raise ValueError("format-description controls differ; retain uncertainty, do not force semantics")
