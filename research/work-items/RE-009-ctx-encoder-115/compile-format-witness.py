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
frames=json.loads((O/"contexts.json").read_text(encoding="utf-8"))["records"]
def captured(frame,site,size):
 f=next(f for f in frames if f["start"]==frame);r=next(x for x in f["instructions"] if x["va"]==site)["ripReferences"][0]
 return {"va":r["va"],"bytes":bytes.fromhex(r["raw32"])[:size].hex()}
patterns={"year":captured("0x1628bc0","0x1628ce4",8),"frac3":captured("0x162a760","0x162a949",10),"frac6":captured("0x162a760","0x162a977",10),"frac9":captured("0x162a760","0x162a917",10)}
cases=[("year","i32","{value:+05}","year",True),("frac3","u32",".{value:03}","frac3",True),("frac6","u32",".{value:06}","frac6",True),("frac9","u32",".{value:09}","frac9",True),("year_no_plus","i32","{value:05}","year",False),("year_no_zero","i32","{value:+5}","year",False),("year_width4","i32","{value:+04}","year",False)]
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
 command=[str(RUST),"--crate-type=lib","--edition=2024","--crate-name","ctx_witness_"+name,"--target","x86_64-pc-windows-gnullvm","-C","opt-level=2","-C","debuginfo=0","--emit=obj","--remap-path-prefix",O.as_posix()+"=/research-operator",src.as_posix(),"-o",obj.as_posix()]
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
result={"rustcVersion":version,"rustcSha256":hashlib.sha256(RUST.read_bytes()).hexdigest(),"targetObject":"x86_64-pc-windows-gnullvm COFF","targetCapture":"Node115 Linux x86-64 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301","comparison":"Static format-description data only, no machine-code/ELF equivalence claim","cases":results,"allControlsPassed":all(x["controlPassed"] for x in results),"capturedCodeExecuted":False,"capturedCodeEmulated":False,"ownWitnessCodeExecuted":False,"witnessIsNotProductionCtxCode":True}
(OUT/"format-descriptor-witness.json").write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8",newline="\n")
if not result["allControlsPassed"]:raise ValueError("format-description controls differ; retain uncertainty, do not force semantics")
