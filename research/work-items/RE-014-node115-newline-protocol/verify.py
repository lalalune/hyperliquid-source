#!/usr/bin/env python3
"""Regeneration and fresh native/binding controls, never target execution."""
from __future__ import annotations
import argparse, copy, json, subprocess, tempfile
from pathlib import Path
from collect import (Image,RANGES,bind,collect,constants,encode,fde,need,
                     native_rows,partition,sha)
from algebra import certificate,skip,word

def patched(image,off,new):
 fixture=copy.copy(image)
 fixture.data=image.data[:off]+new+image.data[off+len(new):]
 return fixture

def decode_fixture(image,objdump):
 start,end=RANGES["adapter115"][1:3]
 raw=image.at(start,end-start)
 with tempfile.TemporaryDirectory(prefix="newline-mutant-static-")as tmp:
  p=Path(tmp)/"body.bin";p.write_bytes(raw);p.chmod(0o400)
  args=["-D","-b","binary","-m","i386:x86-64","-M","intel","--wide",
        "--insn-width=16",f"--adjust-vma={start}","body.bin"]
  text=subprocess.check_output([objdump]+args,cwd=tmp,text=True)
 return partition(image,text,start,end),text

def verify(root,retained,objdump,readelf,llvm):
 fresh=collect(root,objdump,readelf,llvm)
 image=Image("115",(root/"artifacts/node/115/hl-node").read_bytes())
 fresh["algebra.json"]=encode(certificate(image))
 for name,data in fresh.items():
  need((retained/name).read_bytes()==data,"retained regeneration:"+name)
 rows=native_rows(fresh["adapter115.gnu.txt"].decode())
 controls=[]
 def reject(name,kind,fn,error,**detail):
  try:fn()
  except ValueError as e:
   need(error in str(e),"wrong rejection:"+name+":"+str(e))
   controls.append({"name":name,"kind":kind,"rejectedBy":str(e),**detail})
  else:raise ValueError("accepted control:"+name)
 reject("truncated","identity",lambda:Image("115",image.data[:-1]),"capture identity")
 reject("LFS-pointer","identity",lambda:Image("115",b"version https://git-lfs.github.com/spec/v1\n"),"capture identity")
 off=image.offset(0x1686cb9);fixture=patched(image,off,b"\x0e")
 reject("changed-full-image","identity",lambda:Image("115",fixture.data),"capture identity")
 del fixture
 mutations=[
  ("wide-threshold",0x1686cb9,"0e","witness:wide-threshold"),
  ("stride",0x1686d52,"20","witness:stride-and-limit"),
  ("short-LF",0x1686cd3,"0d","witness:short-LF"),
  ("prefix-LF",0x1686d73,"0d","witness:prefix-LF"),
  ("tail-LF",0x1686da3,"0d","witness:tail-LF"),
  ("short-index-register",0x1686cc6,"ff","witness:short-index-zero"),
  ("first-load-displacement",0x1686d24,"00","witness:first-word"),
  ("flag-store-source",0x1686c43,"09","witness:payload-arguments-and-store"),
  ("flag-store-target",0x1686c43,"02","witness:payload-arguments-and-store"),
  ("payload-method",0x1686c54,"20","witness:payload-arguments-and-store"),
  ("indent-method",0x1686e18,"20","witness:indent-arguments"),
  ("indent-length",0x1686e03,"03","witness:indent-arguments"),
  ("post-payload-flags",0x1686c6b,"03","witness:payload-result-flags"),
  ("restored-cursor",0x1686c57,"e7","witness:payload-result-flags"),
  ("tail-continuation",0x1686c75,"00","witness:header-continuation"),
  ("indent-error-branch",0x1686e1f,"74","complete branch relation"),
  ("payload-error-branch",0x1686c6f,"84","complete branch relation"),
  ("failure-byte",0x1686e36,"02","witness:failure-and-epilogue"),
  ("prefixed-NOP-to-AX-write",0x1686d15,"6666b8ffff909090909090","exact no-op admission"),
  ("wrong-LF-word",0x1686bed,"0b0b0b0b0b0b0b0b","witness:LF-materialization"),
  ("zeroed-C-lane1",0x1686cfe,"00","witness:late-C-preserves-flags"),
  ("missing-high-lane7",0x1686bea,"00","witness:HI-materialization")]
 for name,va,hexnew,error in mutations:
  new=bytes.fromhex(hexnew);off=image.offset(va,len(new))
  old=image.at(va,len(new));need(old!=new,"mutation applied")
  fixture=patched(image,off,new)
  decoded,text=decode_fixture(fixture,objdump)
  affected=[{"va":hex(a),"raw":b.hex(),"text":t}for a,b,t in decoded
            if a<va+len(new) and va<a+len(b)]
  reject(name,"fresh native below-image-hash binding",
         lambda:bind(fixture,decoded),error,va=hex(va),fileOffset=hex(off),
         original=old.hex(),changed=new.hex(),mutantRows=len(decoded),
         nativeSha256=sha(text.encode()),affectedNativeRows=affected)
  # These three controls also carry real scalar false-negative witnesses.
  if name in("wrong-LF-word","zeroed-C-lane1","missing-high-lane7"):
   v=next(v for v in certificate(image)["constantMutationWitnesses"]if v["name"]==name)
   w0,w1=int(v["w0"],16),int(v["w1"],16)
   need(not skip(constants(image),w0,w1) and skip(constants(fixture),w0,w1),
        "actual mutant constant counterexample")
   controls[-1]["mathematicalFalseNegative"]={"w0":hex(w0),"w1":hex(w1),
                                            "baselineSkip":False,"mutantSkip":True}
  if name=="wide-threshold":
   need(fixture.at(0x1686cb9,1)[0]==14 and 15>14 and 16>15,"threshold overread witness")
   controls[-1]["intervalCounterexample"]={"remaining":15,"readBytes":16}
  if name=="stride":
   need(fixture.at(0x1686d52,1)[0]==32 and 32>16,"stride gap witness")
   controls[-1]["intervalCounterexample"]={"unchecked":[16,32],"LFAt":16}
  del fixture,decoded,text
 for name,va,new,error in(
  ("space-literal",0x45a128,b"!", "four-space literal"),
  ("parent-call-displacement",0x167da76,b"\x27","RIP edge:0x167da74"),
  ("table-header",0x6407900,b"\x19","raw fixed table")):
  off=image.offset(va,len(new));fixture=patched(image,off,new)
  reject(name,"below-image-hash data/edge",lambda:bind(fixture,rows),error,
         va=hex(va),fileOffset=hex(off))
  del fixture
 for slot in(0x64e00a0,0x6407910):
  off=image.relas()[slot][2]+16
  fixture=patched(image,off,bytes([image.data[off]^1]))
  reject("RELA-"+hex(slot),"below-image-hash RELA",lambda:bind(fixture,rows),
         "RELA:"+hex(slot),fileOffset=hex(off))
  del fixture
 frames=fresh["adapter115.fde.txt"].decode()
 eh=image.named[".eh_frame"];fa=eh[4]+0x1c7cc
 for name,off,new,error in(
  ("short-FDE",fa,b"\x04","FDE length"),
  ("FDE-CIE-link",fa+4,bytes([image.data[fa+4]^1]),"FDE CIE back-reference"),
  ("CIE-ID",eh[4]+4,b"\x01","CIE identifier")):
  fixture=patched(image,off,new)
  reject(name,"below-image-hash unwind",lambda:fde(fixture,frames,0x1686bd0,0x1686e46,0x1c7cc),
         error,fileOffset=hex(off))
  del fixture
 reject("duplicate-FDE","record",lambda:fde(image,frames+"\n"+frames,0x1686bd0,0x1686e46,0x1c7cc),
        "unique exact FDE")
 # Native exports contain spaced hex; mutate one complete scalar row's byte text.
 text=fresh["adapter115.gnu.txt"].decode()
 bad=text.replace("80 3c 30 0a","80 3c 30 0b",1)
 need(bad!=text,"export mutation applied")
 reject("retained-native-byte","record",lambda:partition(image,bad,0x1686bd0,0x1686e46),"native bytes")
 return {"regeneratedFiles":len(fresh),"retainedBytesMatch":True,"controls":controls,
         "controlCount":len(controls),"identityControls":3,
         "freshNativeControls":len(mutations),"belowHashNonNativeControls":8,
         "recordControls":2,"capturedExecution":False,"instructionEvaluation":False,
         "sourceSha256":{n:sha((Path(__file__).parent/n).read_bytes())
                         for n in("collect.py","algebra.py","verify.py")},
         "limits":"Fresh mutant decoding and named exact binding rejection are not changed-program execution. Five controls additionally have mathematical false-negative/interval witnesses. The conditional higher-order proof remains manual."}

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument("--root",type=Path,default=Path("."))
 p.add_argument("--retained",type=Path,default=Path(__file__).parent/"observed")
 p.add_argument("--output",type=Path,required=True);p.add_argument("--objdump",default="objdump")
 p.add_argument("--readelf",default="readelf");p.add_argument("--llvm",default="llvm-objdump")
 a=p.parse_args();need(not a.output.exists(),"output exists")
 r=verify(a.root,a.retained,a.objdump,a.readelf,a.llvm)
 a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_bytes(encode(r))
 print(f"Retained regeneration matched; {r['controlCount']} controls rejected; no captured execution.")
if __name__=="__main__":main()
