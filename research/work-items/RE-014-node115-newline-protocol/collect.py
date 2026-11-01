#!/usr/bin/env python3
"""Static ELF/native bindings only; no target execution or instruction evaluator."""
from __future__ import annotations
import argparse, hashlib, json, re, struct, subprocess, tempfile
from pathlib import Path

IDENTITIES={
 "94":(91774280,"3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"),
 "115":(105896032,"a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")}
RANGES={
 "adapter115":("115",0x1686bd0,0x1686e46,0x1c7cc),
 "parent115":("115",0x167d950,0x167dad6,0x1bccc),
 "adapter94":("94",0x157d000,0x157d26e,0x19de8)}
BRANCHES={
 0x1686c24:("jmp",0x1686c74),0x1686c6e:("jne",0x1686e35),
 0x1686c76:("jne",0x1686e31),0x1686c7f:("jae",0x1686c90),
 0x1686c88:("jmp",0x1686de3),0x1686c94:("jmp",0x1686cac),
 0x1686ca6:("jb",0x1686de3),0x1686cba:("ja",0x1686cf0),
 0x1686cbf:("je",0x1686de0),0x1686cd4:("je",0x1686db0),
 0x1686ce0:("jne",0x1686cd0),0x1686ce2:("jmp",0x1686de0),
 0x1686d05:("jne",0x1686d60),0x1686d4d:("jne",0x1686d90),
 0x1686d56:("jbe",0x1686d20),0x1686d58:("jmp",0x1686d90),
 0x1686d74:("je",0x1686db0),0x1686d7c:("jne",0x1686d70),
 0x1686d85:("jbe",0x1686d0e),0x1686d9a:("je",0x1686de0),
 0x1686da4:("je",0x1686db0),0x1686dac:("jne",0x1686da0),
 0x1686dae:("jmp",0x1686de0),0x1686dbd:("jae",0x1686ca0),
 0x1686dc7:("jne",0x1686ca0),0x1686dd8:("jmp",0x1686df6),
 0x1686df4:("je",0x1686e31),0x1686e00:("je",0x1686e21),
 0x1686e1f:("jne",0x1686e35),0x1686e24:("jne",0x1686c30),
 0x1686e2c:("jmp",0x1686c38),0x1686e33:("jmp",0x1686e37)}
ANCHORS={
 "HI-materialization":(0x1686be1,"48bb8080808080808080"),
 "LF-materialization":(0x1686beb,"49bc0a0a0a0a0a0a0a0a"),
 "header-continuation":(0x1686c74,"a801"),
 "header-bounds":(0x1686c7c,"4c39f2"),
 "failed-bound-setup":(0x1686c81,"4d89f5488b7dd0"),
 "scan-base":(0x1686c90,"488b7dd0"),
 "retry-setup":(0x1686ca0,"4d89ee4c39ea"),
 "zero-length-compare":(0x1686cbc,"4c39f2"),
 "short-index-zero":(0x1686cc5,"31f6"),
 "short-index-step":(0x1686cda,"48ffc64839f1"),
 "late-C-preserves-flags":(0x1686cfb,"49bd0001010101010101"),
 "prefix-index-zero":(0x1686d60,"31f6"),
 "prefix-index-step":(0x1686d76,"48ffc64939f3"),
 "tail-index-and-base":(0x1686d90,"4c89de4c39d9488b7dd0"),
 "tail-index-step":(0x1686da6,"48ffc64839f1"),
 "frame":(0x1686bd0,"554889e54157415641554154534883ec38"),
 "cached-pointers":(0x1686bf5,"488b4710488945b0488b07488945b8488b4708488945c0"),
 "saved-input":(0x1686c0c,"488975d0488d4608488945a84531f64531ff31c0488955a0"),
 "payload-last-byte":(0x1686c30,"807c1fff0a0f94c0"),
 "payload-arguments-and-store":(0x1686c38,"4c29fb4901ff488b4db08801488b7db84c89fe4889da488b45c0ff5018"),
 "payload-result-flags":(0x1686c55,"4d89ef84c0488b55a04c89e349bc0a0a0a0a0a0a0a0a8b45cc"),
 "live-cursors":(0x1686cac,"4889d14c29f14a8d0437"),
 "wide-threshold":(0x1686cb6,"4883f90f"),
 "short-LF":(0x1686cd0,"803c300a"),
 "alignment":(0x1686cf0,"4c8d58074983e3f84929c3"),
 "block-bound":(0x1686d07,"488d71f04531db"),
 "two-word-base":(0x1686d0e,"488b7da84c01f7"),
 "first-word":(0x1686d20,"4e8b441ff84d89c14d31e14d89ea4d29ca4d09c2"),
 "second-word":(0x1686d34,"4e8b041f4d31e04d89e94d29c14d09c14921da4d21ca4939da"),
 "stride-and-limit":(0x1686d4f,"4983c3104939f3"),
 "prefix-LF":(0x1686d70,"803c300a"),
 "prefix-bound":(0x1686d7e,"488d71f04939f3"),
 "tail-LF":(0x1686da0,"803c300a"),
 "match-end":(0x1686db0,"4e8d2c3649ffc54901f64939d6"),
 "match-recheck":(0x1686dc3,"803c300a"),
 "newline-phase":(0x1686dcd,"4989dc31c04d89ee4c89eb"),
 "tail-phase":(0x1686de0,"4989d54989dcb0014d89ee4d89fd4889d34c39fa"),
 "current-flag":(0x1686df6,"8945cc488b45b0803800"),
 "indent-arguments":(0x1686e02,"ba04000000488b7db8488d351633ddfe488b45c0ff5018"),
 "indent-result":(0x1686e19,"488b7dd084c0"),
 "piece-nonempty":(0x1686e21,"4c39fb"),
 "empty-payload-predicate":(0x1686e2a,"31c0"),
 "success-result":(0x1686e31,"31c0"),
 "failure-and-epilogue":(0x1686e35,"b0014883c4385b415c415d415e415f5dc3")}
SLOTS={0x64e00a0:0x1686bd0,0x6407910:0x1686bd0,
       0x6407918:0x1686b70,0x6407920:0x168aa10}
NOPS={0x1686c26:"662e0f1f840000000000",0x1686c8d:"0f1f00",
 0x1686c96:"662e0f1f840000000000",0x1686cc7:"660f1f840000000000",
 0x1686ce7:"660f1f840000000000",0x1686d15:"66662e0f1f840000000000",
 0x1686d5a:"660f1f440000",0x1686d62:"66666666662e0f1f840000000000",
 0x1686d87:"660f1f840000000000",0x1686d9c:"0f1f4000",0x1686dda:"660f1f440000"}

def need(ok,message):
 if not ok: raise ValueError(message)
def sha(b): return hashlib.sha256(b).hexdigest()
def encode(j): return (json.dumps(j,indent=2,sort_keys=True)+"\n").encode()

class Image:
 def __init__(self,release,data):
  size,digest=IDENTITIES[release]
  need(len(data)==size and sha(data)==digest,"capture identity:"+release)
  self.release,self.data=release,data
  ph=struct.unpack_from("<Q",data,32)[0]; stride,count=struct.unpack_from("<HH",data,54)
  self.loads=[struct.unpack_from("<IIQQQQQQ",data,ph+i*stride)for i in range(count)]
  sh=struct.unpack_from("<Q",data,40)[0]; stride,count,ni=struct.unpack_from("<HHH",data,58)
  self.sections=[struct.unpack_from("<IIQQQQIIQQ",data,sh+i*stride)for i in range(count)]
  ns=self.sections[ni]; names=data[ns[4]:ns[4]+ns[5]]
  self.named={names[s[0]:names.index(0,s[0])].decode():s for s in self.sections}
 def offset(self,va,n=1,code=False):
  ps=[p for p in self.loads if p[0]==1 and p[3]<=va and va+n<=p[3]+p[5]]
  need(len(ps)==1 and(not code or ps[0][1]&1),"PT_LOAD range")
  return ps[0][2]+va-ps[0][3]
 def at(self,va,n):
  off=self.offset(va,n);return self.data[off:off+n]
 def relas(self):
  found={}
  for s in self.sections:
   if s[1]!=4:continue
   for off in range(s[4],s[4]+s[5],s[9]):
    va,info,addend=struct.unpack_from("<QQq",self.data,off)
    if va in SLOTS:
     need(va not in found,"duplicate selected RELA")
     found[va]=(info,addend,off)
  return found

def native_rows(text):
 out=[]
 for line in text.splitlines():
  m=re.match(r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(.*)$",line)
  if m:out.append((int(m[1],16),bytes.fromhex(m[2]),m[3].strip()))
 return out

def partition(image,text,start,end):
 rows=native_rows(text);cursor=start
 for va,raw,_ in rows:
  need(va==cursor and raw and va+len(raw)<=end,"native partition")
  need(raw==image.at(va,len(raw)),"native bytes")
  cursor+=len(raw)
 need(cursor==end,"native completeness")
 return rows

def branches(rows):
 result={}
 for va,raw,asm in rows:
  if asm.split()[0].startswith("j"):
   m=re.match(r"(j\w+)\s+(?:0x)?([0-9a-f]+)",asm)
   need(m is not None,"branch decode")
   result[va]=(m[1],int(m[2],16))
 return result

def constants(image):
 return {"HI":struct.unpack("<Q",image.at(0x1686be3,8))[0],
         "LFWORD":struct.unpack("<Q",image.at(0x1686bed,8))[0],
         "C":struct.unpack("<Q",image.at(0x1686cfd,8))[0],
         "restoredLFWORD":struct.unpack("<Q",image.at(0x1686c63,8))[0]}

def bind(image,rows):
 # This seam deliberately has no whole-image or whole-body identity check.
 # Production authenticates first; private mutants test these bindings directly.
 for name,(va,want) in ANCHORS.items():
  need(image.at(va,len(bytes.fromhex(want))).hex()==want,"witness:"+name)
 need(branches(rows)==BRANCHES,"complete branch relation")
 for va,(_,target)in BRANCHES.items():
  need(target in {a for a,_,_ in rows},"branch boundary")
 calls=[(a,b.hex())for a,b,t in rows if t.split()[0]=="call"]
 need(calls==[(0x1686c52,"ff5018"),(0x1686e16,"ff5018")],"two fresh-method calls")
 need([(a,b.hex())for a,b,t in rows if t.split()[0]=="ret"]==[(0x1686e45,"c3")],"single RET")
 roles={}
 for va,raw,asm in rows:
  covered=[k for k,(a,h)in ANCHORS.items()
           if a<=va and va+len(raw)<=a+len(bytes.fromhex(h))]
  if va in BRANCHES:covered.append("branch:"+BRANCHES[va][0])
  if va in NOPS:
   need(raw.hex()==NOPS[va] and re.search(r"\bnop\b",asm),"exact no-op admission")
   covered.append("exact-no-op")
  need(covered,"unaccounted native row:"+hex(va))
  roles[hex(va)]=covered
 c=constants(image)
 need(c=={"HI":0x8080808080808080,"LFWORD":0x0a0a0a0a0a0a0a0a,
          "C":0x0101010101010100,"restoredLFWORD":0x0a0a0a0a0a0a0a0a},"word constants")
 need(image.at(0x45a128,4)==b"    ","four-space literal")
 # Fixed parent edges are not the generic callback's incoming V.
 for va,op,off,size,target in (
  (0x167da69,b"\x48\x8d\x05",3,7,0x64078f8),
  (0x167da74,b"\xff\x15",2,6,0x64e00a0),
  (0x167da92,b"\xff\x15",2,6,0x64e00a0),
  (0x1686e0b,b"\x48\x8d\x35",3,7,0x45a128)):
  need(image.at(va,len(op))==op and
       va+size+struct.unpack("<i",image.at(va+off,4))[0]==target,"RIP edge:"+hex(va))
 need(image.at(0x64078f8,48)==struct.pack("<6Q",0,24,8,0,0,0),"raw fixed table")
 rel=image.relas()
 for slot,target in SLOTS.items():
  image.offset(slot,8)
  need(slot in rel and rel[slot][:2]==(8,target),"RELA:"+hex(slot))
 writes=[(a,t)for a,_,t in rows if re.match(r"mov\s+(?:BYTE|DWORD|QWORD) PTR \[",t)]
 need(len(writes)==8 and sum("[rbp" in t for _,t in writes)==7,"explicit store inventory")
 return {"constants":{k:hex(v)for k,v in c.items()},"nativeRowRoles":roles,
         "anchors":{k:{"va":hex(v[0]),"raw":v[1]}for k,v in ANCHORS.items()},
         "explicitStores":[{"va":hex(a),"text":t}for a,t in writes],
         "relocations":{hex(k):{"type":v[0],"addend":hex(v[1]),"fileOffset":hex(v[2]),
                               "raw":image.data[v[2]:v[2]+24].hex()}for k,v in rel.items()},
         "table":{"va":"0x64078f8","raw":image.at(0x64078f8,48).hex()},
         "literal":{"va":"0x45a128","raw":"20202020"},
         "branchCount":len(BRANCHES),"callbackSites":["0x1686c52","0x1686e16"]}

def fde(image,frames,start,end,expected):
 pattern=r"(?m)^([0-9a-f]+) ([0-9a-f]+) [0-9a-f]+ FDE cie=([0-9a-f]+) pc=([0-9a-f]+)\.\.([0-9a-f]+)"
 ms=[m for m in re.finditer(pattern,frames)if(int(m[4],16),int(m[5],16))==(start,end)]
 need(len(ms)==1,"unique exact FDE")
 m=ms[0];off,size,cie=int(m[1],16),int(m[2],16)+4,int(m[3],16)
 need(off==expected and size==44 and cie==0,"selected FDE/CIE coordinates")
 sec=image.named[".eh_frame"];at=sec[4]+off
 need(off+4<=sec[5] and struct.unpack_from("<I",image.data,at)[0]+4==size
      and off+size<=sec[5],"FDE length")
 raw=image.data[at:at+size]
 need(off+4-struct.unpack_from("<I",raw,4)[0]==cie,"FDE CIE back-reference")
 ca=sec[4]+cie;cs=struct.unpack_from("<I",image.data,ca)[0]+4
 need(8<=cs and cie+cs<=sec[5],"CIE bounds")
 cr=image.data[ca:ca+cs];need(struct.unpack_from("<I",cr,4)[0]==0,"CIE identifier")
 record={"fileOffset":hex(at),"sectionOffset":hex(off),"raw":raw.hex(),"sha256":sha(raw),
         "cie":{"fileOffset":hex(ca),"sectionOffset":hex(cie),"raw":cr.hex(),"sha256":sha(cr)}}
 block=frames[m.start():frames.find("\n\n",m.start())]+"\n"
 return record,block

def collect(root,objdump,readelf,llvm):
 files,records,images={},{},{}
 versions={name:subprocess.check_output([tool,"--version"],text=True).splitlines()[0]
           for name,tool in(("GNU",objdump),("readelf",readelf),("LLVM",llvm))}
 need("GNU" in versions["GNU"] and"GNU" in versions["readelf"],"GNU tools required")
 for release in("115","94"):
  image=Image(release,(root/f"artifacts/node/{release}/hl-node").read_bytes())
  images[release]=image
  with tempfile.TemporaryDirectory(prefix="node-newline-static-")as tmp:
   target=Path(tmp)/"node.elf";target.write_bytes(image.data);target.chmod(0o400)
   frame_text=subprocess.check_output([readelf,"--debug-dump=frames","node.elf"],cwd=tmp,text=True)
   for name,(rel,start,end,fo)in RANGES.items():
    if rel!=release:continue
    image.offset(start,end-start,code=True)
    fr,ft=fde(image,frame_text,start,end,fo);files[name+".fde.txt"]=ft.encode()
    options=[f"--start-address={start:#x}",f"--stop-address={end:#x}","node.elf"]
    gargs=["-d","-w","-M","intel","--insn-width=16"]+options
    largs=["-d","--x86-asm-syntax=intel"]+options
    gt=subprocess.check_output([objdump]+gargs,cwd=tmp,text=True)
    lt=subprocess.check_output([llvm]+largs,cwd=tmp,text=True)
    gr=partition(image,gt,start,end);lr=partition(image,lt,start,end)
    need([(a,b)for a,b,_ in gr]==[(a,b)for a,b,_ in lr],"GNU/LLVM byte partitions")
    files[name+".gnu.txt"]=gt.encode();files[name+".llvm.txt"]=lt.encode()
    rec={"release":release,"startVA":hex(start),"endVA":hex(end),"bytes":end-start,
         "fileOffset":hex(image.offset(start,end-start)),"bodySha256":sha(image.at(start,end-start)),
         "rows":len(gr),"fde":fr,"gnuCommand":["objdump"]+gargs,"llvmCommand":["llvm-objdump"]+largs,
         "gnuSha256":sha(gt.encode()),"llvmSha256":sha(lt.encode())}
    if name=="adapter115":rec["bindings"]=bind(image,gr)
    records[name]=rec
   need(target.read_bytes()==image.data,"snapshot changed")
 data={"schema":1,"sourceBase":"56c0ec672bd8fdcfaa80f2db700a61e6240b3663",
       "identities":{k:{"bytes":v[0],"sha256":v[1]}for k,v in IDENTITIES.items()},
       "ranges":records,"versions":versions,"capturedExecution":False,"emulation":False,
       "newRecoveryCredit":0,"normalizedByteEquivalenceClaim":False}
 files["records.json"]=encode(data)
 return files

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument("--root",type=Path,default=Path("."))
 p.add_argument("--output",type=Path,required=True)
 p.add_argument("--objdump",default="objdump");p.add_argument("--readelf",default="readelf")
 p.add_argument("--llvm",default="llvm-objdump");a=p.parse_args()
 need(not a.output.exists(),"output exists; preserve receipts")
 files=collect(a.root,a.objdump,a.readelf,a.llvm);a.output.mkdir(parents=True)
 for name,data in files.items():(a.output/name).write_bytes(data)
 print("Three complete FDE bodies bound; GNU/LLVM byte partitions agree; target not executed.")
if __name__=="__main__":main()
