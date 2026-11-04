from pathlib import Path
import hashlib,json,struct,sys
import argparse
ROOT=Path(__file__).resolve().parents[3]
ap=argparse.ArgumentParser(description="Static Node115 relation and deterministic fixture derivation; never executes the capture.")
ap.add_argument("--target",type=Path,default=ROOT/"artifacts/node/115/hl-node")
ap.add_argument("--out",type=Path,required=True)
args=ap.parse_args()
O=args.out.resolve()
if O.is_relative_to(ROOT) and not O.is_relative_to(ROOT/"work"):
 raise ValueError("Use ignored work/ or an external scratch output, not durable source.")
O.mkdir(parents=True,exist_ok=False)
REF=ROOT/"tools"
for name,want in {"elf_index.py":"f142a7c03b0c2aee07d547cf93b0f6ef4b330b43ec61909d9388f340d0cdd70e","fde_extents.py":"69798abfa12273bf8e3fa0be6e46dcb0a7807f2803287bbaa0916143ae527714"}.items():
 if hashlib.sha256((REF/name).read_bytes()).hexdigest()!=want:raise ValueError("parser identity")
sys.path.insert(0,str(REF))
from elf_index import sections
from fde_extents import eh_frame_records
import capstone
D=args.target.read_bytes()
sha=hashlib.sha256(D).hexdigest()
if sha!="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301":raise ValueError("target identity")
ss=sections(D);_,fs=eh_frame_records(D,ss)
def read(va,n):
 hits=[s["offset"]+va-s["address"] for s in ss if s["type"]!=8 and s["address"]<=va and va+n<=s["address"]+s["size"]]
 if len(hits)!=1:raise ValueError("VA map")
 return D[hits[0]:hits[0]+n]
f=[x for x in fs if x["start"]==0x162a290]
if len(f)!=1 or f[0]["end"]!=0x162a42b:raise ValueError("FDE")
raw=read(f[0]["start"],411)
if hashlib.sha256(raw).hexdigest()!="4e6a48de01cb915adb84718584904b4aa3546e1507b109ac85851f7e2247d0f5":raise ValueError("body")
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);md.detail=True
ins=list(md.disasm(raw,0x162a290));cursor=0x162a290
for i in ins:
 if i.address!=cursor:raise ValueError("partition")
 cursor+=i.size
if cursor!=0x162a42b:raise ValueError("decode end")
table=read(0x46bcaa,401)
# Independent Gregorian count of leap years in years [0,y), not native bytes.
def leaps_before(y):return (y+3)//4-(y+99)//100+(y+399)//400
expected=bytes(leaps_before(y) for y in range(401))
if table!=expected:raise ValueError("Gregorian leap table")
year_rows=0
for year in range(-262144,262144):
 # Native year division by400 uses signed reciprocal and remainder repair.
 product=year*0x51eb851f
 high=product>>39
 quotient=high+((product>>63)&1)
 rem=year-400*quotient
 native_cycle=quotient-(1 if rem<0 else 0)
 native_rem=rem+(400 if rem<0 else 0)
 if (native_cycle,native_rem)!=divmod(year,400):raise ValueError("year quotient")
 if native_cycle*146097+native_rem*365+table[native_rem] != year*365+leaps_before(year):raise ValueError("year day relation")
 year_rows+=1
# Prove positive quotient monotonic intervals; negative high-product correction
# is ceil(m*x/2^90) = -floor(m*(-x)/2^90), without interpreting target code.
magic=0x112e0be826d694b3;bound=(1<<32)-1;intervals=[]
for q in range(5):
 lo=q*1000000000;hi=min((q+1)*1000000000-1,bound)
 if (magic*lo//(1<<90),magic*hi//(1<<90))!=(q,q):raise ValueError("nanos reciprocal")
 intervals.append({"quotient":q,"absoluteDifferenceMin":lo,"absoluteDifferenceMax":hi})
relsec=next(s for s in ss if s["name"]==".rela.dyn")
relocations=[]
for offset in range(relsec["offset"],relsec["offset"]+relsec["size"],24):
 site,info,addend=struct.unpack_from("<QQq",D,offset)
 if site==0x64df848:relocations.append({"entryFileOffset":hex(offset),"siteVA":hex(site),"type":info&0xffffffff,"symbol":info>>32,"addend":hex(addend)})
if len(relocations)!=1 or relocations[0]["type"]!=8 or relocations[0]["addend"]!="0x1681e40":
 raise ValueError("panic call relocation")
location=read(0x6405408,24)
rawpath,pathlen,line,column=struct.unpack("<QQII",location)
if pathlen>1024:raise ValueError("source path limit")
pathrel=[]
for offset in range(relsec["offset"],relsec["offset"]+relsec["size"],24):
 site,info,addend=struct.unpack_from("<QQq",D,offset)
 if site==0x6405408:pathrel.append({"entryFileOffset":hex(offset),"siteVA":hex(site),"type":info&0xffffffff,"symbol":info>>32,"addend":hex(addend)})
if len(pathrel)!=1 or pathrel[0]["type"]!=8 or pathrel[0]["addend"]!="0x44583a":raise ValueError("source path relocation")
pathva=int(pathrel[0]["addend"],16)
pathbytes=read(pathva,pathlen)
panic={"callVA":"0x162a425","slotVA":"0x64df848","targetVA":"0x1681e40","relocations":relocations,
"locationVA":"0x6405408","locationBytes":location.hex(),"sourcePathVA":hex(pathva),"sourcePathRelocations":pathrel,"sourcePathBytes":pathbytes.hex(),"line":line,"column":column,
"closure":"boundary and relocation only; panic helper body/unwind behavior not reconstructed"}
report={"targetSha256":sha,"referenceCommit":"05bc2de303c05525b71e7e257426e741bc66a390","fde":f[0],"bodySha256":hashlib.sha256(raw).hexdigest(),"bodyBytes":len(raw),"panicBoundary":panic,"instructions":[{"address":hex(i.address),"bytes":i.bytes.hex(),"mnemonic":i.mnemonic,"operands":i.op_str} for i in ins],"leapTable":{"address":"0x46bcaa","bytes":401,"sha256":hashlib.sha256(table).hexdigest(),"mathematicalRowsEqual":401},"yearCases":year_rows,"nanosReciprocalIntervals":intervals,"status":"initial static arithmetic qualification; no source implementation or runtime-equivalence claim","targetExecuted":False,"capstoneBinding":capstone.__version__,"capstoneCore":capstone.cs_version(),"coordinateSystem":"ELF linked VAs; no runtime ASLR base"}
(O/"native-intake.json").write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
print(json.dumps({k:v for k,v in report.items() if k!="instructions"}),flush=True)

import re
gnu=ROOT/"research/work-items/RE-008-node115-heartbeat-query-static/0x162a290.objdump.txt"
got=[]
for row in gnu.read_text(encoding="utf-8").splitlines():
 m=re.fullmatch(r"\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)\s*(.*)",row)
 if m:got.append((hex(int(m[1],16)),bytes.fromhex(m[2]).hex()))
if got!=[(i["address"],i["bytes"]) for i in report["instructions"]]:raise ValueError("existing GNU/Capstone partition")
report["reusedGnuExport"]={"path":gnu.relative_to(ROOT).as_posix(),"sha256":hashlib.sha256(gnu.read_bytes()).hexdigest(),"instructions":len(got),"bytes":411}
(O/"native-intake.json").write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")

import random
j=json.loads((O/"native-intake.json").read_text(encoding="utf-8"))
if j["bodySha256"]!="4e6a48de01cb915adb84718584904b4aa3546e1507b109ac85851f7e2247d0f5":raise ValueError("native qualification drift")
ins={int(i["address"],16):bytes.fromhex(i["bytes"]) for i in j["instructions"]}
def imm32(a):return int.from_bytes(ins[a][-4:],"little",signed=True)
y1m=imm32(0x162a2a0);y2m=imm32(0x162a302);ynm=imm32(0x162a3cd)
cycle=imm32(0x162a3f6);daysec=imm32(0x162a403)
magic=int.from_bytes(ins[0x162a38d][-8:],"little",signed=True)
lthreshold=imm32(0x162a352);rthreshold=imm32(0x162a373)
nsmul=imm32(0x162a3ab);nsmask=imm32(0x162a3c4)
# Table is already authenticated against all mathematical Gregorian entries.
# Rebuild its values mathematically; do not transplant it into an implementation.
def leaps(y):return (y+3)//4-(y+99)//100+(y+399)//400
table=[leaps(y) for y in range(401)]
def signed32(x):return x if x<1<<31 else x-(1<<32)
def packed(y,ordinal=1,flags=0):return ((y<<13)|(ordinal<<4)|flags)&0xffffffff
def oracle(left,right):
 def day(w):
  y=signed32(w)>>13;ordinal=(w>>4)&511
  if y%400==0 and ordinal==0:return None
  return y*365+leaps(y)+ordinal
 a=day(left[0]);b=day(right[0])
 if a is None or b is None:return None
 correction=(1 if right[2]>=1000000000 and left[1]>right[1] else 0)-(1 if left[2]>=1000000000 and left[1]<right[1] else 0)
 nanoseconds=(((a-b)*86400+left[1]-right[1]+correction)*1000000000+left[2]-right[2])
 return divmod(nanoseconds,1000000000)
def native_relation(left,right,params=None):
 lm,rm,negm,mag,lt,rt,mul,mask,cyc,ds=(params or (y1m,y2m,ynm,magic,lthreshold,rthreshold,nsmul,nsmask,cycle,daysec))
 def parts(word,m):
  y=signed32(word)>>13
  prod=y*m;q=(prod>>39)+((prod>>63)&1)
  rem=y-400*q
  if not -399<=rem<=399:raise ValueError("counterfactual year remainder outside proved range")
  r=rem+(400 if rem<0 else 0)
  d=r*365+table[r]+((word>>4)&511)
  return y,q,rem,d
 y1,q1,r1,d1=parts(left[0],lm)
 if d1==0:return None
 y2,q2,r2,d2=parts(right[0],rm)
 if d2==0:return None
 np=y2*negm
 negq2=(np>>39)+((np>>63)&1)
 cycles=q1+negq2-(1 if r1<0 else 0)+(1 if r2<0 else 0)
 adjust=-int(left[2]>=lt and left[1]<right[1])
 if right[2]>=rt and left[1]>right[1]:adjust=1
 n=left[2]-right[2];p=n*mag
 q=(p>>90)+int(p<0)
 rem=n-q*mul
 carry=-int(rem<0)
 nanos=((rem&0xffffffff)+(mask if rem<0 else 0))&0xffffffff
 secs=((cycles*cyc+d1-d2)*ds+left[1]-right[1]+q+adjust+carry)
 return secs,nanos
def cases():
 for y in range(-262144,262144):
  yield (packed(y),0,0),(packed(0),0,0),"full-year-left"
  yield (packed(0),0,0),(packed(y),0,0),"full-year-right"
 for y in [-262144,-401,-400,-399,-100,-4,-1,0,1,4,99,100,399,400,401,262143]:
  for o in [0,1,59,60,365,366,367,511]:
   for flags in [0,1,15]:
    yield (packed(y,o,flags),86399,999999999),(packed(y,1,15),0,0),"ordinal-flags"
 secs=[0,1,58,59,60,86399,86400,0xffffffff]
 ns=[0,1,999999999,1000000000,1000000001,1999999999,2000000000,0x7fffffff,0x80000000,0xffffffff]
 for a in secs:
  for b in secs:
   for x in ns:
    for y in ns:yield (packed(2000),a,x),(packed(1999,365),b,y),"nanos-and-seconds"
 rng=random.Random(0x115162a290)
 for n in range(16384):
  yield tuple(rng.randrange(1<<32) for _ in range(3)),tuple(rng.randrange(1<<32) for _ in range(3)),"raw-words"
out=O/"pre-rust-vectors.tsv"
if out.exists():raise ValueError("frozen output already exists")
digest=hashlib.sha256();count=0;groups={};smoke=[]
with out.open("wb") as f:
 for left,right,group in cases():
  want=oracle(left,right);got=native_relation(left,right)
  if got!=want:raise ValueError("relation mismatch "+repr((left,right,want,got)))
  if want is None:expected=(0,0,0)
  else:expected=(1,*want)
  line=("\t".join(map(str,(*left,*right,*expected)))+"\n").encode("ascii")
  f.write(line);digest.update(line);count+=1;groups[group]=groups.get(group,0)+1
  if len(smoke)<8 or group in ["ordinal-flags","nanos-and-seconds","raw-words"] and group not in {x["group"] for x in smoke}:
   smoke.append({"group":group,"left":left,"right":right,"expected":expected})
  if count%131072==0:print("$ freeze checked "+str(count),flush=True)
controls=[]
base=[y1m,y2m,ynm,magic,lthreshold,rthreshold,nsmul,nsmask,cycle,daysec]
# Every selected changed immediate is from a real instruction; demonstrate a
# changed scalar result, not just a hash refusal. No captured code is executed.
for name,at,index,replacement,left,right in [
 ("nanos reciprocal -1",0x162a38d,3,magic-1,(packed(2000),59,1000000000),(packed(2000),59,0)),
 ("left leap boundary +1",0x162a352,4,1000000001,(packed(2000),59,1000000000),(packed(2000),60,0)),
 ("right leap boundary +1",0x162a373,5,1000000001,(packed(2000),60,0),(packed(2000),59,1000000000)),
 ("cycle days +1",0x162a3f6,8,146098,(packed(400),0,0),(packed(0),0,0)),
 ("seconds per day +1",0x162a403,9,86401,(packed(2000,2),0,0),(packed(2000,1),0,0))
]:
 p=list(base);p[index]=replacement
 original=native_relation(left,right);changed=native_relation(left,right,p)
 if original==changed:raise ValueError("ineffective native-operand counterfactual "+name)
 controls.append({"name":name,"nativeSite":hex(at),"replacement":replacement,"left":left,"right":right,"original":original,"changed":changed,"targetExecuted":False})
freeze={"targetSha256":j["targetSha256"],"bodySha256":j["bodySha256"],"vectors":out.name,"rows":count,"groups":groups,"sha256":digest.hexdigest(),"smoke":smoke,"nativeOperandCounterfactuals":controls,"sourceCheckoutExists":True,"rustWritten":True,"observationStage":"post-authorship reproduction; initial pre-Rust observation is separately preserved","comparisonScope":"Whole normal-return raw integer relation against independent wide nanosecond Gregorian arithmetic. Not observed execution, not native ABI/panic equivalence.","rawDomainCaveat":"Includes arbitrary raw packed/date/seconds/nanos words; does not assert reachability or validity as original typed timestamp values."}
(O/"pre-rust-freeze.json").write_text(json.dumps(freeze,indent=2)+"\n",encoding="utf-8")
print(json.dumps({k:v for k,v in freeze.items() if k!="smoke"}),flush=True)
