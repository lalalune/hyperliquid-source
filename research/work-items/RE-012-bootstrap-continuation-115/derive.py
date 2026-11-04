"""Reproduce scalar vectors after authorship; initial freeze is a separate immutable receipt."""
from pathlib import Path
import argparse,hashlib,json,random
from native import observe
ROOT=Path(__file__).resolve().parents[3]
ap=argparse.ArgumentParser();ap.add_argument("--out",type=Path,required=True);ap.add_argument("--target",type=Path)
args=ap.parse_args();O=args.out.resolve()
if O.is_relative_to(ROOT) and not O.is_relative_to(ROOT/"work"):raise ValueError("use ignored work or external output")
O.mkdir(parents=True,exist_ok=False)
observe(ROOT,args.target or ROOT/"artifacts/node/115/hl-node",O)
native=json.loads((O/"static-intake.json").read_text(encoding="utf-8"))
cross=json.loads((O/"gnu-crosscheck.json").read_text(encoding="utf-8"))
if native["bodySha256"]!="993bd9a168f2e37e4cdc80092c5ea5e68a3bc0225098621c57e89fccb7bf57fc" or not cross["allBytesAndBoundariesMatchCapstone"]:raise ValueError("native owner binding")
rows=json.loads((O/"instructions.json").read_text());ins={int(r["va"],16):r for r in rows}
def raw(at):return bytes.fromhex(ins[at]["bytes"])
threshold=int.from_bytes(raw(0x5a883a1)[-4:],"little")
sub_delta=int.from_bytes(raw(0x5a8302e)[-1:],"little",signed=True)
add_delta=int.from_bytes(raw(0x5a83037)[-1:],"little",signed=True)
tagbase=int.from_bytes(raw(0x5a883fd)[-8:],"little")
U=(1<<64)-1
if (threshold,sub_delta,add_delta,tagbase)!=(30001,-99,99,1<<63):raise ValueError("encoded constants")
for at,text in [(0x5a8816c,"rcx"),(0x5a83001,"rdx"),(0x5a8841d,"rdx")]:
 if ins[at]["mnemonic"]!="inc" or ins[at]["operands"]!=text:raise ValueError("INC identity")
if ins[0x5a88436]["mnemonic"]!="jne":raise ValueError("completion branch")
def increment_native(v,enabled=True):
 if not enabled:return v
 x=(v+1)&U
 return x if x else U
def native_window(first,target,sub=sub_delta,add=add_delta):
 subtract=sub&U
 d=(first-subtract)&U
 if first>=subtract:
  total=(first+add)&U
  d=U if total<first else total
 return min(target,d)
def native_relation(op,args,change=None):
 if op in ["I","N"]:
  previous,target=args
  first=increment_native(previous,change!=op+"-no-inc")
  if op=="I":
   diff=(target-first)&U
   if target>=first and diff>=threshold:return (first,"S",0,0)
  if first>target:return (first,"R",0,0)
  endpoint=native_window(first,target,sub_delta+1 if change=="sub-window" else sub_delta)
  return (first,"W",first,endpoint)
 has_record,fallback,tag,a,b,target=args
 expected=fallback
 if has_record:
  magic=(tagbase+1+(change=="tag-plus-one"))&U
  value=a if tag==magic else b
  expected=increment_native(value,change!="C-no-inc")
 match=int(expected==target)
 if change=="comparison-inverted":match=1-match
 return expected,match
def oracle(op,args):
 # Wide mathematical operations, not the native repaired carry/subtraction path.
 if op in ["I","N"]:
  previous,target=args;first=min(U,previous+1)
  if op=="I" and target-first>30000:return first,"S",0,0
  if first>target:return first,"R",0,0
  return first,"W",first,min(target,first+99)
 has_record,fallback,tag,a,b,target=args
 value=(min(U,(a if tag==(1<<63)+1 else b)+1) if has_record else fallback)
 return value,int(value==target)
bounds=[0,1,2,98,99,100,101,29998,29999,30000,30001,30002,(1<<31)-1,(1<<32)-1,(1<<63)-1,1<<63,(1<<63)+1,U-101,U-100,U-99,U-98,U-1,U]
tags=[0,1,(1<<63)-1,1<<63,(1<<63)+1,(1<<63)+2,U]
leaves=[0,1,98,99,(1<<63)-1,U-1,U]
def cases():
 for op in ["I","N"]:
  for previous in bounds:
   for target in bounds:yield op,(previous,target),op+"-boundary"
  rng=random.Random(0x1155a883c4+(op=="N"))
  for k in range(100000):
   previous=rng.randrange(1<<64);first=min(U,previous+1)
   target=(rng.randrange(1<<64) if k%3==0 else (first+rng.randint(-30100,30100))&U)
   yield op,(previous,target),op+"-raw64"
 for has in [0,1]:
  for fallback in [0,1,U]:
   for tag in tags:
    for a in leaves:
     for b in leaves:
      for target in [0,1,U]:yield "C",(has,fallback,tag,a,b,target),"C-boundary"
 rng=random.Random(0x1155a88433)
 for k in range(100000):
  has=rng.randrange(2);fallback=rng.randrange(1<<64);tag=(rng.choice(tags) if k%2 else rng.randrange(1<<64));a=rng.randrange(1<<64);b=rng.randrange(1<<64)
  expected=min(U,(a if tag==(1<<63)+1 else b)+1) if has else fallback
  target=expected if k%2 else rng.randrange(1<<64)
  yield "C",(has,fallback,tag,a,b,target),"C-raw64"
out=O/"frozen-vectors.tsv"
if out.exists():raise ValueError("freeze output already exists")
digest=hashlib.sha256();groups={};count=0
with out.open("xb") as stream:
 for op,args,group in cases():
  expected=oracle(op,args)
  if native_relation(op,args)!=expected:raise ValueError("static relation divergence "+repr((op,args)))
  line=("\t".join(map(str,(op,*args,*expected)))+"\n").encode("ascii")
  stream.write(line);digest.update(line);count+=1;groups[group]=groups.get(group,0)+1
  if count%131072==0:print("$ frozen "+str(count),flush=True)
controls=[]
for name,site,op,args,change in [
 ("fresh increment removed","0x5a8816c","I",(0,1),"I-no-inc"),
 ("loop increment removed","0x5a83001","N",(10,15),"N-no-inc"),
 ("window SUB immediate -99 to -98","0x5a8302e","N",(1,1000),"sub-window"),
 ("completion tag immediate +1","0x5a883fd","C",(1,0,(1<<63)+1,8,19,9),"tag-plus-one"),
 ("record increment removed","0x5a8841d","C",(1,0,0,0,U-1,U),"C-no-inc"),
 ("completion JNE inverted","0x5a88436","C",(0,17,0,0,0,17),"comparison-inverted")
]:
 correct=native_relation(op,args);wrong=native_relation(op,args,change)
 if correct==wrong:raise ValueError("ineffective operand/branch control")
 controls.append({"name":name,"nativeSite":site,"siteBytes":ins[int(site,16)]["bytes"],"operation":op,"inputs":args,"original":correct,"counterfactual":wrong,"method":"Changed static lowering at actual selected INC/immediate/Jcc; no captured instruction execution/emulation."})
baseline=(ROOT/"src/node115-bootstrap-range/lib.rs").read_bytes()
record={"targetSha256":native["targetSha256"],"bodySha256":native["bodySha256"],"baseHead":"05bc2de303c05525b71e7e257426e741bc66a390","baselineRustSha256":hashlib.sha256(baseline).hexdigest(),"existingBaseRustAcknowledged":True,"newCheckoutExists":True,"newRustExtensionWritten":True,"observationStage":"post-authorship reproduction; initial freeze preserved separately","rows":count,"groups":groups,"vectorsSha256":digest.hexdigest(),"vectorsFile":out.name,"operationContract":{"I":"Fresh saturated predecessor+1 then existing initial span/window relation","N":"Saturated old endpoint+1, no initial span recheck, then range or reversed route","C":"Conditional fallback/last-record projection and equality gate; NOT whole bootstrap completion or native memory/return ABI"},"premises":["C has_record=0 denotes the observed zero-length or zero last-entry-address fallback, not a null loaded record pointer.","Record values project qualified readable fields +0x28/+0x60/+0xb0, not original recovered types.","Opaque call memory effects, whole async states and execution waiter behavior remain outside these value projections.","No newly invented fixture result or captured-target differential execution claim; same-author mathematical vs native-derived arithmetic forms."],"nativeCounterfactuals":controls,"capturedTargetExecutedOrEmulated":False}
with (O/"derived.json").open("x",encoding="utf-8") as f:json.dump(record,f,indent=2);f.write("\n")
print(json.dumps({"rows":count,"groups":groups,"sha256":digest.hexdigest(),"counterfactuals":len(controls),"newRustExtensionWritten":True}),flush=True)
