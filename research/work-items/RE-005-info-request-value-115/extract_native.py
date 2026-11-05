"""Collect complete selected FDEs and relocation records; never run captured code."""
from pathlib import Path
import argparse,hashlib,json,struct,subprocess,sys
ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/"tools"))
from elf_index import sections
from fde_extents import eh_frame_records
import capstone
from capstone.x86_const import X86_OP_MEM,X86_OP_IMM,X86_REG_RIP
p=argparse.ArgumentParser()
p.add_argument("--target",required=True,type=Path);p.add_argument("--objdump",required=True,type=Path)
p.add_argument("--output",required=True,type=Path);a=p.parse_args()
O=a.output;O.mkdir(parents=True,exist_ok=True)
target=a.target;b=target.read_bytes()
STARTS=(0x273bf30,0x2773bd0,0x26eb010,0x26eb1d0,0x26eb390,0x26eb5e0,0x26eb830,0x26eba60,0x26ebcc0,0x26ebe80,0x26ec100,0x26ec2b0,0x2780510,0x5c558a0,0x5c55a00,0x26f3fc0,0x26ae950,0x26b1890,0x273f3b0,0x2ecf9d0,0x2b6cb40,0x2e3ed10,0x2eabb50)
sha=hashlib.sha256(b).hexdigest();assert sha=="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
ss=sections(b);_,fdes=eh_frame_records(b)
def offset(va,n):
 rows=[s["offset"]+va-s["address"] for s in ss if s["type"]!=8 and s["address"]<=va and va+n<=s["address"]+s["size"]]
 assert len(rows)==1,(hex(va),n);return rows[0]
def read(va,n):
 pos=offset(va,n);return b[pos:pos+n]
engine=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);engine.detail=True
objdump=a.objdump
objdump_version=subprocess.run([str(objdump),"--version"],capture_output=True,timeout=30,check=True).stdout.decode().splitlines()[0]
records=[];text=[];gnu=[];wanted=set();total=0
for start in sorted(STARTS):
 fs=[f for f in fdes if f["start"]==start];assert len(fs)==1,hex(start)
 end=fs[0]["end"];length=end-start
 assert 0<length<=131072,"review finite body budget before expanding"
 total+=length;assert total<=524288,"review total static body budget"
 code=read(start,length);ins=list(engine.disasm(code,start))
 assert ins and ins[0].address==start and sum(i.size for i in ins)==length
 assert all(x.address+x.size==y.address for x,y in zip(ins,ins[1:]))
 rows=[];refs=[];calls=[]
 for i in ins:
  rows.append({"address":hex(i.address),"bytes":bytes(i.bytes).hex(),"mnemonic":i.mnemonic,"operands":i.op_str})
  if i.mnemonic in {"call","jmp"} and i.operands and i.operands[0].type==X86_OP_IMM:
   dest=i.operands[0].imm
   if not start<=dest<end:calls.append({"site":hex(i.address),"kind":i.mnemonic,"target":hex(dest)})
  for op in i.operands:
   if op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP:
    dest=i.address+i.size+op.mem.disp;wanted.add(dest)
    try:chunk=read(dest,64)
    except AssertionError:continue
    refs.append({"site":hex(i.address),"target":hex(dest),"raw64":chunk.hex()})
  text.append(f"{i.address:08x}: {bytes(i.bytes).hex():32} {i.mnemonic} {i.op_str}".rstrip())
 if True:
  command=[str(objdump),"-d","-w","--insn-width=16","-M","intel","--start-address="+hex(start),"--stop-address="+hex(end),str(target)]
  out=subprocess.run(command,capture_output=True,timeout=30,check=True).stdout.decode().replace("\r\n","\n")
  gnu.append(out.replace(str(target),"TARGET_INPUT"))
  import re
  parsed=[]
  for line in out.splitlines():
   m=re.match(r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}(?:\s+|$))+)",line)
   if m:parsed.append((int(m[1],16),bytes.fromhex(m[2])))
  assert parsed==[(i.address,bytes(i.bytes)) for i in ins],hex(start)
 records.append({"start":hex(start),"end":hex(end),"fileOffset":offset(start,length),"bytes":length,
  "sha256":hashlib.sha256(code).hexdigest(),"instructions":rows,"ripReferences":refs,
  "externalDirectControlTransfers":calls,"gnuBytePartitionCompared":True})
 text.append("");print(hex(start),length,len(rows),"instructions; GNU",True,flush=True)
rel=next(s for s in ss if s["name"]==".rela.dyn");ds=next(s for s in ss if s["name"]==".dynsym");dt=next(s for s in ss if s["name"]==".dynstr");relocations=[]
for at,info,addend in struct.iter_unpack("<QQq",memoryview(b)[rel["offset"]:rel["offset"]+rel["size"]]):
 if at not in wanted:continue
 r={"slot":hex(at),"type":info&0xffffffff,"addend":hex(addend)}
 if info&0xffffffff==8:
  f=[f for f in fdes if f["start"]==addend];r["exactFunctionStart"]=len(f)==1
  if f:r["functionEnd"]=hex(f[0]["end"])
  else:
   try:chunk=read(addend,256);r["dataHex"]=chunk.hex()
   except AssertionError:pass
 if info>>32:
  pos=ds["offset"]+24*(info>>32);name=struct.unpack_from("<I",b,pos)[0];begin=dt["offset"]+name;end=b.find(b"\0",begin,dt["offset"]+dt["size"]);assert end>=begin;r["symbol"]=b[begin:end].decode()
 relocations.append(r)
root=next(r for r in records if r["start"]=="0x273bf30")
boundaries={int(i["address"],16) for i in root["instructions"]}
dispatch=[]
for index in range(55):
 slot=0x5f45d0+index*4;raw=read(slot,4);destination=0x5f45d0+struct.unpack("<i",raw)[0]
 assert destination in boundaries
 dispatch.append({"index":index,"slot":hex(slot),"fileOffset":offset(slot,4),"bytes":raw.hex(),"destination":hex(destination)})
result={"dispatch":dispatch,"data":{"hexAlphabet":read(0x455d40,16).hex(),"hexAlphabetVa":"0x455d40","hexAlphabetFileOffset":offset(0x455d40,16)},"targetSha256":sha,"base":"05bc2de303c05525b71e7e257426e741bc66a390","records":records,"relocations":relocations,
 "tools":{"capstone":capstone.__version__,"objdump":objdump_version,"python":sys.version.split()[0]},"originalCodeExecuted":False,"originalCodeEmulated":False,
 "wireContractEstablished":False,"scope":"Complete selected FDEs and local refs, not transitive semantic closure or source equivalence"}
from qualify_native import qualify
frozen=json.loads((Path(__file__).with_name("frozen-cases.json")).read_text(encoding="utf-8"))
profile=qualify(result,frozen["spec"])
(O/"qualified-profile.json").write_text(json.dumps(profile,indent=2)+"\n",encoding="utf-8",newline="\n")
for name,content in [("native.json",json.dumps(result,indent=2)+"\n"),("native-disassembly.txt","\n".join(text).rstrip()+"\n"),("native-gnu.txt","\n".join(gnu))]:
 (O/name).write_text(content,encoding="utf-8",newline="\n")
print(json.dumps({"fdes":len(records),"bytes":total,"instructions":sum(len(r["instructions"]) for r in records),"relocationRecords":len(relocations),"gnuCompared":True}),flush=True)
