import hashlib,json,struct
from pathlib import Path
import capstone
import argparse
ROOT=Path(__file__).resolve().parents[3]
parser=argparse.ArgumentParser(description="Reproduce the bounded Node115 signed-reader reference census, without target execution.")
parser.add_argument("--binary",type=Path,default=ROOT/"artifacts/node/115/hl-node")
parser.add_argument("--output",type=Path,required=True)
args=parser.parse_args()
OUT=args.output
OUT.mkdir(parents=True,exist_ok=False)
target=args.binary
data=target.read_bytes()
digest=hashlib.sha256(data).hexdigest()
if digest!="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301": raise ValueError("target digest")
if data[:6]!=b"\x7fELF\x02\x01": raise ValueError("ELF64 LE")
shoff=struct.unpack_from("<Q",data,40)[0]
entsize,count,namesidx=struct.unpack_from("<HHH",data,58)
if entsize!=64: raise ValueError("section entry width")
rows=[struct.unpack_from("<IIQQQQIIQQ",data,shoff+i*entsize) for i in range(count)]
names=data[rows[namesidx][4]:rows[namesidx][4]+rows[namesidx][5]]
sections={}
for r in rows:
    end=names.index(0,r[0]); name=names[r[0]:end].decode("ascii")
    if name in sections: raise ValueError("duplicate section")
    sections[name]={"address":r[3],"offset":r[4],"size":r[5],"flags":r[2]}
def offset(va):
    found=[s["offset"]+va-s["address"] for s in sections.values() if s["address"]<=va<s["address"]+s["size"] and s["flags"]&2]
    if len(found)!=1: raise ValueError("VA mapping")
    return found[0]
hdr=sections[".eh_frame_hdr"]
h=hdr["offset"]
if data[h:h+4]!=bytes([1,0x1b,3,0x3b]): raise ValueError("unwind header encoding")
n=struct.unpack_from("<I",data,h+8)[0]
if 12+n*8!=hdr["size"]: raise ValueError("unwind table size")
def leb(pos,signed=False):
    value=0; shift=0
    while True:
        b=data[pos]; pos+=1; value|=(b&127)<<shift; shift+=7
        if not b&128: break
        if shift>70: raise ValueError("LEB length")
    if signed and b&64: value-=1<<shift
    return value,pos
def fde_bounds(fde):
    f=offset(fde)
    length,back=struct.unpack_from("<II",data,f)
    cie=f+4-back
    if struct.unpack_from("<I",data,cie+4)[0]!=0 or data[cie+8]!=1: raise ValueError("CIE identity")
    end=data.index(0,cie+9); aug=data[cie+9:end]; p=end+1
    _,p=leb(p); _,p=leb(p,True); _,p=leb(p)
    auglen,p=leb(p)
    augend=p+auglen
    if not aug.startswith(b"z"): raise ValueError("unbounded CIE augmentation")
    encoding=None
    for tag in aug[1:]:
        if tag==ord("P"):
            enc=data[p]; p+=1
            form=enc&15
            if form in (1,9): _,p=leb(p,form==9)
            elif form in (0,2,3,4,10,11,12):
                p+={0:8,2:2,3:4,4:8,10:2,11:4,12:8}[form]
            else: raise ValueError("personality pointer encoding")
        elif tag==ord("L"): p+=1
        elif tag==ord("R"): encoding=data[p]; p+=1
        else: raise ValueError("unsupported CIE augmentation")
    if p!=augend or encoding!=0x1b: raise ValueError("CIE range encoding")

    start=fde+8+struct.unpack_from("<i",data,f+8)[0]
    size=struct.unpack_from("<I",data,f+12)[0]
    return start,size,length
import bisect,re,subprocess
idx=[struct.unpack_from("<ii",data,h+12+i*8) for i in range(n)]
starts=[hdr["address"]+a for a,b in idx]
fdevas=[hdr["address"]+b for a,b in idx]
rel=sections[".rela.dyn"]
relocs={}
for p in range(rel["offset"],rel["offset"]+rel["size"],24):
    slot,info,addend=struct.unpack_from("<QQq",data,p)
    if info&0xffffffff==8:
        if slot in relocs: raise ValueError("duplicate relative slot")
        relocs[slot]=addend
def owner(va):
    i=bisect.bisect_right(starts,va)-1
    s,z,_=fde_bounds(fdevas[i])
    if s!=starts[i] or not s<=va<s+z: raise ValueError("not within FDE")
    return s,z
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64); md.detail=True
roots={0x2935ae0,0x5659e00}
ts=sections[".text"]; tb=data[ts["offset"]:ts["offset"]+ts["size"]]
raw=[]
for opcode in (b"\xe8",b"\xe9"):
    p=0
    while True:
        p=tb.find(opcode,p)
        if p<0: break
        if p+5<=len(tb):
            dest=ts["address"]+p+5+struct.unpack_from("<i",tb,p+1)[0]
            if dest in roots: raw.append((ts["address"]+p,dest))
        p+=1
slots={slot:dest for slot,dest in relocs.items() if dest in roots}
for op in (b"\xff\x15",b"\xff\x25"):
    p=0
    while True:
        p=tb.find(op,p)
        if p<0: break
        if p+6<=len(tb):
            slot=ts["address"]+p+6+struct.unpack_from("<i",tb,p+2)[0]
            if slot in slots: raw.append((ts["address"]+p,slots[slot]))
        p+=1
byowner={}
unresolved=[]
for site,targetva in raw:
    try: start,size=owner(site)
    except ValueError:
        unresolved.append({"site":hex(site),"reason":"no containing FDE"}); continue
    byowner.setdefault((start,size),[]).append((site,targetva))
refs=[]
for (start,size),sites in byowner.items():
    if size>65536:
        unresolved.extend({"site":hex(site),"owner":hex(start),"size":size,"reason":"owner above 65536 static intake bound"} for site,d in sites);continue
    code=data[offset(start):offset(start)+size]
    ins=list(md.disasm(code,start))
    if sum(x.size for x in ins)!=size: raise ValueError("caller decode incomplete")
    for site,targetva in sites:
        found=[i for i,x in enumerate(ins) if x.address==site and x.mnemonic in ("call","jmp")]
        if len(found)!=1:
            unresolved.append({"site":hex(site),"reason":"raw bytes are not a decoded call/jump boundary"});continue
        i=found[0]
        refs.append({"site":hex(site),"target":hex(targetva),"owner":hex(start),"ownerEnd":hex(start+size),"ownerSha256":hashlib.sha256(code).hexdigest(),"context":[{"address":hex(x.address),"bytes":x.bytes.hex(),"mnemonic":x.mnemonic,"operands":x.op_str} for x in ins[max(0,i-10):i+11]]})
slow=0x58225c0; start,size=owner(slow)
for x in md.disasm(data[offset(start):offset(start)+size],start):
    if x.mnemonic=="lea" and x.operands[1].type==3 and x.operands[1].mem.base==capstone.x86_const.X86_REG_RIP:
        base=x.address+x.size+x.operands[1].mem.disp
        entries=struct.unpack_from("<iiii",data,offset(base))
        dest=[base+v for v in entries]
        if not all(start<=v<start+size for v in dest): raise ValueError("slow table escapes")
        slowtable={"site":hex(x.address),"base":hex(base),"raw":data[offset(base):offset(base)+16].hex(),"signedEntries":list(entries),"destinations":[hex(v) for v in dest]}
report={"targetSha256":digest,"targetExecuted":False,"mainHead":"8fd8db680ec4bfef40996e5616bce3d5156d0b86","scope":"Full .text raw E8/E9 and FF15/FF25 to roots/actual RELATIVE slots; containing FDE decode confirms instruction boundaries. No dataflow-derived function pointer census claimed.","rawReferences":len(raw),"relativeSlots":{hex(k):hex(v) for k,v in slots.items()},"confirmedReferences":refs,"unresolved":unresolved,"slowJumpTable":slowtable}
(OUT/"caller-census.json").write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
print(json.dumps({"raw":len(raw),"confirmed":len(refs),"unresolved":len(unresolved),"owners":len(byowner),"relativeSlots":len(slots)}),flush=True)
