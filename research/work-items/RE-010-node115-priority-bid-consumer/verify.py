#!/usr/bin/env python3
"""Verify the retained node115 priority-bid consumer static evidence. Never execute it."""
from pathlib import Path
import argparse,copy,hashlib,json,re,struct,sys
PACKET=Path(__file__).resolve().parent
ROOT=PACKET.parents[2]
sys.path.insert(0,str(ROOT/"tools"))
for name,want in {"elf_index.py":"f142a7c03b0c2aee07d547cf93b0f6ef4b330b43ec61909d9388f340d0cdd70e","fde_extents.py":"69798abfa12273bf8e3fa0be6e46dcb0a7807f2803287bbaa0916143ae527714"}.items():
    if hashlib.sha256((ROOT/"tools"/name).read_bytes()).hexdigest()!=want:
        raise ValueError("reference parser drift: "+name)
from elf_index import sections
from fde_extents import eh_frame_records
TARGET_SHA="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
def require(ok,message):
    if not ok: raise ValueError(message)
def parse_gnu(text):
    rows=[]
    for line in text.splitlines():
        m=re.fullmatch(r"\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)\s*(.*)",line)
        require(m is not None,"malformed GNU instruction record")
        rows.append((int(m[1],16),bytes.fromhex(m[2]),m[3]))
    return rows
def validate(data,record,claims,gnu):
    secs=sections(data);_,fdes=eh_frame_records(data,secs)
    def read(va,n):
        hits=[s["offset"]+va-s["address"] for s in secs if s["type"]!=8 and s["address"]<=va and va+n<=s["address"]+s["size"]]
        require(len(hits)==1,"ambiguous or unavailable VA")
        return data[hits[0]:hits[0]+n]
    relocations={}
    rs=next(s for s in secs if s["name"]==".rela.dyn")
    for off in range(rs["offset"],rs["offset"]+rs["size"],24):
        slot,info,add=struct.unpack_from("<QQq",data,off)
        relocations.setdefault(slot,[]).append((info&0xffffffff,info>>32,add))
    ds=next(s for s in secs if s["name"]==".dynsym")
    st=next(s for s in secs if s["name"]==".dynstr")
    def binding(expected):
        slot=int(expected["slot"],16);rr=relocations.get(slot,[])
        require(len(rr)==1,"relocation multiplicity")
        kind,symbol,add=rr[0]
        require((kind,symbol,hex(add))==(expected["type"],expected["symbol"],expected["addend"]),"relocation binding")
        if "name" in expected:
            at=st["offset"]+struct.unpack_from("<I",data,ds["offset"]+symbol*24)[0]
            require(data[at:data.index(b"\0",at)].decode("ascii")==expected["name"],"import name")
        return add
    instructions={};total=0
    for b in record["bodies"]:
        start,end=int(b["start"],16),int(b["end"],16)
        require([f for f in fdes if f["start"]==start]==[b["fde"]],"FDE identity")
        require(b["fde"]["end"]==end and end-start==b["bytes"],"extent")
        raw=read(start,end-start)
        require(hashlib.sha256(raw).hexdigest()==b["sha256"],"body digest")
        rows=parse_gnu(gnu[b["gnu"]]);cursor=start
        for address,code,text in rows:
            require(address==cursor and len(code)>0,"instruction partition")
            require(code==read(address,len(code)),"instruction bytes")
            require(address not in instructions,"overlapping body")
            instructions[address]=(code,text);cursor+=len(code)
        require(cursor==end,"instruction end")
        raw_lines=[line for line in gnu[b["rawGNU"]].splitlines() if re.fullmatch(r"\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)\s*(.*)",line)]
        require(parse_gnu("\n".join(raw_lines))==rows,"raw GNU export differs")
        total+=len(raw)
    for c in claims:
        address=int(c["address"],16)
        require(address in instructions,"claim outside exported instruction")
        require(instructions[address][0].hex()==c["bytes"],"claim bytes")
    call_count=0;locations=0
    by_start={b["start"]:b for b in record["bodies"]}
    require({c["start"] for c in record["context"]}==set(by_start),"complete context scope")
    for context in record["context"]:
        rows=parse_gnu(gnu[by_start[context["start"]]["gnu"]])
        sites=[hex(a) for a,b,t in rows if t.startswith("call ")]
        require(sites==[c["site"] for c in context["calls"]],"complete call census")
        for c in context["calls"]:
            address=int(c["site"],16);code,text=instructions[address]
            require(text.startswith("call "),"call site")
            if "target" in c:
                require(code[0]==0xe8 and len(code)==5,"direct call encoding")
                require(address+5+struct.unpack("<i",code[1:])[0]==int(c["target"],16),"direct call target")
            elif "binding" in c:
                require(code[:2]==b"\xff\x15" and len(code)==6,"indirect RIP call encoding")
                require(address+6+struct.unpack("<i",code[2:])[0]==int(c["binding"]["slot"],16),"call slot")
                binding(c["binding"])
            else:
                require(c.get("unresolvedRegister") is True,"unclassified call")
                require(code[0]!=0xe8 and code[:2]!=b"\xff\x15","unresolved direct/slot call")
            call_count+=1
        for r in context["dataReferences"]:
            if "binding" in r:binding(r["binding"])
            if "location" not in r:continue
            loc=r["location"];address=int(r["address"],16)
            p=binding(loc["pointerBinding"])
            length,line,column=struct.unpack("<QII",read(address+8,16))
            require((length,line,column)==(loc["length"],loc["line"],loc["column"]),"Location record")
            require(read(p,length).decode("utf-8")==loc["path"],"Location source path")
            locations+=1

    for t in record["tables"]:
        base,index=int(t["base"],16),t["index"]
        require(int(t["entry"],16)==base+index*4,"table coordinate")
        raw=read(base+index*4,4)
        require(raw.hex()==t["bytes"],"table entry bytes")
        dest=base+struct.unpack("<i",raw)[0]
        require(hex(dest)==t["target"] and dest in instructions,"selected table target")
    for n in record["names"]:
        va=binding(n["binding"])
        require(read(va,n["length"]).decode("ascii")==n["name"],"action name")
        slot=int(n["binding"]["slot"],16)
        raw=read(slot+8,8)
        require(raw.hex()==n["lengthBytes"] and struct.unpack("<Q",raw)[0]==n["length"],"action name length")

    return {"bodies":len(record["bodies"]),"bodyBytes":total,"instructions":len(instructions),"callRecords":call_count,"locationRecords":locations,"claimPins":len(claims)}
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--target",type=Path,default=ROOT/"artifacts/node/115/hl-node")
    ap.add_argument("--capstone",action="store_true",help="independently decode all retained ranges with installed Capstone")
    args=ap.parse_args()
    data=args.target.read_bytes()
    require(hashlib.sha256(data).hexdigest()==TARGET_SHA,"target SHA256")
    record=json.loads((PACKET/"records.json").read_text(encoding="utf-8"))
    require(record["targetSha256"]==TARGET_SHA,"record target")
    claims=json.loads((PACKET/"claims.json").read_text(encoding="utf-8"))
    gnu={k:(PACKET/k).read_text(encoding="utf-8") for b in record["bodies"] for k in [b["gnu"],b["rawGNU"]]}
    result=validate(data,record,claims,gnu)

    if args.capstone:
        import capstone
        md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
        ss=sections(data)
        count=0
        for b in record["bodies"]:
            start,end=int(b["start"],16),int(b["end"],16)
            offsets=[s["offset"]+start-s["address"] for s in ss if s["type"]!=8 and s["address"]<=start and end<=s["address"]+s["size"]]
            require(len(offsets)==1,"Capstone VA map")
            raw=data[offsets[0]:offsets[0]+end-start]
            got=[(i.address,bytes(i.bytes)) for i in md.disasm(raw,start)]
            want=[(a,code) for a,code,text in parse_gnu(gnu[b["gnu"]])]
            require(got==want,"independent decoder partition")
            count+=len(got)
        result["capstoneGNUEqualInstructions"]=count
        result["capstoneBindingVersion"]=capstone.__version__

    controls=[]
    def rejects(name,r=record,c=claims,g=gnu):
        try:validate(data,r,c,g)
        except ValueError as exc:controls.append({"name":name,"rejected":True,"reason":str(exc)})
        else:raise ValueError("negative control accepted: "+name)
    r=copy.deepcopy(record);r["bodies"][0]["fde"]["end"]-=1;rejects("wrong FDE extent",r=r)
    g=dict(gnu);key=record["bodies"][0]["gnu"];lines=g[key].splitlines();g[key]="\n".join(lines[:-1]);rejects("missing tail instruction",g=g)
    c=copy.deepcopy(claims);c[0]["bytes"]="90";rejects("changed guard pin",c=c)
    r=copy.deepcopy(record);call=next(c for x in r["context"] for c in x["calls"] if "target" in c);call["target"]=hex(int(call["target"],16)+1);rejects("wrong direct call",r=r)
    r=copy.deepcopy(record);call=next(c for x in r["context"] for c in x["calls"] if "binding" in c);call["binding"]["addend"]="0x0";rejects("wrong relocation callee",r=r)
    r=copy.deepcopy(record);next(c for c in r["context"] if c["calls"])["calls"].pop();rejects("missing call record",r=r)
    r=copy.deepcopy(record);r["tables"][0]["target"]="0x0";rejects("wrong selected action arm",r=r)
    r=copy.deepcopy(record);r["tables"][2]["bytes"]="00000000";rejects("wrong selected drop arm",r=r)
    r=copy.deepcopy(record);r["names"][0]["length"]+=1;rejects("wrong action name length",r=r)
    print(json.dumps({"targetSha256":TARGET_SHA,"staticEvidence":result,"negativeControls":controls,"targetExecuted":False,"runtimeEquivalenceClaimed":False},sort_keys=True))
if __name__=="__main__":main()
