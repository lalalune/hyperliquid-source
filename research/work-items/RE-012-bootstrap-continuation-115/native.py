"""Authenticate and statically bind node115 bootstrap continuation; no target execution."""
from pathlib import Path
import argparse,hashlib,json,re,struct,sys,collections
def observe(root,target,out):
    ROOT=root
    O=out
    REF=ROOT/"tools"
    for name,want in {"elf_index.py":"f142a7c03b0c2aee07d547cf93b0f6ef4b330b43ec61909d9388f340d0cdd70e","fde_extents.py":"69798abfa12273bf8e3fa0be6e46dcb0a7807f2803287bbaa0916143ae527714"}.items():
     if hashlib.sha256((REF/name).read_bytes()).hexdigest()!=want:raise ValueError("parser identity")
    sys.path.insert(0,str(REF))
    from elf_index import sections
    from fde_extents import eh_frame_records
    import capstone
    print("$ authenticate inert node115",flush=True)
    data=target.read_bytes();digest=hashlib.sha256(data).hexdigest()
    if digest!="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301":raise ValueError("target drift")
    secs=sections(data);_,fdes=eh_frame_records(data,secs)
    owner=next(f for f in fdes if f["start"]==0x5a82670)
    if owner["end"]!=0x5a89535:raise ValueError("FDE extent")
    def read(va,n):
     matches=[s["offset"]+va-s["address"] for s in secs if s["type"]!=8 and s["address"]<=va and va+n<=s["address"]+s["size"]]
     if len(matches)!=1:raise ValueError("VA mapping")
     return data[matches[0]:matches[0]+n]
    raw=read(owner["start"],owner["end"]-owner["start"])
    bodysha=hashlib.sha256(raw).hexdigest()
    if bodysha!="993bd9a168f2e37e4cdc80092c5ea5e68a3bc0225098621c57e89fccb7bf57fc":raise ValueError("body drift")
    print("$ complete FDE disassembly",flush=True)
    md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);md.detail=True
    ins=list(md.disasm(raw,owner["start"]));cursor=owner["start"]
    for i in ins:
     if i.address!=cursor:raise ValueError("instruction gap")
     cursor+=i.size
    if cursor!=owner["end"] or len(ins)!=4774:raise ValueError("complete decode")
    relsec=next(s for s in secs if s["name"]==".rela.dyn")
    rel={}
    for pos in range(relsec["offset"],relsec["offset"]+relsec["size"],24):
     at,info,addend=struct.unpack_from("<QQq",data,pos)
     rel.setdefault(at,[]).append({"fileOffset":hex(pos),"type":info&0xffffffff,"symbol":info>>32,"addend":hex(addend)})
    rows=[];writes=[];branches=[];calls=[];memfields=[]
    for i in ins:
     reads,written=i.regs_access()
     row={"va":hex(i.address),"bytes":i.bytes.hex(),"mnemonic":i.mnemonic,"operands":i.op_str,"writes":[i.reg_name(x) for x in written]}
     rows.append(row)
     if any(x in row["writes"] for x in ["r14","r14d","r14w","r14b","r15","r15d","r15w","r15b"]):writes.append(row)
     if i.group(capstone.CS_GRP_JUMP):
      op=i.operands[0]
      branches.append({**row,"directTarget":hex(op.imm) if op.type==capstone.x86.X86_OP_IMM else None,"resolved":op.type==capstone.x86.X86_OP_IMM})
     if i.group(capstone.CS_GRP_CALL):
      op=i.operands[0];record=dict(row)
      if op.type==capstone.x86.X86_OP_IMM:record["directTarget"]=hex(op.imm)
      elif op.type==capstone.x86.X86_OP_MEM and op.mem.base==capstone.x86.X86_REG_RIP:
       slot=i.address+i.size+op.mem.disp;record.update(slotVA=hex(slot),relocations=rel.get(slot,[]))
      calls.append(record)
     for op in i.operands:
      if op.type==capstone.x86.X86_OP_MEM and op.mem.base==capstone.x86.X86_REG_RBX and op.mem.disp in [0x288,0x290]:
       memfields.append({**row,"access":op.access,"operandBytes":op.size,"directFieldOffset":hex(op.mem.disp)})
    (O/"instructions.json").write_text(json.dumps(rows,indent=2)+"\n",encoding="utf-8")
    (O/"capstone.txt").write_text("\n".join(r["va"]+" "+r["bytes"]+" "+r["mnemonic"]+" "+r["operands"] for r in rows)+"\n",encoding="utf-8")
    result={"targetSha256":digest,"baseHead":"05bc2de303c05525b71e7e257426e741bc66a390","coordinateSystem":"ELF linked VAs; file offsets named separately","owner":owner,"bodySha256":bodysha,"bodyBytes":len(raw),"instructions":len(ins),"capstoneBinding":capstone.__version__,"capstoneCore":capstone.cs_version(),"r14r15Writes":writes,"branches":branches,"calls":calls,"directRbxRangeFields":memfields,"targetExecuted":False,"knownSharedContext":"Existing bootstrap/input-writers/limit-writers/block-fill/grant packets already bind this owning body. No new body discovery/coverage claim.","scope":"Static raw census; source is qualified separately. No whole original ABI/future claim."}
    (O/"static-intake.json").write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"bytes":len(raw),"instructions":len(ins),"r14r15Writes":len(writes),"calls":len(calls),"branches":len(branches),"indirectBranches":sum(not x["resolved"] for x in branches),"directRbxRangeAccesses":len(memfields),"targetExecuted":False}),flush=True)

    by={i.address:i for i in ins}
    tables=[];indirect={}
    print("$ conservative byte-selector jump tables",flush=True)
    for k,i in enumerate(ins):
     if not i.group(capstone.CS_GRP_JUMP) or i.operands[0].type==capstone.x86.X86_OP_IMM:continue
     window=ins[max(0,k-9):k]
     selectors=[z for z in window if z.mnemonic=="movzx" and z.op_str.startswith("eax, byte ptr [")]
     bases=[z for z in window if z.mnemonic=="lea" and z.op_str.startswith("rcx, [rip")]
     if not selectors or not bases or i.op_str!="rax":raise ValueError("unqualified table pattern")
     selector=selectors[-1];baseins=bases[-1]
     table=baseins.address+baseins.size+baseins.operands[1].mem.disp
     # Pin the actual relative-load and add instructions, not just a guessed table.
     after=[z for z in window if z.address>baseins.address]
     if [(z.mnemonic,z.op_str) for z in after if z.mnemonic in ["movsxd","add"]]!=[("movsxd","rax, dword ptr [rcx + rax*4]"),("add","rax, rcx")]:raise ValueError("table lowering")
     body=read(table,1024);entries=[]
     for index in range(256):
      disp=struct.unpack_from("<i",body,index*4)[0];dest=table+disp
      entries.append({"selectorByte":index,"target":hex(dest),"instructionInOwner":dest in by})
     targets={int(e["target"],16) for e in entries if e["instructionInOwner"]}
     indirect[i.address]=targets
     tables.append({"jump":hex(i.address),"selectorLoad":hex(selector.address),"selectorSource":selector.op_str,"baseInstruction":hex(baseins.address),"tableVA":hex(table),"readBytes":1024,"sha256":hashlib.sha256(body).hexdigest(),"interpretation":"Conservative all-256-byte superset; includes adjacent data and INVALID enum values. Not recovered declared table size or admitted state set.","entries":entries})
    pred=collections.defaultdict(set);succ={i.address:set() for i in ins};external=[]
    for i in ins:
     nxt=i.address+i.size
     if i.group(capstone.CS_GRP_JUMP):
      if i.operands[0].type==capstone.x86.X86_OP_IMM:
       targets={i.operands[0].imm}
      else:targets=indirect[i.address]
      for d in targets:
       if d in by:succ[i.address].add(d)
       else:external.append({"from":hex(i.address),"to":hex(d)})
      if i.mnemonic!="jmp" and nxt in by:succ[i.address].add(nxt)
     elif i.mnemonic not in ["ret","retf","ud2","int3"] and nxt in by:
      succ[i.address].add(nxt)
     for d in succ[i.address]:pred[d].add(i.address)
    def lastdefs(point,names):
     todo=list(pred[point]);seen=set();found=set();entry=False
     while todo:
      at=todo.pop()
      if at in seen:continue
      seen.add(at);i=by[at]
      if names.intersection(i.reg_name(x) for x in i.regs_access()[1]):found.add(at);continue
      if at==0x5a82670:entry=True
      todo.extend(pred[at])
     return {"point":hex(point),"lastWrites":[{"va":hex(at),"instruction":by[at].mnemonic+" "+by[at].op_str} for at in sorted(found)],"entryWithoutWrite":entry,"backwardNodesVisited":len(seen)}
    defs={}
    for reg in ["r14","r15"]:
     names={reg,reg+"d",reg+"w",reg+"b"}
     defs[reg]=lastdefs(0x5a88391,names)
    fields=[];dynamic=[];aliases=[]
    wanted=[0x1e8,0x1f8,0x200,0x258,0x260,0x268,0x270,0x278,0x280,0x288,0x290]
    for i in ins:
     for op in i.operands:
      if op.type!=capstone.x86.X86_OP_MEM or op.mem.base!=capstone.x86.X86_REG_RBX:continue
      row={"va":hex(i.address),"bytes":i.bytes.hex(),"mnemonic":i.mnemonic,"operands":i.op_str,"access":op.access,"size":op.size,"displacement":hex(op.mem.disp)}
      if op.mem.index:
       dynamic.append(row);continue
      if i.mnemonic=="lea":
       if op.mem.disp in wanted:aliases.append(row)
       continue
      overlaps=[hex(x) for x in wanted if op.mem.disp<x+8 and op.mem.disp+op.size>x]
      if overlaps:fields.append({**row,"overlappingQwords":overlaps})
    record={"targetSha256":hashlib.sha256(data).hexdigest(),"bodySha256":hashlib.sha256(raw).hexdigest(),"tableJumps":len(tables),"tables":tables,"selectedRegisterLastDefinitions":defs,"directRbxFieldAccesses":fields,"rbxAddressComputations":aliases,"dynamicRbxIndexAccesses":dynamic,"externalDirectEdges":external,"selectedEntryPredecessors":{hex(p):[hex(a) for a in sorted(pred[p])] for p in [0x5a8815e,0x5a881cc,0x5a88391,0x5a883c4,0x5a8842b,0x5a83026]},"assumptions":["Entry is the FDE start; calls return to fallthrough and honor physical callee-save expectations.","All256 selector values overapproximate admitted original states; no recovered enum-validity or declared table extent claim.","No exceptional/unwind/re-entry paths or opaque helper memory writes are proved by this graph."],"targetExecuted":False}
    (O/"cfg-provenance.json").write_text(json.dumps(record,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"tables":len(tables),"lastDefinitions":defs,"directFieldAccesses":len(fields),"dynamicRbxIndexedAccesses":len(dynamic),"targetExecuted":False}),flush=True)

    helper=[f for f in fdes if f["start"]==0x5a897e0]
    if len(helper)!=1 or helper[0]["end"]!=0x5a8a1cc:raise ValueError("existing waiter FDE")
    hb=read(0x5a897e0,2540)
    if hashlib.sha256(hb).hexdigest()!="99646f05de23478a72a44701b2bf5ea62dc5176cff29626205b74fc2fc250f67":raise ValueError("existing waiter body")
    hi=list(md.disasm(hb,0x5a897e0))
    if len(hi)!=468 or sum(i.size for i in hi)!=2540:raise ValueError("waiter decode")
    gnu=Path(__file__).resolve().parent/"owner.gnu.txt"
    pairs=[]
    for line in gnu.read_text(encoding="utf-8").splitlines():
     m=re.fullmatch(r"\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)\s*(.*)",line)
     if m:pairs.append((hex(int(m[1],16)),bytes.fromhex(m[2]).hex()))
    if pairs!=[(hex(i.address),i.bytes.hex()) for i in ins]:raise ValueError("retained GNU/fresh Capstone partition")
    cross={"bodyBytes":28357,"instructions":4774,"allBytesAndBoundariesMatchCapstone":True,"gnuExportSha256":hashlib.sha256(gnu.read_bytes()).hexdigest(),"normalization":"File-header path redacted in retained export; no instruction/operand masks."}
    (O/"gnu-crosscheck.json").write_text(json.dumps(cross,indent=2)+"\n",encoding="utf-8",newline="\n")
    alias=lastdefs(0x5a8765f,{"r13","r13d","r13w","r13b"})
    if [x["va"] for x in alias["lastWrites"]]!=["0x5a8760c"]:raise ValueError("field200 alias")
    stores={int(x["va"],16):(int(x["displacement"],16),x["size"]) for x in fields if x["access"]&2}
    stores[0x5a8765f]=(0x200,8)
    def memory_sources(point,offset):
     todo=[(x,255) for x in pred[point]];seen=set();hits=set();entry=False
     while todo:
      at,mask=todo.pop()
      if (at,mask) in seen:continue
      seen.add((at,mask))
      if at in stores:
       base,size=stores[at];cover=sum(1<<k for k in range(8) if base<=offset+k<base+size)
       if cover&mask:hits.add(at)
       mask &= ~cover
      if not mask:continue
      if at==0x5a82670:entry=True
      todo.extend((q,mask) for q in pred[at])
     return {"point":hex(point),"field":hex(offset),"explicitStores":[hex(x) for x in sorted(hits)],"entryBytesRemain":entry,"scope":"Direct and qualified R13 stores only; opaque helper/other alias memory effects excluded."}
    sources=[memory_sources(0x5a88165,0x200),memory_sources(0x5a88188,0x1f8),memory_sources(0x5a828ba,0x258),memory_sources(0x5a828c1,0x260)]
    if sources[0]["explicitStores"]!=["0x5a8765f"] or sources[1]["explicitStores"]!=["0x5a87605"]:raise ValueError("selected field sources")
    summary={"targetSha256":digest,"ownerFde":owner,"bodySha256":bodysha,"bytes":28357,"instructions":4774,"gnu":cross,"tables":[{k:v for k,v in t.items() if k!="entries"} for t in tables],"registerDefinitions":defs,"fieldSources":sources,"alias":alias,"waiter":{"fde":helper[0],"bytes":2540,"instructions":468,"sha256":hashlib.sha256(hb).hexdigest(),"credit":"Existing RE-001-node115-nv-stream-execution-wait-loop; body rebound, semantic work not duplicated."},"calls":calls,"assumptions":record["assumptions"],"targetExecutedOrEmulated":False}
    (O/"native-summary.json").write_text(json.dumps(summary,indent=2)+"\n",encoding="utf-8",newline="\n")
    return summary

if __name__=="__main__":
 ap=argparse.ArgumentParser();ap.add_argument("--out",type=Path,required=True);ap.add_argument("--target",type=Path)
 args=ap.parse_args();root=Path(__file__).resolve().parents[3];out=args.out.resolve()
 if out.is_relative_to(root) and not out.is_relative_to(root/"work"):raise ValueError("use ignored work or external output")
 out.mkdir(parents=True,exist_ok=False)
 observe(root,args.target or root/"artifacts/node/115/hl-node",out)
