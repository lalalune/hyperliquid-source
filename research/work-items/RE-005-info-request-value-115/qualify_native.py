"""Re-derive whole request field mappings from decoded native evidence.
This is conservative static graph analysis, never execution/emulation of code.
"""
def field_map(packet):
    root=next(r for r in packet["records"] if r["start"]=="0x273bf30")
    ins=root["instructions"];by={int(i["address"],16):i for i in ins}
    refs={x["site"]:x for x in root["ripReferences"]}
    helpers={"0x26eb010":"u64","0x26eb1d0":"u64","0x26eb5e0":"snapshot",
      "0x26eb830":"text","0x26eba60":"address","0x26ebcc0":"u32",
      "0x26ebe80":"optional_address","0x26ec100":"bool","0x26ec2b0":"literal"}
    def previous(rows,prefix):
        matches=[x for x in rows if x["operands"].startswith(prefix)]
        assert matches, prefix
        return matches[-1]
    calls={}
    for j,i in enumerate(ins):
        if i["mnemonic"]!="call" or i["operands"] not in helpers:continue
        before=ins[max(0,j-10):j]
        lea=previous(before,"rsi, [rip");length=previous(before,"edx, ")
        n=int(length["operands"].split(", ")[1],0)
        key=bytes.fromhex(refs[lea["address"]]["raw64"])[:n].decode("utf-8")
        row={"site":i["address"],"helper":i["operands"],"kind":helpers[i["operands"]],
             "key":key,"keyVa":refs[lea["address"]]["target"]}
        if i["operands"]=="0x26ec2b0":
            value=previous(before,"rcx, [rip");length=previous(before,"r8d, ")
            n=int(length["operands"].split(", ")[1],0)
            row["literal"]=bytes.fromhex(refs[value["address"]]["raw64"])[:n].decode("utf-8")
            row["valueVa"]=refs[value["address"]]["target"]
        calls[int(i["address"],16)]=row
    def successors(address):
        i=by[address];nxt=address+len(bytes.fromhex(i["bytes"]))
        m=i["mnemonic"];op=i["operands"]
        if m in {"ret","ud2"}:return []
        if m=="jmp":return [int(op,16)] if op.startswith("0x") and int(op,16) in by else []
        if m.startswith("j") and op.startswith("0x"):
            return [a for a in [int(op,16),nxt] if a in by]
        return [nxt] if nxt in by else []
    arms=[]
    for slot in packet["dispatch"]:
        todo=[int(slot["destination"],16)];seen=set()
        while todo:
            at=todo.pop()
            if at in seen:continue
            seen.add(at);todo.extend(successors(at))
        selected=[calls[a] for a in sorted(seen) if a in calls]
        types=[x for x in selected if x["key"]=="type" and "literal" in x]
        assert len(types)==1,slot
        arms.append({"index":slot["index"],"destination":slot["destination"],
          "type":types[0]["literal"],"typeCall":types[0],
          "fields":[x for x in selected if x is not types[0]]})
    return arms

def qualify(packet,spec):
    validate_decoding(packet)
    rows={r["start"]:r for r in packet["records"]}
    def at(start,site,mnemonic,operands):
        r=rows[start]
        i=next(i for i in r["instructions"] if i["address"]==site)
        assert (i["mnemonic"],i["operands"])==(mnemonic,operands),site
    root=rows["0x273bf30"]
    assert (root["end"],root["bytes"])==("0x273ebc0",11408)
    assert len(packet["dispatch"])==len(spec)==55
    arms=field_map(packet)
    for index,(arm,expected) in enumerate(zip(arms,spec,strict=True)):
        assert arm["index"]==index and arm["type"]==expected["type"],index
        assert [(x["key"],x["kind"]) for x in arm["fields"]]==[(x["name"],x["kind"]) for x in expected["fields"]],index
        assert len({x["key"] for x in arm["fields"]})==len(arm["fields"])
        assert "type" not in {x["key"] for x in arm["fields"]}
    assert len({a["type"] for a in arms})==55
    for start,site,mnemonic,operands in [
      ("0x273bf30","0x273bf43","movabs","r15, 0x8000000000000005"),
      ("0x273bf30","0x273bf54","add","rcx, -4"),
      ("0x273bf30","0x273bf58","sar","rax, 0x3f"),
      ("0x273bf30","0x273bf5c","and","rax, rcx"),
      ("0x26eb010","0x26eb0cf","mov","rax, qword ptr [r15]"),
      ("0x26eb1d0","0x26eb28f","mov","rax, qword ptr [r15]"),
      ("0x26ebcc0","0x26ebd7f","mov","eax, dword ptr [r15]"),
      ("0x26ec100","0x26ec131","movzx","r13d, byte ptr [rcx]"),
      ("0x26ec100","0x26ec1c0","lea","rax, [r12 + 1]"),
      ("0x26eb830","0x26eb8f0","mov","r12, qword ptr [r15 + 0x10]"),
      ("0x26eb830","0x26eb938","lea","rax, [rbp + 3]"),
      ("0x26ebe80","0x26ebf40","cmp","byte ptr [r15], 1"),
      ("0x26ebe80","0x26ebf44","jne","0x26ebf8b"),
      ("0x26ebe80","0x26ebf8b","mov","rax, rbp"),
      ("0x26ebe80","0x26ec04f","call","0x2b6cb40"),
      ("0x26eba60","0x26ebb37","mov","esi, 0x2a"),
      ("0x26eba60","0x26ebb3c","mov","ecx, 0x14"),
      ("0x26eba60","0x26ebb44","xor","r8d, r8d"),
      ("0x26ebe80","0x26ebf60","mov","esi, 0x2a"),
      ("0x26ebe80","0x26ebf65","mov","ecx, 0x14"),
      ("0x26ebe80","0x26ebf6d","xor","r8d, r8d"),
      ("0x2eabb50","0x2eabb62","mov","word ptr [rdi], 0x7830"),
      ("0x273f3b0","0x273f5ea","cmp","r13, rax"),
      ("0x273f3b0","0x273f5ed","je","0x273f60b"),
      ("0x273f3b0","0x273f60b","test","r12b, r12b"),
      ("0x273f3b0","0x273f60e","je","0x273f477"),
      ("0x5c558a0","0x5c55968","mov","qword ptr [rbx], r14"),
      ("0x5c558a0","0x5c55997","mov","qword ptr [rbx + 0x48], rax"),
      ("0x26f3fc0","0x26f4369","imul","rcx, rbx, 0x68"),
      ("0x26f3fc0","0x26f43c4","inc","rbx"),
      ("0x26f3fc0","0x26f43c7","mov","qword ptr [r12 + 0x10], rbx"),
    ]:at(start,site,mnemonic,operands)
    assert packet["data"]["hexAlphabet"]==b"0123456789abcdef".hex()
    reloc=next(x for x in packet["relocations"] if x["slot"]=="0x64e4d08")
    assert (reloc["type"],reloc["addend"])==(8,"0x2eabb50")
    snap=rows["0x273f3b0"];refs={r["site"]:r for r in snap["ripReferences"]}
    for site,n,expected in [
      ("0x273f454",14,"referrerStates"),("0x273f569",11,"l4Snapshots"),
      ("0x273f58c",12,"includeUsers"),("0x273f5a9",20,"includeTriggerOrders"),
      ("0x273f5ef",4,"coin"),("0x273f618",16,"includeL4Details")]:
        assert bytes.fromhex(refs[site]["raw64"])[:n].decode()==expected,site
    return {"variants":55,"wholeValueLogicalProfileQualified":True,
      "normalization":"Canonical fixture JSON sorts object keys only; separate tests check native construction order.",
      "unknowns":["Native enum/value ABI and constructor provenance","Allocator/TLS/hash implementation and panic/unwind identity",
                  "Complete captured dependency graph and later wire/HTTP behavior","Whole-node equivalence and component gates remain unproved"],
      "arms":arms}

def validate_decoding(packet):
    import hashlib, struct, capstone
    engine=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
    assert packet["targetSha256"]=="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
    rows=packet["records"]
    assert len(rows)==len({r["start"] for r in rows})==23
    assert sum(r["bytes"] for r in rows)==32536
    assert sum(len(r["instructions"]) for r in rows)==6600
    for r in rows:
        start,end=int(r["start"],16),int(r["end"],16)
        raw=b"".join(bytes.fromhex(i["bytes"]) for i in r["instructions"])
        assert len(raw)==r["bytes"]==end-start
        assert hashlib.sha256(raw).hexdigest()==r["sha256"]
        decoded=list(engine.disasm(raw,start))
        actual=[(hex(i.address),bytes(i.bytes).hex(),i.mnemonic,i.op_str) for i in decoded]
        saved=[(i["address"],i["bytes"],i["mnemonic"],i["operands"]) for i in r["instructions"]]
        assert actual==saved
        assert decoded[-1].address+decoded[-1].size==end
        assert r["gnuBytePartitionCompared"] is True
    root=next(r for r in rows if r["start"]=="0x273bf30")
    boundaries={int(i["address"],16) for i in root["instructions"]}
    assert len(packet["dispatch"])==55
    for j,slot in enumerate(packet["dispatch"]):
        assert slot["index"]==j and int(slot["slot"],16)==0x5f45d0+j*4
        assert int(slot["destination"],16)==0x5f45d0+struct.unpack("<i",bytes.fromhex(slot["bytes"]))[0]
        assert int(slot["destination"],16) in boundaries
