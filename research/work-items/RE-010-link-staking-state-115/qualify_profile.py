"""Static evidence qualification only; never execute/emulate captured code."""
import hashlib,struct
STARTS={0x5536770,0x4e10080,0x5551140,0x5551540,0x51e4c80,0x55f99b0,
 0x58c07d0,0x5611bd0,0x469fa60,0x469fe90,0x3ce1080,0x4559130,0x4546140,
 0x370caf0,0x4556850,0x2bcbbf0,0x34dba60,0x3dc74f0,0x3909130,0x3892d40,0x4572f70}
PARTS=[(0,"0x5611bd0","0x5611cfe",0),(0,"0x5611bd0","0x5611cf3",15),
 (1,"0x469fa60","0x469fbd4",0),(1,"0x469fa60","0x469fbc9",16),
 (2,"0x469fa60","0x469fc71",0),(2,"0x469fa60","0x469fc66",16),(2,"0x469fa60","0x469fc5b",27),
 (3,"0x469fa60","0x469fde2",0),(3,"0x469fa60","0x469fdd7",16),(3,"0x469fa60","0x469fdcc",27),
 (3,"0x469fe90","0x46a0214",0),(3,"0x469fe90","0x46a0209",16),(3,"0x469fe90","0x46a01fe",27),
 (4,"0x469fe90","0x46a0076",0),(4,"0x469fe90","0x46a006b",16),(4,"0x469fe90","0x46a0060",29)]

def qualify(packet,frozen):
    import capstone
    from capstone.x86_const import X86_OP_MEM,X86_REG_RIP
    assert packet["targetSha256"]==frozen["targetSha256"]=="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
    records=packet["records"];rows={r["start"]:r for r in records}
    assert len(records)==len(rows)==21 and {int(r["start"],16) for r in records}==STARTS
    assert sum(r["bytes"] for r in records)==33303
    assert sum(len(r["instructions"]) for r in records)==7170
    engine=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);engine.detail=True
    for r in records:
        start,end=int(r["start"],16),int(r["end"],16)
        raw=b"".join(bytes.fromhex(i["bytes"]) for i in r["instructions"])
        assert len(raw)==r["bytes"]==end-start
        assert hashlib.sha256(raw).hexdigest()==r["sha256"]
        decoded=list(engine.disasm(raw,start))
        assert [(hex(i.address),bytes(i.bytes).hex(),i.mnemonic,i.op_str) for i in decoded]==[(i["address"],i["bytes"],i["mnemonic"],i["operands"]) for i in r["instructions"]]
        assert decoded[-1].address+decoded[-1].size==end and r["gnuBytePartitionCompared"]
        by={hex(i.address):i for i in decoded}
        for ref in r["ripReferences"]:
            i=by[ref["site"]]
            destinations=[i.address+i.size+op.mem.disp for op in i.operands if op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP]
            assert int(ref["target"],16) in destinations
    def at(start,site,mnemonic,operands):
        i=next(i for i in rows[start]["instructions"] if i["address"]==site)
        assert (i["mnemonic"],i["operands"])==(mnemonic,operands),site
    for a in frozen["nativeAnchors"]:at(a["function"],a["site"],a["mnemonic"],a["operands"])
    for idx,start,site,offset in PARTS:
        ref=next(x for x in rows[start]["ripReferences"] if x["site"]==site)
        assert bytes.fromhex(ref["raw64"])[:16]==frozen["errorLiterals"][idx]["text"].encode()[offset:offset+16],site
    at("0x469fa60","0x469fbde","mov","dword ptr [rax + 0x20], 0x666c6573")
    # Bind actual wrapper payload/caller copies and the two explicit upsert calls.
    for site,mnemonic,op in [
      ("0x58c07ec","mov","eax, dword ptr [rsi + 0x38]"),
      ("0x58c07f3","movups","xmm0, xmmword ptr [rsi + 0x28]"),
      ("0x58c07fc","movups","xmm0, xmmword ptr [rdx]"),
      ("0x58c0803","mov","eax, dword ptr [rdx + 0x10]"),
      ("0x58c0878","movups","xmm0, xmmword ptr [rsi + 0x28]"),
      ("0x58c0880","movups","xmm0, xmmword ptr [rdx]")]:
        at("0x58c07d0",site,mnemonic,op)
    rel={r["slot"]:r for r in packet["relocations"]}
    assert (rel["0x64e7a80"]["type"],rel["0x64e7a80"]["addend"])==(8,"0x469fe90")
    assert (rel["0x64e7f20"]["type"],rel["0x64e7f20"]["addend"])==(8,"0x469fa60")
    assert rel["0x64dfb50"]["type"]==6 and rel["0x64dfb50"]["symbol"]=="memcmp"
    writes=[c["site"] for c in rows["0x469fe90"]["externalDirectControlTransfers"] if c["target"]=="0x3ce1080"]
    assert writes==["0x46a0288","0x46a02b6"]
    return {"completeFdes":21,"bytes":33303,"instructions":7170,"frozenWholeStates":len(frozen["cases"]),
      "nativeBranchAnchors":len(frozen["nativeAnchors"]),"nativeErrorDataChunks":len(PARTS),
      "activeOutcomes":["success","missing stake key","same request keys","trading linked","staking linked","missing matching pending relation"],
      "observation":"Complete selected FDE byte partitions, actual branch/data/call anchors and relocation identities verified statically.",
      "interpretation":"Whole logical normal request/finalize state contract on valid20-byte-key stable maps with observed row tags0/1/2 and successful allocation.",
      "notClaimed":["Original enum/container ABI or complete allocator/panic/unwind/dependency equivalence","Transient tag3 or arbitrary raw stable row states","Parent classification/admission/signature/nonce/wire/network path","Captured execution/emulation, runtime oracle observations or compiled native-byte equivalence","Whole-node completion, component gates or byte-window credit"]}
