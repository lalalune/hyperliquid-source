"""Static Node115 metadata packet. Never executes or emulates target bytes."""
from pathlib import Path
import argparse, hashlib, json, re, struct, subprocess, sys
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import sections
from fde_extents import eh_frame_records
import capstone
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
TARGET = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
STARTS = (
 0x2f186b0,0x2f19810,0x2f19850,0x2f19890,0x2f19910,0x2ec7750,
 0x2ec25a0,0x2ec0710,0x2ec2190,0x2ebc090,0x2ee9e50,0x2ef3770,
 0x2ec3be0,0x2ec4170,0x2ec8930,0x2ec99e0,0x2ecabd0,0x2ede440,
 0x141e264,0x1680e60,0x1681da0,0x1681e40,0x2eabf70,0x2edf980,
 0x2edfa70,0x2edfbb0,0x5c54800,0x141e251,0x141e280,0x1680500,
 0x1680bd0,0x1680cab,0x1680e80,0x2ecaee0,0x2ecaef0,0x2f06ec0,
 0x44a61d0,0x5c54780,0x6355830,0x635de30,0x141e3a0,0x1628bc0,
 0x162a760,0x1680e40,0x1688740,0x5c826c0,0x5c827a0,0x167bc20,0x167c040,
)
KEYS = [
 (0x64457f,"szDecimals"),(0x45a108,"name"),(0x644589,"maxLeverage"),
 (0x644594,"marginTableId"),(0x6445a1,"onlyIsolated"),(0x6445ad,"isDelisted"),
 (0x6445b7,"marginMode"),(0x6445c1,"growthMode"),
 (0x6445cb,"lastFeeScaleChangeTime"),(0x450850,"deployerFeeScale"),
]

def qualify(packet):
    """Check decoded contract anchors, independently of the frozen Rust outputs."""
    rows = {r["start"]: r for r in packet["records"]}
    entry = rows["0x2f186b0"]
    assert entry["end"] == "0x2f1890c" and entry["bytes"] == 604
    calls = [r["operands"] for r in entry["instructions"] if r["mnemonic"] == "call"]
    assert calls[:10] == [
      "0x2ec7750","0x2ec25a0","0x2ec0710","0x2ec2190","0x2ebc090",
      "0x2ebc090","0x2f19810","0x2f19850","0x2f19890","0x2f19910"]
    ins = {r["address"]: (r["mnemonic"],r["operands"]) for r in entry["instructions"]}
    for address, mnemonic, operands in [
      ("0x2f1870e","lea","rcx, [rbx + 0x3d]"),
      ("0x2f1873c","lea","rcx, [rbx + 0x10]"),
      ("0x2f1876a","lea","rcx, [rbx + 0x3c]"),
      ("0x2f18798","lea","rcx, [rbx + 0x28]"),
      ("0x2f187bb","test","bpl, bpl"),("0x2f187ee","test","r15b, r15b"),
      ("0x2f18821","test","r13b, r13b"),("0x2f1883d","cmp","r12b, 1"),
      ("0x2f18856","cmp","dword ptr [rsp + 0x1c], 0"),
      ("0x2f18870","cmp","qword ptr [rsp + 0x28], 0"),
    ]:
        assert ins[address] == (mnemonic, operands), address
    for address, branch in [
      ("0x2f187be","0x2f187ee"),("0x2f187f1","0x2f18821"),
      ("0x2f18824","0x2f1883d"),("0x2f18841","0x2f18856"),
      ("0x2f1885b","0x2f18870"),("0x2f18876","0x2f1888a")]:
        assert ins[address] == ("je",branch), address
    assert [(r["va"],r["text"]) for r in packet["keys"]] == [(hex(a),s) for a,s in KEYS]
    tables = packet["data"]
    assert tables["feeDescriptor"] == "c5200000700a0000"
    classes = bytearray(256)
    for i in range(32): classes[i] = ord("u")
    for k,v in {8:"b",9:"t",10:"n",12:"f",13:"r",34:'"',92:"\\"}.items():
        classes[k] = ord(v)
    assert tables["escapeClasses"] == classes.hex()
    assert tables["hexAlphabet"] == b"0123456789abcdef".hex()
    assert any(i["mnemonic"] == "mov" and i["operands"] == "eax, dword ptr [rdi]"
               for i in rows["0x2ede440"]["instructions"])
    callback = [(i["mnemonic"],i["operands"]) for i in rows["0x1688740"]["instructions"]]
    assert ("test","esi, 0x10000000") in callback
    assert ("movzx","edx, word ptr [rax + 0x16]") in callback
    assert ("jmp","0x167bc20") in callback and ("jmp","0x167c040") in callback
    assert not any(m == "add" and o.startswith("edx,") for m,o in callback)
    return {"fieldCalls":10,"conditionalFields":6,"escapeClasses":256,
            "hexAlphabetBytes":16,"wholeRecordBytes":604,
            "floatMeaning":"qualified source correspondence; no universal native proof"}

def collect(target, objdump, output):
    b = target.read_bytes()
    assert hashlib.sha256(b).hexdigest() == TARGET, "wrong capture"
    ss = sections(b); _, fdes = eh_frame_records(b)
    def offset(va, size):
        matches = [s["offset"]+va-s["address"] for s in ss if s["type"] != 8
                   and s["address"] <= va and va+size <= s["address"]+s["size"]]
        assert len(matches) == 1, (hex(va),size)
        return matches[0]
    def data(va, n):
        at = offset(va,n)
        return b[at:at+n]
    output.mkdir(parents=True,exist_ok=True)
    version = subprocess.run([str(objdump),"--version"],capture_output=True,
                             timeout=15,check=True).stdout.decode().splitlines()[0]
    engine = capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);engine.detail=True
    records=[];text=[];gnu_text=[];wanted=set()
    for start in sorted(STARTS):
        found=[f for f in fdes if f["start"] == start]
        assert len(found) == 1, hex(start)
        end=found[0]["end"];raw=data(start,end-start)
        decoded=list(engine.disasm(raw,start))
        assert decoded and decoded[0].address == start
        assert sum(i.size for i in decoded) == len(raw)
        assert all(x.address+x.size==y.address for x,y in zip(decoded,decoded[1:]))
        command=[str(objdump),"-d","-w","--insn-width=16","-M","intel",
                 "--start-address="+hex(start),"--stop-address="+hex(end),str(target)]
        p=subprocess.run(command,capture_output=True,timeout=30,check=True)
        gnu=p.stdout.decode().replace("\r\n","\n");gnu_text.append(gnu.replace(str(target),"TARGET_INPUT"))
        parsed=[]
        for line in gnu.splitlines():
            m=re.match(r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}(?:\s+|$))+)",line)
            if m: parsed.append((int(m[1],16),bytes.fromhex(m[2])))
        assert parsed == [(i.address,bytes(i.bytes)) for i in decoded], hex(start)
        rows=[];refs=[]
        for i in decoded:
            rows.append({"address":hex(i.address),"bytes":bytes(i.bytes).hex(),
                         "mnemonic":i.mnemonic,"operands":i.op_str})
            for op in i.operands:
                if op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP:
                    va=i.address+i.size+op.mem.disp;wanted.add(va)
                    try: chunk=data(va,64)
                    except AssertionError: continue
                    refs.append({"site":hex(i.address),"target":hex(va),"raw64":chunk.hex()})
            text.append(f"{i.address:08x}: {bytes(i.bytes).hex():32} {i.mnemonic} {i.op_str}")
        records.append({"start":hex(start),"end":hex(end),"fileOffset":offset(start,len(raw)),
                        "bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),
                        "instructions":rows,"ripReferences":refs,"gnuBytePartitionEqual":True})
        text.append("")
        print(hex(start),len(raw),len(rows),"instructions; GNU partition equal",flush=True)
    rel=next(s for s in ss if s["name"]==".rela.dyn")
    ds=next(s for s in ss if s["name"]==".dynsym")
    dt=next(s for s in ss if s["name"]==".dynstr")
    relocations=[]
    for at,info,addend in struct.iter_unpack("<QQq",memoryview(b)[rel["offset"]:rel["offset"]+rel["size"]]):
        if at not in wanted:continue
        row={"slot":hex(at),"type":info&0xffffffff,"addend":hex(addend)}
        if info>>32:
            symbol=ds["offset"]+24*(info>>32);name=struct.unpack_from("<I",b,symbol)[0]
            begin=dt["offset"]+name;end=b.find(b"\0",begin,dt["offset"]+dt["size"])
            assert end>=begin;row["symbol"]=b[begin:end].decode()
        relocations.append(row)
    packet={"targetSha256":TARGET,"base":"05bc2de303c05525b71e7e257426e741bc66a390",
      "entry":"0x2f186b0","coordinateSystem":"ELF virtual address, not rebased runtime address",
      "tools":{"python":sys.version.split()[0],"capstone":capstone.__version__,"objdump":version},
      "records":records,"relocations":relocations,
      "keys":[{"va":hex(a),"fileOffset":offset(a,len(s)),"text":data(a,len(s)).decode()} for a,s in KEYS],
      "data":{"feeDescriptor":data(0x459898,8).hex(),
              "escapeClasses":data(0x946dcc,256).hex(),"hexAlphabet":data(0x946ecc,16).hex()},
      "capturedTargetExecuted":False,"capturedTargetEmulated":False,
      "machineCodeComparisonToReconstruction":False,"wholeModuleDenominatorKnown":False}
    packet["contractAnchors"]=qualify(packet)
    packet["metrics"]={"selectedFdes":len(records),"selectedBytes":sum(r["bytes"] for r in records),
        "selectedInstructions":sum(len(r["instructions"]) for r in records),
        "gnuBytePartitionsEqual":len(records),"relocationRecords":len(relocations)}
    for name,value in [("native.json",json.dumps(packet,indent=2)+"\n"),
                       ("native-disassembly.txt","\n".join(text)+"\n"),
                       ("gnu-disassembly.txt","\n".join(gnu_text))]:
        (output/name).write_text(value,encoding="utf-8",newline="\n")
    print(json.dumps(packet["metrics"]),flush=True)
    return packet

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--target",type=Path,required=True)
    p.add_argument("--objdump",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();collect(a.target,a.objdump,a.output)
