#!/usr/bin/env python3
"""Static ELF/native collection only; no captured instruction evaluator."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import sections
from fde_extents import eh_frame_records

SHA = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
SIZE = 91774280
BINARY = "artifacts/node/94/hl-node"
RANGES = {"digest":[72663120,72663724],"timed-serializer":[79120336,79120746],"serializer-mode":[74567216,74567811],"serializer-dispatch":[72905680,72906946],"concatenate":[75781328,75781722],"vote-size":[74934240,74934519],"vote-write":[74933936,74934229],"u64-size":[78291504,78291659],"u64-write":[78290816,78291496],"bytes32-size":[78290464,78290507],"bytes32-write":[78290640,78290760],"bytes20-write":[78290512,78290630],"tag-write":[78289632,78290054],"hash-update":[83204624,83205690],"hash-final":[83205696,83206461],"permutation-context":[83203200,83204610],"signing-caller":[72658976,72659304],"qc-caller":[74812784,74814368]}
GNU = "/opt/homebrew/opt/binutils/bin/objdump"
LLVM = "/Library/Developer/CommandLineTools/usr/bin/llvm-objdump"

def require(ok, message):
    if not ok:
        raise ValueError(message)

def digest(data):
    return hashlib.sha256(data).hexdigest()

def segments(data):
    require(data[:6] == b"\x7fELF\x02\x01", "ELF64 little-endian required")
    require(struct.unpack_from("<H", data, 18)[0] == 62, "x86-64 required")
    off = struct.unpack_from("<Q", data, 32)[0]
    entsize, count = struct.unpack_from("<HH", data, 54)
    require(entsize == 56 and off + count * entsize <= len(data), "program headers")
    found = []
    for i in range(count):
        typ, flags, foff, va, _, fsize, msize, align = struct.unpack_from("<IIQQQQQQ", data, off + i * entsize)
        if typ == 1:
            require(foff + fsize <= len(data) and fsize <= msize, "PT_LOAD bounds")
            found.append((va, fsize, foff, flags))
    return found

def offset(data, va, size=1):
    found = [foff + va - start for start, length, foff, flags in segments(data)
             if start <= va and va + size <= start + length]
    require(len(found) == 1, "ambiguous or unbacked VA")
    return found[0]

def read(data, va, size):
    off = offset(data, va, size)
    return data[off:off + size]

def contract(data):
    """Fixed manual witnesses; intentionally below whole-image/body hash gates."""
    pins = json.loads((HERE / "pins.json").read_text())
    for name, row in pins["instructions"].items():
        expected = bytes.fromhex(row["hex"])
        require(read(data, int(row["va"],16), len(expected)) == expected, "pin:" + name)
    for row in pins["literals"]:
        require(read(data, int(row["va"],16), len(bytes.fromhex(row["hex"]))).hex() == row["hex"], "literal:" + row["va"])
    for row in pins["tables"]:
        va = int(row["va"],16)
        raw = read(data, va, 4 * len(row["targets"]))
        got = [hex(va + v) for v in struct.unpack("<" + str(len(row["targets"])) + "i", raw)]
        require(got == row["targets"], "dispatch:" + row["va"])
    secs = sections(data)
    rela = [s for s in secs if s["name"] == ".rela.dyn"]
    require(len(rela) == 1 and rela[0]["size"] % 24 == 0, "RELA section")
    expected = {int(r["slot"],16):r for r in pins["relocations"]}
    found = {}
    s = rela[0]
    for off in range(s["offset"], s["offset"] + s["size"], 24):
        slot, info, addend = struct.unpack_from("<QQq", data, off)
        if slot in expected:
            r = expected[slot]
            require(slot not in found and info & 0xffffffff == r["type"] and
                    info >> 32 == r["symbol_index"] and addend == int(r["addend"],16),
                    "relocation:" + hex(slot))
            found[slot] = {"slot":hex(slot),"record_file_offset":off,"record_hex":data[off:off+24].hex()}
    require(set(found) == set(expected), "missing relocation")
    # Confirm the imported byte-copy operation rather than assuming its slot name.
    dynsym = next(s for s in secs if s["name"] == ".dynsym")
    dynstr = next(s for s in secs if s["name"] == ".dynstr")
    name = struct.unpack_from("<I",data,dynsym["offset"] + 6*24)[0]
    pos = dynstr["offset"] + name
    require(data[pos:data.index(0,pos)] == b"memcpy", "copy import symbol")
    return [found[k] for k in sorted(found)]

def fdes(data):
    secs = sections(data)
    _, all_fdes = eh_frame_records(data, secs)
    hdr = next(s for s in secs if s["name"] == ".eh_frame_hdr")
    raw = data[hdr["offset"]:hdr["offset"]+hdr["size"]]
    require(raw[:4] == bytes.fromhex("011b033b"), "unwind index encoding")
    count = struct.unpack_from("<I",raw,8)[0]
    require(len(raw) == 12+8*count,"unwind index size")
    entries = [(hdr["address"]+a,hdr["address"]+b) for a,b in struct.iter_unpack("<ii",raw[12:])]
    result = {}
    for name,(start,end) in RANGES.items():
        match = [f for f in all_fdes if f["start"] == start]
        require(len(match)==1 and match[0]["end"]==end,"FDE extent:" + name)
        f = match[0]
        require([b for a,b in entries if a==start] == [f["fde"]],"FDE index:" + name)
        require(any(a<=start and end<=a+n and flags&1 for a,n,_,flags in segments(data)), "non-executable FDE")
        result[name] = f
    return result

def parse(text, start, end):
    rows = []
    pat = re.compile(r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)\s*(\S.*)$")
    for line in text.splitlines():
        m = pat.match(line)
        if m and start <= int(m[1],16) < end:
            rows.append((int(m[1],16),bytes.fromhex(m[2]),m[3].strip()))
    cursor = start
    for va,b,_ in rows:
        require(va==cursor,"decode gap or overlap")
        cursor += len(b)
    require(cursor==end,"incomplete decode")
    return rows

def partition(rows):
    result = []
    i = 0
    while i < len(rows):
        va,b,asm = rows[i]
        if b==b"\xf0" and asm=="lock":
            require(i+1<len(rows) and rows[i+1][0]==va+1,"dangling LOCK")
            b += rows[i+1][1]
            asm += " " + rows[i+1][2]
            i += 1
        result.append((va,b,asm))
        i += 1
    return result

def native(data, tool, label, name, snapshot):
    start,end = RANGES[name]
    flags = ["-d","-M","intel","--insn-width=16"] if label=="gnu" else ["--disassemble","--x86-asm-syntax=intel"]
    output = subprocess.check_output([tool,*flags,f"--start-address={start:#x}",f"--stop-address={end:#x}",snapshot.name],cwd=snapshot.parent,text=True)
    rows = parse(output,start,end)
    require(b"".join(b for _,b,_ in rows)==read(data,start,end-start),"native bytes differ")
    return output,partition(rows)

def collect(binary, out, gnu=GNU, llvm=LLVM):
    data = binary.read_bytes()
    require(len(data)==SIZE and digest(data)==SHA,"target identity")
    relocs = contract(data)
    fs = fdes(data)
    out.mkdir(parents=True,exist_ok=False)
    records = {"target":{"sha256":SHA,"size":SIZE,"path":BINARY},
               "scope":"18 full unwind extents; static decoders, never captured execution",
               "coordinate_system":"linked ELF virtual addresses, half-open ranges",
               "native_input":"one private read-only full authenticated snapshot, hashed before/after both providers",
               "providers":{k:subprocess.check_output([v,"--version"],text=True).splitlines()[0]
                            for k,v in [("gnu",gnu),("llvm",llvm)]},
               "parser_sha256":{p:digest((ROOT/p).read_bytes()) for p in ("tools/elf_index.py","tools/fde_extents.py")},
               "relocations":relocs,"ranges":{}}
    with tempfile.TemporaryDirectory(prefix="qc-vote-native-") as tmp:
        snapshot=Path(tmp)/"hl-node"
        snapshot.write_bytes(data); snapshot.chmod(0o400)
        require(digest(snapshot.read_bytes())==SHA,"snapshot identity")
        for name,(start,end) in RANGES.items():
            decoded={}; exports={}
            for label,tool in [("gnu",gnu),("llvm",llvm)]:
                text,rows=native(data,tool,label,name,snapshot)
                raw=text.encode()
                stored=raw if label=="gnu" else gzip.compress(raw,mtime=0)
                filename=name+"."+label+".txt"+("" if label=="gnu" else ".gz")
                (out/filename).write_bytes(stored)
                exports[label]={"file":filename,"raw_sha256":digest(raw),"stored_sha256":digest(stored)}
                decoded[label]=rows
            require([(v,b) for v,b,_ in decoded["gnu"]]==[(v,b) for v,b,_ in decoded["llvm"]],"native partition differs")
            f=fs[name]
            records["ranges"][name]={"start":hex(start),"end":hex(end),"bytes":end-start,
                "sha256":digest(read(data,start,end-start)),"rows":len(decoded["gnu"]),
                "fde":{k:hex(v) if isinstance(v,int) else v for k,v in f.items()},"exports":exports}
        require(digest(snapshot.read_bytes())==SHA,"snapshot changed")
    (out/"records.json").write_text(json.dumps(records,sort_keys=True,separators=(",",":"))+"\n")
    return records

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out",type=Path,required=True)
    p.add_argument("--gnu",default=GNU)
    p.add_argument("--llvm",default=LLVM)
    a=p.parse_args()
    r=collect(ROOT/BINARY,a.out,a.gnu,a.llvm)
    print(json.dumps({"ranges":len(r["ranges"]),"bytes":sum(x["bytes"] for x in r["ranges"].values()),"rows":sum(x["rows"] for x in r["ranges"].values())}))
