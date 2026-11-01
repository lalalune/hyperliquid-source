#!/usr/bin/env python3
"""Offline native bindings for one Visor calendar argument; never runs target code.

Image/RELA and byte-partition mechanics adapt the MIT readiness-clock survey.
No imported evidence is changed and no inferred reference source is read.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile

SHA256 = "89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31"
SIZE = 8305392
RANGES = {
    "duration": (0x330360, 0x330581),
    "date": (0x444040, 0x44426c),
    "time": (0x445830, 0x445992),
    "readiness": (0x5b41b0, 0x5b470d),
}
BODY_SHA = {
    "duration": "d31464d9a4f97c5f6ab3920f7c103717ec1af1d832413bb48d0b8f826b5052f7",
    "date": "be40e662a5257c476579cf7851c04fe1589143c1203c96d542def232e1d5900b",
    "time": "0ff407297f468fc38852e0373517fab9d4fabf6bb96b50edeb87b27161b41754",
    "readiness": "efd43ecd28e6194b7cf702be637dafcabb609e8fe892e39e35602ed0675cf560",
}
SLOTS = {0x7e53c8: 0x330360, 0x7e5390: 0x445830, 0x7e5398: 0x444040}
ANCHORS = {
    "source-tail-copy": (0x5b4369, "418b470889842490000000"),
    "source-head-copy": (0x5b4374, "498b074889842488000000"),
    "sixty-load-call": (0x5b437f, "f20f1005c1a3abffff153b102300"),
    "time-argument-and-call": (0x5b43d7, "488db4248c0000004c8d7c24284c89ffff15a30f2300"),
    "carry-first-guard": (0x5b43f2, "48b908ac1c5a643bdfff4801c148ba105839b4c876beff4839d17677"),
    "carry-second-guard": (0x5b440e, "48b9000000004057ffff4801c148ba81aefeff7faefeff4839d1725b"),
    "caller-carry-division": (0x5b443a, "48b9572951cea0c8451848f7e94889d648c1ee3f48c1ea0d01d6"),
    "date-argument": (0x5b4433, "8bbc2488000000"),
    "date-call": (0x5b4454, "ff153e0f2300"),
    "date-zero-fallback": (0x5b445a, "85c07427"),
    "fallback-address": (0x5b448d, "4c8d3d5083acff"),
    "strict-last-compare": (0x5b44c0, "8b00394424080f87e4000000"),
    "time-input": (0x445831, "448b068b7604"),
    "time-nano-threshold": (0x445859, "81fe00ca9a3b7c41"),
    "time-positive-branch": (0x445861, "4885d27f36"),
    "time-nano-reduction": (0x44589c, "81c6003665c4"),
    "time-carry-multiplier": (0x4458dd, "48b9572951cea0c84518"),
    "time-output-layout": (0x445923, "448907897704488947084889f859c3"),
    "date-ordinal": (0x444043, "89f9c1e90481e1ff010000"),
    "date-year-length": (0x444060, "89fac1e21cc1fa1f81c26e010000"),
    "date-year-division": (0x44407c, "4869d01f85eb51"),
    "date-cycle-division": (0x4440d8, "4869f7bd066b39"),
    "date-365-division": (0x444109, "4c69d161f31967"),
    "date-leap-table": (0x4440b3, "4c8d1dd895c3ff"),
    "date-flag-table": (0x4441d9, "488d054396c3ff"),
    "date-year-gate": (0x4441c9, "81c60100fcff81fe0200f8ff72b4"),
    "date-final-validation": (0x4441f0, "4489d181e1f81f000031c081f9e1160000410f42c2"),
    "date-fast-return": (0x44420c, "81e70fe0ffffc1e00409f8"),
}
FDE_EXPECTED = {
    "duration": (0x3018, 0x18, 0),
    "date": (0x10ba8, 0x4c, 0),
    "time": (0x11010, 0x1c, 0),
    "readiness": (0x7d070, 0x54, 0x43d5c),
}

def require(ok, message):
    if not ok:
        raise ValueError(message)

def digest(data):
    return hashlib.sha256(data).hexdigest()

def encoded(data):
    return (json.dumps(data, indent=2, sort_keys=True) + "\n").encode()

class Image:
    def __init__(self, data):
        require(len(data) == SIZE and digest(data) == SHA256, "capture identity")
        self.data = data
        phoff = struct.unpack_from("<Q", data, 32)[0]
        stride, count = struct.unpack_from("<HH", data, 54)
        self.loads = [struct.unpack_from("<IIQQQQQQ", data, phoff+i*stride)
                      for i in range(count)]
        shoff = struct.unpack_from("<Q", data, 40)[0]
        stride, count, names_idx = struct.unpack_from("<HHH", data, 58)
        self.sections = [struct.unpack_from("<IIQQQQIIQQ", data, shoff+i*stride)
                         for i in range(count)]
        names_sec = self.sections[names_idx]
        names = data[names_sec[4]:names_sec[4]+names_sec[5]]
        self.by_name = {names[s[0]:names.index(0, s[0])].decode(): s
                        for s in self.sections}

    def offset(self, va, size=1):
        found = [p[2]+va-p[3] for p in self.loads if p[0] == 1
                 and p[3] <= va and va+size <= p[3]+p[5]]
        require(len(found) == 1, "unmapped/ambiguous PT_LOAD range")
        return found[0]

    def at(self, va, size):
        off = self.offset(va, size)
        return self.data[off:off+size]

    def relocations(self):
        rows = {}
        for sec in self.sections:
            if sec[1] != 4:
                continue
            for off in range(sec[4], sec[4]+sec[5], sec[9]):
                slot, info, addend = struct.unpack_from("<QQq", self.data, off)
                require(slot not in rows, "duplicate relocation")
                rows[slot] = (info, addend, off)
        return rows

def leap(y):
    return y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)

def canonical_tables():
    # Mathematical calendar definition, not a captured-instruction evaluator.
    prefix = bytes(sum(leap(j) for j in range(y)) for y in range(401))
    flags = bytes((0 if leap(y) else 8) |
                  ((365*y+prefix[y]+3) % 7+1) for y in range(400))
    return prefix, flags

def bind(image):
    """Named semantic-byte/data bindings; deliberately has no whole-image hash.

    Production calls this only after Image authenticates. Negative controls
    call it on private changed byte fixtures to test these checks separately.
    Exact byte checks are not semantic-equivalence tests of changed programs.
    """
    result = {}
    for name, (va, expected) in ANCHORS.items():
        raw = image.at(va, len(bytes.fromhex(expected)))
        require(raw.hex() == expected, "anchor: "+name)
        result[name] = {"va": hex(va), "fileOffset": hex(image.offset(va)),
                        "bytes": raw.hex()}
    rel = image.relocations()
    for slot, target in SLOTS.items():
        require(slot in rel and rel[slot][:2] == (8, target),
                "relocation: "+hex(slot))
    prefix, flags = canonical_tables()
    require(image.at(0x7d692, 401) == prefix, "Gregorian leap-prefix table")
    require(image.at(0x7d823, 400) == flags, "Gregorian year-flag table")
    require(image.at(0x6e748, 8) == bytes.fromhex("0000000000004e40"),
            "fixed binary64 duration")
    maximum = (262142 << 13) | (365 << 4) | flags[262142 % 400]
    require(image.at(0x7c7e4, 12) == struct.pack("<III", maximum, 86399, 999999999),
            "maximum ordinary-time fallback")
    return {"anchors": result,
            "relocations": {hex(k): {"type": v[0], "target": hex(v[1]),
                                    "fileOffset": hex(v[2]),
                                    "bytes": image.data[v[2]:v[2]+24].hex()}
                            for k, v in rel.items() if k in SLOTS},
            "tables": {"leapPrefix": {"va": "0x7d692", "bytes": prefix.hex(),
                                     "sha256": digest(prefix), "length": 401},
                       "yearFlags": {"va": "0x7d823", "bytes": flags.hex(),
                                     "sha256": digest(flags), "length": 400}},
            "fallback": {"va": "0x7c7e4", "bytes": image.at(0x7c7e4,12).hex(),
                         "year": 262142, "ordinal": 365, "flags": maximum & 15,
                         "second": 86399, "nano": 999999999}}

def rows(text):
    out = []
    for line in text.splitlines():
        m = re.match(r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(.*)$", line)
        if m:
            out.append((int(m[1], 16), bytes.fromhex(m[2]), m[3].strip()))
    return out

def partition(image, text, start, end):
    found = rows(text)
    cursor = start
    for va, raw, _ in found:
        require(va == cursor and bool(raw) and va+len(raw) <= end, "row partition")
        require(image.at(va, len(raw)) == raw, "row bytes")
        cursor += len(raw)
    require(cursor == end, "row completeness")
    return found

def fde_record(image, frames, name):
    start, end = RANGES[name]
    pattern = r"(?m)^([0-9a-f]+) ([0-9a-f]+) [0-9a-f]+ FDE cie=([0-9a-f]+) pc=([0-9a-f]+)\.\.([0-9a-f]+)"
    found = [m for m in re.finditer(pattern, frames)
             if (int(m[4],16),int(m[5],16)) == (start,end)]
    require(len(found) == 1, "unique exact FDE: "+name)
    m = found[0]
    off, size, cie = int(m[1],16), int(m[2],16)+4, int(m[3],16)
    require((off,size,cie) == FDE_EXPECTED[name], "FDE coordinates: "+name)
    sec = image.by_name[".eh_frame"]
    raw = image.data[sec[4]+off:sec[4]+off+size]
    require(len(raw) == size and struct.unpack_from("<I",raw)[0]+4 == size,
            "FDE record bytes")
    require(off+4-struct.unpack_from("<I",raw,4)[0] == cie,
            "FDE CIE back-reference")
    cie_at = sec[4]+cie
    cie_size = struct.unpack_from("<I",image.data,cie_at)[0]+4
    require(8 <= cie_size and cie+cie_size <= sec[5], "CIE record bounds")
    cie_raw = image.data[cie_at:cie_at+cie_size]
    require(struct.unpack_from("<I",cie_raw,4)[0] == 0, "CIE record ID")
    block = frames[m.start():frames.find("\n\n",m.start())]+"\n"
    return {"sectionOffset": hex(off), "fileOffset": hex(sec[4]+off),
            "cieSectionOffset": hex(cie), "bytes": raw.hex(),
            "sha256": digest(raw), "header": m[0],
            "cieRecord": {"sectionOffset":hex(cie), "fileOffset":hex(cie_at),
                          "bytes":cie_raw.hex(), "sha256":digest(cie_raw)}}, block

def collect(binary, objdump, readelf, llvm):
    image = Image(binary.read_bytes())
    bindings = bind(image)
    versions = {}
    for label, tool in (("objdump",objdump),("readelf",readelf),("llvm",llvm)):
        versions[label] = subprocess.check_output([tool,"--version"],text=True).splitlines()[0]
    require("GNU" in versions["objdump"] and "GNU" in versions["readelf"],
            "GNU native tools required")
    files, records = {}, {}
    with tempfile.TemporaryDirectory(prefix="visor-calendar-static-") as directory:
        private = Path(directory)/"visor.elf"
        private.write_bytes(image.data)
        private.chmod(0o400)
        frames = subprocess.check_output([readelf,"--debug-dump=frames","visor.elf"],
                                         cwd=directory,text=True)
        for name,(start,end) in RANGES.items():
            require(digest(image.at(start,end-start)) == BODY_SHA[name],
                    "body identity: "+name)
            fde, block = fde_record(image,frames,name)
            files[name+".fde.txt"] = block.encode()
            gargs = ["-d","-w","-M","intel","--insn-width=16",
                     f"--start-address={start:#x}",f"--stop-address={end:#x}","visor.elf"]
            largs = ["-d","--x86-asm-syntax=intel",
                     f"--start-address={start:#x}",f"--stop-address={end:#x}","visor.elf"]
            gnu = subprocess.check_output([objdump]+gargs,cwd=directory,text=True)
            ll = subprocess.check_output([llvm]+largs,cwd=directory,text=True)
            first, second = partition(image,gnu,start,end), partition(image,ll,start,end)
            require([(a,b) for a,b,_ in first] == [(a,b) for a,b,_ in second],
                    "independent decoder partition: "+name)
            files[name+".objdump.txt"],files[name+".llvm.txt"] = gnu.encode(),ll.encode()
            # Branch census is local decoding, not complete ownership or xref proof.
            branches, calls = [], []
            starts = {a for a,_,_ in first}
            for va,raw,asm in first:
                mnemonic = asm.split()[0]
                if mnemonic.startswith("j"):
                    dest = re.match(r"j\w*\s+([0-9a-f]+)",asm)
                    require(dest is not None, "unknown branch syntax")
                    target = int(dest[1],16)
                    require(target in starts, "branch not at in-range instruction")
                    branches.append({"va":hex(va),"target":hex(target),"text":asm})
                if mnemonic == "call":
                    calls.append({"va":hex(va),"bytes":raw.hex(),"text":asm})
            records[name] = {"startVA":hex(start),"endVA":hex(end),
                             "fileOffset":hex(image.offset(start,end-start)),
                             "bytes":end-start,"bodySha256":BODY_SHA[name],
                             "nativeRows":len(first),"fde":fde,"branches":branches,
                             "calls":calls,"gnuCommand":["objdump"]+gargs,
                             "llvmCommand":["llvm-objdump"]+largs,
                             "gnuExportSha256":digest(gnu.encode()),
                             "llvmExportSha256":digest(ll.encode())}
        require(private.read_bytes() == image.data, "analysis snapshot changed")
    record = {"schema":1,"targetSha256":SHA256,"targetBytes":SIZE,
              "sourceBase":"56c0ec672bd8fdcfaa80f2db700a61e6240b3663",
              "coordinates":"ELF virtual addresses, PT_LOAD translated file offsets",
              "versions":versions,"ranges":records,"bindings":bindings,
              "decoderScope":{"bytes":sum(b-a for a,b in RANGES.values()),
                              "rows":sum(r["nativeRows"] for r in records.values()),
                              "sameBytePartitions":True},
              "capturedExecution":False,"emulation":False,"newRecoveryCredit":0}
    files["records.json"] = encoded(record)
    return files

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary",required=True,type=Path)
    p.add_argument("--output",required=True,type=Path)
    p.add_argument("--objdump",default="objdump")
    p.add_argument("--readelf",default="readelf")
    p.add_argument("--llvm",default="llvm-objdump")
    a = p.parse_args()
    require(not a.output.exists(),"output already exists; preserve receipts")
    files = collect(a.binary,a.objdump,a.readelf,a.llvm)
    a.output.mkdir(parents=True)
    for name,data in files.items():
        (a.output/name).write_bytes(data)
    print("Bound 4 complete FDE extents; GNU/LLVM byte partitions agree; no target execution.")

if __name__ == "__main__":
    main()
