#!/usr/bin/env python3
"""Static ELF replay of one node115 Location consumer boundary; never runs target."""
import argparse
import hashlib
import json
import re
import struct
import subprocess
from pathlib import Path

TARGET = "artifacts/node/115/hl-node"
SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
ANCHOR = 0x2b2c061
LOCATION = 0x644ab80
CALL = 0x2b2c078
CALLEE = 0x2698f40
BRANCH = 0x2b2c089
DESTINATION = 0x2b2c0a0
# Independently recorded from the single bounded GNU objdump excerpt.
PREFIX = bytes.fromhex("488d0d18eb9103 488dbc2490000000 488d742420 4c89e2 e8c3ceb6ff 4c8bb42490000000 4983fe02 7515")


def require(ok, message):
    if not ok:
        raise ValueError(message)


class Elf:
    def __init__(self, data):
        self.data = data
        require(data[:6] == b"\x7fELF\x02\x01", "ELF64 little endian")
        require(struct.unpack_from("<H", data, 18)[0] == 62, "x86-64")
        phoff = struct.unpack_from("<Q", data, 32)[0]
        pe, pn = struct.unpack_from("<HH", data, 54)
        self.loads = []
        for i in range(pn):
            p = struct.unpack_from("<IIQQQQQQ", data, phoff + i * pe)
            if p[0] == 1:
                self.loads.append((p[3], p[2], p[5]))
        shoff = struct.unpack_from("<Q", data, 40)[0]
        se, sn = struct.unpack_from("<HH", data, 58)
        self.sections = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * se) for i in range(sn)]

    def offset(self, va, n):
        matches = [o + va - v for v, o, z in self.loads if v <= va and va + n <= v + z]
        require(len(matches) == 1, "unique file-backed PT_LOAD mapping")
        require(matches[0] + n <= len(self.data), "mapped range within file")
        return matches[0]

    def read(self, va, n):
        o = self.offset(va, n)
        return self.data[o:o+n]

    def relative(self, va):
        found = []
        for s in self.sections:
            if s[1] != 4:
                continue
            require(s[9] == 24, "ELF64 Rela entry size")
            for o in range(s[4], s[4] + s[5], 24):
                address, info, addend = struct.unpack_from("<QQq", self.data, o)
                if address == va:
                    found.append((info, addend, o))
        require(len(found) == 1, "unique Location relocation")
        info, addend, offset = found[0]
        require(info == 8, "R_X86_64_RELATIVE with symbol zero")
        return addend, offset


def fde_ranges(text):
    return [(int(a, 16), int(z, 16)) for a, z in re.findall(r"FDE .*?pc=([0-9a-f]+)\.\.([0-9a-f]+)", text)]


def verify_content(data, frames):
    """Field controls call this without the CLI's mandatory whole-target digest gate."""
    elf = Elf(data)
    code = elf.read(ANCHOR, len(PREFIX))
    require(code == PREFIX, "exact consumer instruction sequence, including no RCX write before call")
    require(ANCHOR + 7 + struct.unpack_from("<i", code, 3)[0] == LOCATION, "Location RIP displacement")
    calloff = CALL - ANCHOR
    require(CALL + 5 + struct.unpack_from("<i", code, calloff + 1)[0] == CALLEE, "direct call target")
    boff = BRANCH - ANCHOR
    require(BRANCH + 2 + struct.unpack_from("<b", code, boff + 1)[0] == DESTINATION, "jne target")
    require(elf.read(LOCATION, 8) == bytes(8), "zero unapplied relocation slot")
    require(struct.unpack("<QII", elf.read(LOCATION + 8, 16)) == (22, 29, 26), "Location length/line/column")
    source, relocation_offset = elf.relative(LOCATION)
    require(source == 0x4422bd, "Location relocation addend")
    require(elf.read(source, 22) == b"db/src/block_reader.rs", "exact source path")
    ranges = fde_ranges(frames)
    for va in (ANCHOR, CALL, BRANCH, DESTINATION):
        require([r for r in ranges if r[0] <= va < r[1]] == [(0x2b2be60, 0x2b2c4f1)], "caller FDE")
    require([r for r in ranges if r[0] <= CALLEE < r[1]] == [(CALLEE, 0x26990ca)], "callee entry FDE")
    return {
        "location": hex(LOCATION), "location_file_offset": hex(elf.offset(LOCATION, 24)),
        "source": "db/src/block_reader.rs", "source_vaddr": hex(source),
        "source_file_offset": hex(elf.offset(source, 22)), "line": 29, "column": 26,
        "caller_fde": ["0x2b2be60", "0x2b2c4f1"], "callee_fde": [hex(CALLEE), "0x26990ca"],
        "rcx_load": hex(ANCHOR), "call": hex(CALL), "call_target": hex(CALLEE),
        "return_slot": "[rsp+0x90]", "comparison": "r14 != 2", "branch": hex(BRANCH),
        "branch_taken": hex(DESTINATION), "branch_fallthrough": hex(BRANCH + 2),
        "validated_instruction_bytes": len(PREFIX), "native_excerpt_bytes": 128,
        "captured_target_executed": False, "error_tag_semantics": "unresolved",
    }


def authenticate(data):
    require(hashlib.sha256(data).hexdigest() == SHA256, "target SHA-256")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--target", default=TARGET)
    a = p.parse_args()
    data = Path(a.target).read_bytes()
    authenticate(data)
    frames = subprocess.run(["readelf", "--debug-dump=frames", a.target], check=True, capture_output=True, text=True).stdout
    result = verify_content(data, frames)
    result["target_sha256"] = SHA256
    result["readelf_version"] = subprocess.run(["readelf", "--version"], check=True, capture_output=True, text=True).stdout.splitlines()[0]
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
