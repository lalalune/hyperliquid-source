#!/usr/bin/env python3
"""Static verifier for the node #115 lu class-merge packet
(RE-001-node115-lu-classmerge).

Byte reads only; never executes the node binary. Checks:
- binary SHA-256 and size,
- each exhibit .hex against the binary at its VA (.text VA - 0x1000),
- strict mnemonic-line counts of each .objdump.txt excerpt
  (address + bytes field + tab + mnemonic; objdump byte-continuation
  lines carry no mnemonic and are excluded),
- key instruction bytes (entry endbr64, single ret opcode, int3
  padding after the FDE, class-search tail-jump rel32),
- FDE bounds (0x63b9690..0x63b99c8, 824 bytes), zero calls,
  all branch targets inside the FDE, no 0x20 operand in the FDE,
- census: 0 direct E8, 1 E9 (class-search tail call), 0 LEA,
  0 GOT (60,723 .rela.dyn entries),
- disjointness from neighbouring claimed ranges,
- MANIFEST.sha256 coverage (15 entries, MANIFEST itself excluded).
"""

import hashlib
import os
import re
import struct
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(REPO, "research", "work-items", "RE-001-node115-lu-classmerge")
NODE = os.path.join(REPO, "artifacts", "node", "115", "hl-node")

TARGET_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET_SIZE = 105896032

FDE_START = 0x63B9690
FDE_END = 0x63B99C8
RET_SITES = (0x63B9925,)
TAIL_JUMP = {0x63D940A: 0x63B9690}
# Neighbouring claimed ranges that must not overlap this FDE.
NEIGHBOURS = {
    "class-search (#230)": (0x63D9340, 0x63D945B),
    "finder (#226)": (0x63B0980, 0x63B15E9),
    "slot-head (#225)": (0x63ABD00, 0x63AC0CC),
    "release (#224)": (0x63B0780, 0x63B0980),
    "size rep (#227)": (0x63E8C80, 0x63E8D87),
    "sibling (#224)": (0x63E8BF0, 0x63E8C77),
    "table-fill (#228)": (0x63E8D90, 0x63E9152),
    "descbuild thunk (#229)": (0x63DA080, 0x63DA089),
    "descbuild body (#229)": (0x63D9BA0, 0x63D9ED3),
    "next function": (0x63B99D0, 0x63B9C00),
}

EXHIBITS = {
    "cs_entry": (0x63B9690, 0x63B96C6, 54, 16),
    "cs_pair": (0x63B9700, 0x63B9758, 88, 23),
    "cs_loop": (0x63B97D4, 0x63B97F6, 34, 9),
    "cs_phaseb": (0x63B9840, 0x63B9887, 71, 18),
    "cs_final": (0x63B98D1, 0x63B991B, 74, 20),
}

STRICT_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t\S")
BRANCH_RE = re.compile(r"\t(jmp|je|jne|ja|jb|jae|jbe|js|jns|jo|jno)\s+([0-9a-f]+)")


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


def read_node():
    with open(NODE, "rb") as f:
        return f.read()


def main():
    data = read_node()
    if hashlib.sha256(data).hexdigest() != TARGET_SHA:
        fail("binary SHA-256 mismatch")
    if len(data) != TARGET_SIZE:
        fail("binary size mismatch")
    if FDE_END - FDE_START != 824:
        fail("FDE size mismatch")
    off = lambda va: va - 0x1000
    if data[off(FDE_START):off(FDE_START) + 4] != bytes.fromhex("f30f1efa"):
        fail("entry is not endbr64")
    for site in RET_SITES:
        if data[off(site)] != 0xC3:
            fail("ret site %s is not 0xc3" % hex(site))
    if data[off(FDE_END)] != 0xCC:
        fail("byte after FDE is not int3 padding")
    for site, target in TAIL_JUMP.items():
        if data[off(site)] != 0xE9:
            fail("tail site %s is not E9" % hex(site))
        rel = struct.unpack_from("<i", data, off(site) + 1)[0]
        if site + 5 + rel != target:
            fail("tail site %s does not target %s" % (hex(site), hex(target)))
    for name, (start, end, nbytes, nstrict) in EXHIBITS.items():
        with open(os.path.join(PACKET, name + ".hex")) as f:
            raw = bytes.fromhex("".join(f.read().split()))
        if len(raw) != nbytes:
            fail("%s byte length %d != %d" % (name, len(raw), nbytes))
        if raw != data[off(start):off(start) + nbytes]:
            fail("%s bytes do not match binary" % name)
        with open(os.path.join(PACKET, name + ".objdump.txt")) as f:
            strict = sum(1 for line in f if STRICT_RE.match(line))
        if strict != nstrict:
            fail("%s strict count %d != %d" % (name, strict, nstrict))
    # FDE-wide disassembly checks via objdump (byte reads only).
    import subprocess
    out = subprocess.run(
        ["objdump", "-d", "--start-address=%s" % hex(FDE_START),
         "--stop-address=%s" % hex(FDE_END), NODE],
        capture_output=True, text=True, check=True).stdout
    calls = [l for l in out.splitlines() if "\tcall" in l]
    if calls:
        fail("FDE contains call instructions: %s" % calls[:3])
    if "0x20(" in out:
        fail("FDE reads a +0x20 operand")
    for line in out.splitlines():
        m = BRANCH_RE.search(line)
        if m and not (FDE_START <= int(m.group(2), 16) < FDE_END):
            fail("branch target %s outside FDE" % m.group(2))
    # Census: full-file scan for E8/E9/LEA resolving to FDE_START.
    e8, e9, lea = [], [], []
    for o in range(0, len(data) - 7):
        va = o + 0x1000
        b = data[o]
        if b in (0xE8, 0xE9):
            rel = struct.unpack("<i", data[o + 1:o + 5])[0]
            if va + 5 + rel == FDE_START:
                (e8 if b == 0xE8 else e9).append(va)
        if b in (0x48, 0x49, 0x4C, 0x4D) and data[o + 1] == 0x8D \
                and (data[o + 2] & 0xC7) == 0x05:
            rel = struct.unpack("<i", data[o + 3:o + 7])[0]
            if va + 7 + rel == FDE_START:
                lea.append(va)
    if e8 or lea:
        fail("unexpected E8/LEA sites: %s %s" % (e8, lea))
    if [hex(x) for x in e9] != ["0x63d940a"]:
        fail("E9 census mismatch: %s" % [hex(x) for x in e9])
    # .rela.dyn addend scan (file offset 0x6be8, 60,723 entries).
    ro, n = 0x6BE8, 60723
    for i in range(n):
        _off, _info, add = struct.unpack_from("<QQq", data, ro + i * 24)
        if add == FDE_START:
            fail("rela addend hits FDE start")
    for label, (s, e) in NEIGHBOURS.items():
        if not (e <= FDE_START or s >= FDE_END):
            fail("FDE overlaps %s" % label)
    with open(os.path.join(PACKET, "MANIFEST.sha256")) as f:
        entries = [line.split() for line in f if line.strip()]
    if len(entries) != 15:
        fail("MANIFEST has %d entries, expected 15" % len(entries))
    names = [path for _digest, path in entries]
    if "MANIFEST.sha256" in names:
        fail("MANIFEST lists itself")
    for digest, path in entries:
        with open(os.path.normpath(os.path.join(PACKET, path)), "rb") as f:
            if hashlib.sha256(f.read()).hexdigest() != digest:
                fail("MANIFEST mismatch for %s" % path)
    print("all checks passed")


if __name__ == "__main__":
    main()
