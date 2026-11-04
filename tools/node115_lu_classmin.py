#!/usr/bin/env python3
"""Static verifier for the node #115 lu class-minimum-consumer packet
(RE-001-node115-lu-classmin).

Byte reads only; never executes the node binary. Checks:
- binary SHA-256 and size,
- each exhibit .hex against the binary at its VA (.text VA - 0x1000),
- strict mnemonic-line counts of each .objdump.txt excerpt
  (address + bytes field + tab + mnemonic; objdump byte-continuation
  lines carry no mnemonic and are excluded),
- key instruction bytes (entry endbr64, single ret opcode, int3
  padding after the FDE, class-search / take / give-back call rel32s,
  sequence-stamp store, node-embed store, return-value load),
- FDE bounds (0x63b8820..0x63b8d85, 1381 bytes) and that every
  direct branch target in the FDE lies inside the FDE,
- census: 0 direct E8, 0 E9, 1 LEA (0x63b90f5, callback reference),
  0 GOT (60,723 .rela.dyn entries),
- disjointness from neighbouring claimed ranges,
- MANIFEST.sha256 coverage (17 entries, MANIFEST itself excluded).
"""

import hashlib
import os
import re
import struct
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(REPO, "research", "work-items", "RE-001-node115-lu-classmin")
NODE = os.path.join(REPO, "artifacts", "node", "115", "hl-node")

TARGET_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET_SIZE = 105896032

FDE_START = 0x63B8820
FDE_END = 0x63B8D85
RET_SITES = (0x63B889F,)
CALLS = {
    0x63B8918: 0x63D9340,  # class-search helper (#230)
    0x63B892F: 0x63D8E70,  # take helper (cited, not claimed)
    0x63B8A43: 0x63D9070,  # give-back helper (cited, not claimed)
}
# Neighbouring claimed ranges that must not overlap this FDE.
NEIGHBOURS = {
    "class-search (#230)": (0x63D9340, 0x63D945B),
    "class-merge (#231)": (0x63B9690, 0x63B99C8),
    "loop caller A (cited)": (0x63B81B0, 0x63B85F0),
    "finder (#226)": (0x63B0980, 0x63B15E9),
    "slot-head (#225)": (0x63ABD00, 0x63AC0CC),
    "release (#224)": (0x63B0780, 0x63B0980),
    "size rep (#227)": (0x63E8C80, 0x63E8D87),
    "sibling (#224)": (0x63E8BF0, 0x63E8C77),
    "table-fill (#228)": (0x63E8D90, 0x63E9152),
    "descbuild thunk (#229)": (0x63DA080, 0x63DA089),
    "descbuild body (#229)": (0x63D9BA0, 0x63D9ED3),
    "next function": (0x63B8D90, 0x63B9000),
}

EXHIBITS = {
    "cm_entry": (0x63B8820, 0x63B8874, 84, 20),
    "cm_fetch": (0x63B88DE, 0x63B8923, 69, 16),
    "cm_take": (0x63B8929, 0x63B895C, 51, 12),
    "cm_build": (0x63B895C, 0x63B89C0, 100, 22),
    "cm_give": (0x63B8A3D, 0x63B8A5A, 29, 7),
    "cm_ret": (0x63B8AD0, 0x63B8ADA, 10, 2),
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
    if FDE_END - FDE_START != 1381:
        fail("FDE size mismatch")
    off = lambda va: va - 0x1000
    if data[off(FDE_START):off(FDE_START) + 4] != bytes.fromhex("f30f1efa"):
        fail("entry is not endbr64")
    for site in RET_SITES:
        if data[off(site)] != 0xC3:
            fail("ret site %s is not 0xc3" % hex(site))
    if data[off(FDE_END)] != 0xCC:
        fail("byte after FDE is not int3 padding")
    for site, target in CALLS.items():
        if data[off(site)] != 0xE8:
            fail("call site %s is not E8" % hex(site))
        rel = struct.unpack_from("<i", data, off(site) + 1)[0]
        if site + 5 + rel != target:
            fail("call site %s does not target %s" % (hex(site), hex(target)))
    # Sequence-stamp store: mov %rcx,0x8(%r14) at 0x63b894d.
    if data[off(0x63B894D):off(0x63B894D) + 4] != bytes.fromhex("49894e08"):
        fail("stamp store bytes mismatch")
    # Node-embed store: mov %r14,0x18(%r15) at 0x63b89bc.
    if data[off(0x63B89BC):off(0x63B89BC) + 4] != bytes.fromhex("4d897718"):
        fail("embed store bytes mismatch")
    # Return-value load: mov 0x48(%rsp),%rax at 0x63b8ad0.
    if data[off(0x63B8AD0):off(0x63B8AD0) + 5] != bytes.fromhex("488b442448"):
        fail("return load bytes mismatch")
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
    rets = [l for l in out.splitlines() if re.search(r"\tret\s*$", l)]
    if len(rets) != 1:
        fail("expected exactly 1 ret in FDE, found %d" % len(rets))
    for line in out.splitlines():
        m = BRANCH_RE.search(line)
        if m and not (FDE_START <= int(m.group(2), 16) < FDE_END):
            fail("branch target %s outside FDE" % m.group(2))
    # Census: whole-.text scan for E8/E9/LEA resolving to FDE_START.
    # .text: file range [0x1418300, 0x1418300 + 0x4fd7700), VA = off + 0x1000.
    t_off, t_size = 0x1418300, 0x4FD7700
    e8, e9, lea = [], [], []
    for o in range(t_off, t_off + t_size - 7):
        va = o + 0x1000
        b = data[o]
        if b in (0xE8, 0xE9):
            rel = struct.unpack("<i", data[o + 1:o + 5])[0]
            if va + 5 + rel == FDE_START:
                (e8 if b == 0xE8 else e9).append(va)
        if 0x48 <= b <= 0x4F and data[o + 1] == 0x8D \
                and (data[o + 2] & 0xC7) == 0x05:
            rel = struct.unpack("<i", data[o + 3:o + 7])[0]
            if va + 7 + rel == FDE_START:
                lea.append(va)
    if e8 or e9:
        fail("unexpected E8/E9 sites: %s %s" % (e8, e9))
    if [hex(x) for x in lea] != ["0x63b90f5"]:
        fail("LEA census mismatch: %s" % [hex(x) for x in lea])
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
    if len(entries) != 17:
        fail("MANIFEST has %d entries, expected 17" % len(entries))
    names = [path for _digest, path in entries]
    if "MANIFEST.sha256" in names:
        fail("MANIFEST lists itself")
    for digest, path in entries:
        with open(os.path.normpath(os.path.join(PACKET, path)), "rb") as f:
            if hashlib.sha256(f.read()).hexdigest() != digest:
                fail("MANIFEST mismatch for %s" % path)
    print("verifier: all checks passed (6 excerpts, 343 bytes, 79 strict, "
          "census 0 E8 / 0 E9 / 1 LEA, MANIFEST 17/17)")


if __name__ == "__main__":
    main()
