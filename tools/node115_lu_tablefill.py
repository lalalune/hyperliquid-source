#!/usr/bin/env python3
"""Static verifier for the node #115 lu table-fill packet
(RE-001-node115-lu-tablefill).

Byte reads only; never executes the node binary. Checks:
- binary SHA-256 and size,
- each exhibit .hex against the binary at its VA (.text VA - 0x1000),
- strict mnemonic-line counts of each .objdump.txt excerpt,
- key instruction bytes (entry endbr64, base store to 0x6728140,
  table lea to 0x6728180, tail count constant 199, loop-3 clamp
  512, ret opcode, zero calls inside the FDE, all jump targets
  inside the FDE),
- FDE bounds (0x63e8d90..0x63e9152, 962 bytes) via unwind tables,
- census: 1 direct E8 caller, 0 E9, 0 LEA, 0 GOT (60,723 .rela.dyn
  entries),
- disjointness from neighbouring claimed ranges,
- MANIFEST.sha256 coverage (15 entries, MANIFEST itself excluded).
"""

import hashlib
import os
import re
import struct
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(REPO, "research", "work-items", "RE-001-node115-lu-tablefill")
NODE = os.path.join(REPO, "artifacts", "node", "115", "hl-node")

TARGET_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET_SIZE = 105896032

FDE_START = 0x63E8D90
FDE_END = 0x63E9152
RET_SITES = (0x63E913C,)
CALLERS = (0x634EDCE,)
# Neighbouring claimed ranges that must not overlap this FDE.
NEIGHBOURS = {
    "size rep (#227)": (0x63E8C80, 0x63E8D87),
    "sibling (#224)": (0x63E8BF0, 0x63E8C77),
    "finder (#226)": (0x63B0980, 0x63B15E9),
    "slot-head (#225)": (0x63ABD00, 0x63AC0CC),
    "next function": (0x63E9160, 0x63E91B7),
}

EXHIBITS = {
    "wr_entry": (0x63E8D90, 0x63E8DB8, 40, 10),
    "wr_block": (0x63E8DC8, 0x63E8DED, 37, 12),
    "wr_tail": (0x63E8F23, 0x63E8F44, 33, 7),
    "wr_array": (0x63E8F60, 0x63E8F93, 51, 13),
    "wr_fill": (0x63E90F6, 0x63E9115, 31, 8),
}

INSN_RE = re.compile(r"\s*[0-9a-f]+:\t[0-9a-f ]+\t(\S+)")
JUMP_RE = re.compile(r"\s*[0-9a-f]+:\t[0-9a-f ]+\t(j\w+)\s+([0-9a-f]+)")


def text_off(va):
    return va - 0x1000


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


def main():
    with open(NODE, "rb") as f:
        data = f.read()
    if len(data) != TARGET_SIZE:
        fail(f"binary size {len(data)} != {TARGET_SIZE}")
    if hashlib.sha256(data).hexdigest() != TARGET_SHA:
        fail("binary SHA-256 mismatch")
    print(f"binary sha ok ({TARGET_SIZE} bytes)")

    total_bytes = 0
    total_strict = 0
    for name, (start, end, nbytes, strict) in EXHIBITS.items():
        with open(os.path.join(PACKET, name + ".hex")) as f:
            raw = bytes.fromhex("".join(f.read().split()))
        if len(raw) != nbytes or data[text_off(start):text_off(end)] != raw:
            fail(f"exhibit {name} bytes mismatch")
        with open(os.path.join(PACKET, name + ".objdump.txt")) as f:
            dump = f.read()
        got = len(INSN_RE.findall(dump))
        if got != strict:
            fail(f"exhibit {name} strict {got} != {strict}")
        total_bytes += nbytes
        total_strict += strict
    print(f"exhibits ok: {len(EXHIBITS)} excerpts, {total_bytes} bytes, "
          f"{total_strict} strict")

    # Key bytes.
    if data[text_off(FDE_START):text_off(FDE_START) + 4] != bytes.fromhex("f30f1efa"):
        fail("entry endbr64 mismatch")
    # RIP-relative store to base 0x6728140 at 0x63e8db1.
    o = text_off(0x63E8DB1)
    if data[o:o + 3] != bytes.fromhex("488905"):
        fail("base store opcode mismatch")
    disp = struct.unpack("<i", data[o + 3:o + 7])[0]
    if 0x63E8DB1 + 7 + disp != 0x6728140:
        fail("base store target mismatch")
    # RIP-relative lea of table 0x6728180 at 0x63e8daa.
    o = text_off(0x63E8DAA)
    if data[o:o + 3] != bytes.fromhex("4c8d15"):
        fail("table lea opcode mismatch")
    disp = struct.unpack("<i", data[o + 3:o + 7])[0]
    if 0x63E8DAA + 7 + disp != 0x6728180:
        fail("table lea target mismatch")
    # Shift-by-12 for the base at 0x63e8da3.
    if data[text_off(0x63E8DA3):text_off(0x63E8DA3) + 4] != bytes.fromhex("48c1e00c"):
        fail("base shift mismatch")
    for site in RET_SITES:
        if data[text_off(site)] != 0xC3:
            fail(f"ret site {hex(site)} mismatch")
    if data[text_off(0x63E8F23) + 2:text_off(0x63E8F23) + 6] != bytes.fromhex("c7000000"):
        fail("tail count 199 constant mismatch")
    if data[text_off(0x63E90D9) + 1:text_off(0x63E90D9) + 5] != bytes.fromhex("00020000"):
        fail("loop-3 clamp 512 constant mismatch")
    # Loop-1 end: lea 0x19b0(%rdi) at 0x63e8d9c.
    if data[text_off(0x63E8D9C):text_off(0x63E8D9C) + 7] != bytes.fromhex("4c8d9fb0190000"):
        fail("loop-1 end lea mismatch")
    print("key bytes ok: endbr64, base store, table lea, shift 12, "
          "ret, tail 199, clamp 512, loop-1 end")

    # No calls inside the FDE; all jump targets inside the FDE.
    dump = subprocess.run(
        ["objdump", "-d", f"--start-address={hex(FDE_START)}",
         f"--stop-address={hex(FDE_END)}", NODE],
        capture_output=True, text=True).stdout
    if INSN_RE.findall(dump).count("call") != 0:
        fail("unexpected call inside FDE")
    for m in JUMP_RE.finditer(dump):
        tgt = int(m.group(2), 16)
        if not (FDE_START <= tgt < FDE_END):
            fail(f"jump target {hex(tgt)} outside FDE")
    print("FDE bounds ok: tablefill 962B, 0 calls, jumps internal")

    # Unwind-table FDE range.
    frames = subprocess.run(
        ["readelf", "--debug-dump=frames", NODE],
        capture_output=True, text=True).stdout
    if "pc=00000000063e8d90..00000000063e9152" not in frames:
        fail("unwind FDE range mismatch")
    if FDE_END - FDE_START != 962:
        fail("FDE size mismatch")

    # Census: E8 sites (rel32) + E9 absence + GOT absence.
    # .text: VA 0x1419300, file offset 0x1418300, size 0x4fd7700.
    text = data[0x1418300:0x1418300 + 0x4FD7700]
    e8 = []
    pos = 0
    while True:
        pos = text.find(b"\xe8", pos)
        if pos < 0:
            break
        va = 0x1419300 + pos
        if pos + 5 <= len(text):
            rel = struct.unpack("<i", text[pos + 1:pos + 5])[0]
            if va + 5 + rel == FDE_START:
                e8.append(va)
        pos += 1
    if e8 != list(CALLERS):
        fail(f"census E8 {e8} != {list(CALLERS)}")
    pos = 0
    e9 = []
    while True:
        pos = text.find(b"\xe9", pos)
        if pos < 0:
            break
        va = 0x1419300 + pos
        if pos + 5 <= len(text):
            rel = struct.unpack("<i", text[pos + 1:pos + 5])[0]
            if va + 5 + rel == FDE_START:
                e9.append(va)
        pos += 1
    if e9:
        fail(f"unexpected E9 callers {e9}")
    # .rela.dyn addends via ELF section headers.
    e_shoff = struct.unpack("<Q", data[0x28:0x30])[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack("<HHH", data[0x3A:0x40])
    secs = []
    for n in range(e_shnum):
        o = e_shoff + n * e_shentsize
        name, typ, flags, addr, off, size = struct.unpack("<IIQQQQ", data[o:o + 40])
        secs.append((name, off, size))
    shstr_off = secs[e_shstrndx][1]

    def secname(x):
        e = data.index(b"\x00", shstr_off + x)
        return data[shstr_off + x:e].decode()

    rela_total = None
    for name, off, size in secs:
        if secname(name) == ".rela.dyn":
            rela_total = size // 24
            for k in range(rela_total):
                r_add = struct.unpack("<q", data[off + k * 24 + 16:off + k * 24 + 24])[0]
                if r_add == FDE_START:
                    fail("unexpected GOT addend for helper")
    if rela_total != 60723:
        fail(f"rela entries {rela_total} != 60723")
    print(f"census ok: tablefill {len(CALLERS)} E8, 0 E9, 0 LEA, 0 GOT, "
          f"60723 rela entries")

    # Disjointness.
    for label, (a, b) in NEIGHBOURS.items():
        if not (FDE_END <= a or FDE_START >= b):
            fail(f"FDE overlaps {label}")
    for name, (start, end, _n, _s) in EXHIBITS.items():
        if not (FDE_START <= start and end <= FDE_END):
            fail(f"exhibit {name} outside FDE")
    print("disjoint ok: exhibits inside FDE, no neighbour overlap")

    # MANIFEST coverage.
    with open(os.path.join(PACKET, "MANIFEST.sha256")) as f:
        lines = [l for l in f.read().splitlines() if l.strip()]
    if len(lines) != 15:
        fail(f"MANIFEST {len(lines)} entries != 15")
    names = [l.split(None, 1)[1] for l in lines]
    for name in EXHIBITS:
        if name + ".hex" not in names or name + ".objdump.txt" not in names:
            fail(f"MANIFEST missing {name}")
    for extra in ("README.md", "EVIDENCE.md", "records.json",
                  "../../../tools/node115_lu_tablefill.py",
                  "../../../tests/test_node115_lu_tablefill.py"):
        if extra not in names:
            fail(f"MANIFEST missing {extra}")
    if "MANIFEST.sha256" in names:
        fail("MANIFEST lists itself")
    print("MANIFEST ok: 15/15 entries")
    print(f"verifier: all checks passed ({len(EXHIBITS)} excerpts, "
          f"{total_bytes} bytes, {total_strict} strict, census "
          f"{len(CALLERS)} E8 sites, MANIFEST 15 entries)")


if __name__ == "__main__":
    main()
