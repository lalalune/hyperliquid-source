#!/usr/bin/env python3
"""Static verifier for the node #115 lu slot-head packet (RE-001-node115-lu-slothead).

Byte reads only; never executes the node binary. Checks:
- binary SHA-256 and size,
- each exhibit .hex against the binary at its VA (.text VA - 0x1000),
- strict mnemonic-line counts of each .objdump.txt excerpt,
- key instruction bytes (entry endbr64, [slot+8] zero store, ret
  opcodes, signum idiom bytes, E8 rel32 targets),
- FDE bounds (0x63abd00..0x63ac0cc, 972 bytes), zero calls inside
  the FDE, all jump targets inside the FDE,
- census: 6 direct E8 callers, 0 E9, 0 LEA, 0 GOT (60,723 .rela.dyn entries),
- disjointness from adjacent claimed ranges (slot-insert, release),
- MANIFEST.sha256 coverage (15 entries, MANIFEST itself excluded).
"""

import hashlib
import os
import re
import struct
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(REPO, "research", "work-items", "RE-001-node115-lu-slothead")
NODE = os.path.join(REPO, "artifacts", "node", "115", "hl-node")

TARGET_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET_SIZE = 105896032

HEAD_START = 0x63ABD00
HEAD_END = 0x63AC0CC
RET_SITES = (0x63ABF5A, 0x63AC0C3)
CALLERS = (0x63B0912, 0x63B0BC7, 0x63B1131, 0x63B1490, 0x63B14ED, 0x63BCA0F)
# Adjacent claimed ranges that must not overlap this FDE (from #219, #224).
NEIGHBOURS = {
    "slot-insert (#219)": (0x63AC0D0, 0x63AC472),
    "release (#224)": (0x63B0780, 0x63B0980),
}

EXHIBITS = {
    "sh_entry": (0x63ABD00, 0x63ABD36, 54, 16),
    "sh_cmp": (0x63ABD8F, 0x63ABDB6, 39, 13),
    "sh_splice": (0x63ABE00, 0x63ABE36, 54, 14),
    "sh_loop": (0x63ABE36, 0x63ABE60, 42, 10),
    "sh_tail": (0x63ABF23, 0x63ABF4D, 42, 11),
}

INSN_RE = re.compile(r"\s*[0-9a-f]+:\t[0-9a-f ]+\t(\S+)")
JUMP_RE = re.compile(r"\s*[0-9a-f]+:\t[0-9a-f ]+\t(j\w+)\s+([0-9a-f]+)")


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


def text_off(va):
    return va - 0x1000


def main():
    with open(NODE, "rb") as f:
        data = f.read()
    if len(data) != TARGET_SIZE:
        fail(f"binary size {len(data)} != {TARGET_SIZE}")
    sha = hashlib.sha256(data).hexdigest()
    if sha != TARGET_SHA:
        fail(f"binary sha {sha} != {TARGET_SHA}")
    print(f"binary sha ok ({len(data)} bytes)")

    total_bytes = 0
    total_strict = 0
    for name, (start, end, nbytes, strict) in EXHIBITS.items():
        with open(os.path.join(PACKET, name + ".hex")) as f:
            hexs = "".join(f.read().split())
        raw = bytes.fromhex(hexs)
        if len(raw) != nbytes:
            fail(f"{name}: hex length {len(raw)} != {nbytes}")
        got = data[text_off(start):text_off(end)]
        if got != raw:
            fail(f"{name}: binary bytes differ at {hex(start)}")
        with open(os.path.join(PACKET, name + ".objdump.txt")) as f:
            dump = f.read()
        found = INSN_RE.findall(dump)
        if len(found) != strict:
            fail(f"{name}: strict count {len(found)} != {strict}")
        total_bytes += nbytes
        total_strict += strict
    print(f"exhibits ok: {len(EXHIBITS)} excerpts, {total_bytes} bytes, "
          f"{total_strict} strict")

    # Key bytes.
    if data[text_off(0x63ABD00):text_off(0x63ABD00) + 4] != bytes.fromhex("f30f1efa"):
        fail("entry is not endbr64")
    if data[text_off(0x63ABD25):text_off(0x63ABD25) + 8] != bytes.fromhex("48c7470800000000"):
        fail("[slot+8] zero store bytes differ at 0x63abd25")
    if data[text_off(0x63ABD8F):text_off(0x63ABD8F) + 3] != bytes.fromhex("4c39dd"):
        fail("signum cmp bytes differ at 0x63abd8f")
    for site in RET_SITES:
        if data[text_off(site)] != 0xC3:
            fail(f"ret opcode missing at {hex(site)}")
    print("key bytes ok: endbr64, slot+8 zero store, signum cmp, 2 rets")

    # Full-FDE disassembly: zero calls, all jump targets inside the FDE.
    out = subprocess.run(
        ["objdump", "-d", f"--start-address={hex(HEAD_START)}",
         f"--stop-address={hex(HEAD_END)}", NODE],
        capture_output=True, text=True).stdout
    mnemonics = INSN_RE.findall(out)
    if "call" in mnemonics:
        fail("call instruction found inside FDE")
    for m in JUMP_RE.finditer(out):
        tgt = int(m.group(2), 16)
        if not (HEAD_START <= tgt < HEAD_END):
            fail(f"jump target {hex(tgt)} outside FDE")
    print("key calls ok: 0 calls inside FDE, all jumps internal")

    # FDE bounds via readelf.
    frames = subprocess.run(
        ["readelf", "--debug-dump=frames", NODE],
        capture_output=True, text=True).stdout
    if "pc=00000000063abd00..00000000063ac0cc" not in frames:
        fail("FDE bounds 0x63abd00..0x63ac0cc not found in .eh_frame")
    print(f"FDE bounds ok: head 972B")

    # Census: E8 rel32 targets.
    for site in CALLERS:
        o = text_off(site)
        if data[o] != 0xE8:
            fail(f"E8 opcode missing at {hex(site)}")
        rel = struct.unpack("<i", data[o + 1:o + 5])[0]
        if site + 5 + rel != HEAD_START:
            fail(f"E8 at {hex(site)} targets {hex(site + 5 + rel)}")
    e8_hits = []
    i = 0
    while True:
        j = data.find(b"\xe8", i)
        if j < 0:
            break
        if j + 5 <= len(data):
            rel = struct.unpack("<i", data[j + 1:j + 5])[0]
            va = j + 0x1000
            if va + 5 + rel == HEAD_START:
                e8_hits.append(va)
        i = j + 1
    if sorted(e8_hits) != sorted(CALLERS):
        fail(f"E8 census {sorted(hex(x) for x in e8_hits)} != expected")
    e9_hits = []
    i = 0
    while True:
        j = data.find(b"\xe9", i)
        if j < 0:
            break
        if j + 5 <= len(data):
            rel = struct.unpack("<i", data[j + 1:j + 5])[0]
            va = j + 0x1000
            if va + 5 + rel == HEAD_START:
                e9_hits.append(va)
        i = j + 1
    if e9_hits:
        fail(f"E9 sites found: {[hex(x) for x in e9_hits]}")
    lea_re = re.compile(rb"\x48\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]")
    lea_hits = []
    for m in lea_re.finditer(data):
        k = m.start()
        disp = struct.unpack("<i", data[k + 3:k + 7])[0]
        va = k + 0x1000
        if va + 7 + disp == HEAD_START:
            lea_hits.append(va)
    if lea_hits:
        fail(f"LEA sites found: {[hex(x) for x in lea_hits]}")
    # .rela.dyn addend scan.
    e_shoff = struct.unpack("<Q", data[0x28:0x30])[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack("<HHH", data[0x3A:0x40])
    secs = []
    for n in range(e_shnum):
        o = e_shoff + n * e_shentsize
        name, typ, flags, addr, off, size = struct.unpack("<IIQQQQ", data[o:o + 40])
        secs.append((name, typ, addr, off, size))
    shstr_off = secs[e_shstrndx][3]

    def secname(x):
        e = data.index(b"\x00", shstr_off + x)
        return data[shstr_off + x:e].decode()

    rela_total = 0
    got_hits = 0
    for name, typ, addr, off, size in secs:
        if secname(name) == ".rela.dyn":
            rela_total = size // 24
            for k in range(rela_total):
                r_off, r_info, r_add = struct.unpack(
                    "<QQq", data[off + k * 24:off + k * 24 + 24])
                if r_add == HEAD_START:
                    got_hits += 1
    if rela_total != 60723:
        fail(f"rela entries {rela_total} != 60723")
    if got_hits:
        fail(f"GOT addend hits: {got_hits}")
    print(f"census ok: head 6 E8, 0 E9, 0 LEA, 0 GOT, {rela_total} rela entries")

    # Disjointness from adjacent claimed ranges.
    for label, (lo, hi) in NEIGHBOURS.items():
        if HEAD_START < hi and lo < HEAD_END:
            fail(f"FDE overlaps {label}")
    for name, (start, end, nbytes, strict) in EXHIBITS.items():
        if not (HEAD_START <= start and end <= HEAD_END):
            fail(f"exhibit {name} outside FDE")
    print("disjoint ok: exhibits inside FDE, no neighbour overlap")

    # MANIFEST coverage.
    with open(os.path.join(PACKET, "MANIFEST.sha256")) as f:
        lines = [l for l in f.read().splitlines() if l.strip()]
    if len(lines) != 15:
        fail(f"MANIFEST entries {len(lines)} != 15")
    print(f"MANIFEST ok: {len(lines)}/15 entries")

    print(f"verifier: all checks passed ({len(EXHIBITS)} excerpts, "
          f"{total_bytes} bytes, {total_strict} strict, census 6 E8 sites, "
          f"MANIFEST {len(lines)} entries)")


if __name__ == "__main__":
    main()
