#!/usr/bin/env python3
"""Static verifier for the node #115 lu slot-find packet (RE-001-node115-lu-slotfind).

Byte reads only; never executes the node binary. Checks:
- binary SHA-256 and size,
- each exhibit .hex against the binary at its VA (.text VA - 0x1000),
- strict mnemonic-line counts of each .objdump.txt excerpt,
- key instruction bytes (entry endbr64, ret opcode, internal E8 rel32
  targets, range-check bytes),
- FDE bounds (0x63b0980..0x63b15e9, 3177 bytes), 8 calls inside the
  FDE, all jump targets inside the FDE,
- census: 1 direct E8 caller, 0 E9, 0 LEA, 0 GOT (60,723 .rela.dyn entries),
- disjointness from adjacent claimed ranges (release, chain helper),
- MANIFEST.sha256 coverage (15 entries, MANIFEST itself excluded).
"""

import hashlib
import os
import re
import struct
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(REPO, "research", "work-items", "RE-001-node115-lu-slotfind")
NODE = os.path.join(REPO, "artifacts", "node", "115", "hl-node")

TARGET_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET_SIZE = 105896032

FDE_START = 0x63B0980
FDE_END = 0x63B15E9
RET_SITE = 0x63B132B
CALLER = 0x63B49A3
INTERNAL_CALLS = {
    0x63B09CB: 0x63E8C80,
    0x63B0BBB: 0x63ABCF0,
    0x63B0BC7: 0x63ABD00,
    0x63B0F62: 0x63E8C80,
    0x63B0FBC: 0x63E8C80,
    0x63B1131: 0x63ABD00,
    0x63B1490: 0x63ABD00,
    0x63B14ED: 0x63ABD00,
}
# Adjacent claimed ranges that must not overlap this FDE.
NEIGHBOURS = {
    "release (#224)": (0x63B0780, 0x63B0980),
    "chain helper (#213)": (0x63B1B60, 0x63B1D35),
}

EXHIBITS = {
    "fe_entry": (0x63B0980, 0x63B09D0, 80, 21),
    "fe_index": (0x63B09EA, 0x63B0A22, 56, 16),
    "fe_flag": (0x63B0BAC, 0x63B0BD6, 42, 12),
    "fe_scan": (0x63B0C15, 0x63B0C6E, 89, 26),
    "fe_range": (0x63B1136, 0x63B1172, 60, 16),
}

INSN_RE = re.compile(r"\s*[0-9a-f]+:\t[0-9a-f ]+\t(\S+)")
JUMP_RE = re.compile(r"\s*[0-9a-f]+:\t[0-9a-f ]+\t(j\w+)\s+([0-9a-f]+)")


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


def text_off(va):
    return va - 0x1000


def sections(data):
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

    return {secname(s[0]): s for s in secs}


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
    if data[text_off(0x63B0980):text_off(0x63B0980) + 4] != bytes.fromhex("f30f1efa"):
        fail("entry is not endbr64")
    if data[text_off(RET_SITE)] != 0xC3:
        fail("ret opcode missing at 0x63b132b")
    if data[text_off(0x63B1136):text_off(0x63B1136) + 4] != bytes.fromhex("488b0c24"):
        fail("range-check mov bytes differ at 0x63b1136")
    print("key bytes ok: endbr64, ret, range-check mov")

    # Full-FDE disassembly: 8 internal calls, all jump targets inside.
    out = subprocess.run(
        ["objdump", "-d", f"--start-address={hex(FDE_START)}",
         f"--stop-address={hex(FDE_END)}", NODE],
        capture_output=True, text=True).stdout
    mnemonics = INSN_RE.findall(out)
    if mnemonics.count("call") != 8:
        fail(f"call count {mnemonics.count('call')} != 8 inside FDE")
    for m in JUMP_RE.finditer(out):
        tgt = int(m.group(2), 16)
        if not (FDE_START <= tgt < FDE_END):
            fail(f"jump target {hex(tgt)} outside FDE")
    print("key calls ok: 8 calls inside FDE, all jumps internal")

    # Internal call rel32 targets.
    for site, tgt in INTERNAL_CALLS.items():
        o = text_off(site)
        if data[o] != 0xE8:
            fail(f"E8 opcode missing at {hex(site)}")
        rel = struct.unpack("<i", data[o + 1:o + 5])[0]
        if site + 5 + rel != tgt:
            fail(f"E8 at {hex(site)} targets {hex(site + 5 + rel)}")
    print("key calls ok: 8 internal E8 rel32 targets verified")

    # FDE bounds via readelf.
    frames = subprocess.run(
        ["readelf", "--debug-dump=frames", NODE],
        capture_output=True, text=True).stdout
    if "pc=00000000063b0980..00000000063b15e9" not in frames:
        fail("FDE bounds 0x63b0980..0x63b15e9 not found in .eh_frame")
    print(f"FDE bounds ok: finder 3177B")

    # Census: E8/E9 rel32 targets within .text, LEA, .rela.dyn addends.
    secs = sections(data)
    _, _, taddr, toff, tsize = secs[".text"]
    text = data[toff:toff + tsize]

    def va_of(off_in_text):
        return taddr + off_in_text

    e8_hits = []
    i = 0
    while True:
        j = text.find(b"\xe8", i)
        if j < 0:
            break
        if j + 5 <= len(text):
            rel = struct.unpack("<i", text[j + 1:j + 5])[0]
            va = va_of(j)
            if va + 5 + rel == FDE_START:
                e8_hits.append(va)
        i = j + 1
    if e8_hits != [CALLER]:
        fail(f"E8 census {[hex(x) for x in e8_hits]} != [0x63b49a3]")
    o = text_off(CALLER)
    if data[o] != 0xE8:
        fail("E8 opcode missing at caller 0x63b49a3")
    rel = struct.unpack("<i", data[o + 1:o + 5])[0]
    if CALLER + 5 + rel != FDE_START:
        fail("caller E8 target mismatch")
    e9_hits = []
    i = 0
    while True:
        j = text.find(b"\xe9", i)
        if j < 0:
            break
        if j + 5 <= len(text):
            rel = struct.unpack("<i", text[j + 1:j + 5])[0]
            va = va_of(j)
            if va + 5 + rel == FDE_START:
                e9_hits.append(va)
        i = j + 1
    if e9_hits:
        fail(f"E9 sites found: {[hex(x) for x in e9_hits]}")
    lea_re = re.compile(rb"\x48\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]")
    lea_hits = []
    for m in lea_re.finditer(text):
        k = m.start()
        disp = struct.unpack("<i", text[k + 3:k + 7])[0]
        va = va_of(k)
        if va + 7 + disp == FDE_START:
            lea_hits.append(va)
    if lea_hits:
        fail(f"LEA sites found: {[hex(x) for x in lea_hits]}")
    _, _, _, roff, rsize = secs[".rela.dyn"]
    rela_total = rsize // 24
    got_hits = 0
    for k in range(rela_total):
        r_off, r_info, r_add = struct.unpack(
            "<QQq", data[roff + k * 24:roff + k * 24 + 24])
        if r_add == FDE_START:
            got_hits += 1
    if rela_total != 60723:
        fail(f"rela entries {rela_total} != 60723")
    if got_hits:
        fail(f"GOT addend hits: {got_hits}")
    print(f"census ok: finder 1 E8, 0 E9, 0 LEA, 0 GOT, {rela_total} rela entries")

    # Disjointness from adjacent claimed ranges.
    for label, (lo, hi) in NEIGHBOURS.items():
        if FDE_START < hi and lo < FDE_END:
            fail(f"FDE overlaps {label}")
    for name, (start, end, nbytes, strict) in EXHIBITS.items():
        if not (FDE_START <= start and end <= FDE_END):
            fail(f"exhibit {name} outside FDE")
    print("disjoint ok: exhibits inside FDE, no neighbour overlap")

    # MANIFEST coverage.
    with open(os.path.join(PACKET, "MANIFEST.sha256")) as f:
        lines = [l for l in f.read().splitlines() if l.strip()]
    if len(lines) != 15:
        fail(f"MANIFEST entries {len(lines)} != 15")
    print(f"MANIFEST ok: {len(lines)}/15 entries")

    print(f"verifier: all checks passed ({len(EXHIBITS)} excerpts, "
          f"{total_bytes} bytes, {total_strict} strict, census 1 E8 site, "
          f"MANIFEST {len(lines)} entries)")


if __name__ == "__main__":
    main()
