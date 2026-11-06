#!/usr/bin/env python3
"""Static verifier for the node #115 lu loop-caller packet
(RE-001-node115-lu-loopcaller).

Byte reads only; never executes the node binary. Checks:
- binary SHA-256 and size,
- each exhibit .hex against the binary at its VA (.text VA - 0x1000),
- strict mnemonic-line counts of each .objdump.txt excerpt
  (address + bytes field + tab + mnemonic; objdump byte-continuation
  lines carry no mnemonic and are excluded),
- key instruction bytes (entry push sequence -- notably NOT endbr64,
  single ret opcode, int3 padding after the FDE, fetch / class-search /
  take / value / predicate / give-back / release / completion call
  rel32s, sequence-stamp store, node-embed store, splice store,
  loop-counter increment, count comparison, flag-byte set,
  completion-byte set, return-value load),
- FDE bounds (0x63b81b0..0x63b8517, 871 bytes) and that every
  direct branch target in the FDE lies inside the FDE,
- census: 5 direct E8 (2 in the single-shot caller FDE, 3 in the
  driver FDE), 0 E9, 0 LEA, 0 GOT (60,723 .rela.dyn entries),
- disjointness from neighbouring claimed ranges,
- MANIFEST.sha256 coverage (17 entries, MANIFEST itself excluded).
"""

import hashlib
import os
import re
import struct
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(REPO, "research", "work-items", "RE-001-node115-lu-loopcaller")
NODE = os.path.join(REPO, "artifacts", "node", "115", "hl-node")

TARGET_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET_SIZE = 105896032

FDE_START = 0x63B81B0
FDE_END = 0x63B8517
RET_SITES = (0x63B84D4,)
CALLS = {
    0x63B825A: 0x63B5840,  # item fetch (cited, not claimed)
    0x63B827F: 0x63D9340,  # class-search helper (#230)
    0x63B8296: 0x63D8E70,  # take helper (cited, not claimed)
    0x63B82BE: 0x63BA680,  # value compute (cited, not claimed)
    0x63B8330: 0x63AE2B0,  # wake predicate (cited, not claimed)
    0x63B83AC: 0x63D9070,  # give-back helper (cited, not claimed)
    0x63B8467: 0x63B59E0,  # release helper (cited, not claimed)
    0x63B8480: 0x63B7900,  # completion helper (cited, not claimed)
    0x63B8488: 0x63D94A0,  # completion helper (cited, not claimed)
    0x63B84F3: 0x63BF680,  # contention helper (cited, not claimed)
    0x63B850B: 0x63B76B0,  # fallback helper (cited, not claimed)
}
# Neighbouring claimed ranges that must not overlap this FDE.
NEIGHBOURS = {
    "single-shot caller (#232)": (0x63B8820, 0x63B8D85),
    "driver FDE (cited)": (0x63B8D90, 0x63B8FD1),
    "tiny wrapper (adjacent)": (0x63B8160, 0x63B81AB),
    "next function": (0x63B8520, 0x63B8530),
    "class-search (#230)": (0x63D9340, 0x63D945B),
    "class-merge (#231)": (0x63B9690, 0x63B99C8),
    "finder (#226)": (0x63B0980, 0x63B15E9),
    "slot-head (#225)": (0x63ABD00, 0x63AC0CC),
    "release (#224)": (0x63B0780, 0x63B0980),
    "size rep (#227)": (0x63E8C80, 0x63E8D87),
    "table-fill (#228)": (0x63E8D90, 0x63E9152),
    "descbuild thunk (#229)": (0x63DA080, 0x63DA089),
    "descbuild body (#229)": (0x63D9BA0, 0x63D9ED3),
}

EXHIBITS = {
    "lc_entry": (0x63B81B0, 0x63B8212, 98, 24),
    "lc_loop": (0x63B8250, 0x63B8290, 64, 15),
    "lc_take": (0x63B8290, 0x63B82C3, 51, 12),
    "lc_build": (0x63B82C3, 0x63B8335, 114, 24),
    "lc_splice": (0x63B83B1, 0x63B840A, 89, 22),
    "lc_ret": (0x63B849A, 0x63B84D5, 59, 17),
}

EXPECTED_E8 = ["0x63b8baf", "0x63b8c59", "0x63b8e1a", "0x63b8e95", "0x63b8f4d"]

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
    if FDE_END - FDE_START != 871:
        fail("FDE size mismatch")
    off = lambda va: va - 0x1000
    # Entry is push %r15; push %r14 -- deliberately NOT endbr64.
    if data[off(FDE_START):off(FDE_START) + 4] != bytes.fromhex("41574156"):
        fail("entry is not the push sequence")
    for site in RET_SITES:
        if data[off(site)] != 0xC3:
            fail("ret site %s is not 0xc3" % hex(site))
    if data[off(FDE_END):off(FDE_END) + 9] != bytes.fromhex("cc" * 9):
        fail("bytes after FDE are not int3 padding")
    if data[off(0x63B8520):off(0x63B8520) + 4] != bytes.fromhex("f30f1efa"):
        fail("next function does not start with endbr64")
    for site, target in CALLS.items():
        if data[off(site)] != 0xE8:
            fail("call site %s is not E8" % hex(site))
        rel = struct.unpack_from("<i", data, off(site) + 1)[0]
        if site + 5 + rel != target:
            fail("call site %s does not target %s" % (hex(site), hex(target)))
    # Sequence-stamp store: mov %rsi,0x8(%r14) at 0x63b82b4.
    if data[off(0x63B82B4):off(0x63B82B4) + 4] != bytes.fromhex("49897608"):
        fail("stamp store bytes mismatch")
    # Node-embed store: mov %r14,0x18(%r15) at 0x63b8320.
    if data[off(0x63B8320):off(0x63B8320) + 4] != bytes.fromhex("4d897718"):
        fail("embed store bytes mismatch")
    # Splice store: mov %r15,0x30(%rax) at 0x63b83d5.
    if data[off(0x63B83D5):off(0x63B83D5) + 4] != bytes.fromhex("4c897830"):
        fail("splice store bytes mismatch")
    # Loop-counter increment: add $0x1,%rbp at 0x63b83cd.
    if data[off(0x63B83CD):off(0x63B83CD) + 4] != bytes.fromhex("4883c501"):
        fail("counter increment bytes mismatch")
    # Count comparison: cmp %rbp,0x30(%rsp) at 0x63b83f8.
    if data[off(0x63B83F8):off(0x63B83F8) + 4] != bytes.fromhex("48396c24"):
        fail("count comparison bytes mismatch")
    # Flag-byte set: movb $0x1,0x0(%r13) at 0x63b8471.
    if data[off(0x63B8471):off(0x63B8471) + 5] != bytes.fromhex("41c6450001"):
        fail("flag-byte set bytes mismatch")
    # Completion-byte set: mov %al,(%r9) at 0x63b849f.
    if data[off(0x63B849F):off(0x63B849F) + 3] != bytes.fromhex("418801"):
        fail("completion-byte set bytes mismatch")
    # Return-value load: mov %rbp,%rax at 0x63b84c7.
    if data[off(0x63B84C7):off(0x63B84C7) + 3] != bytes.fromhex("4889e8"):
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
    if [hex(x) for x in e8] != EXPECTED_E8:
        fail("E8 census mismatch: %s" % [hex(x) for x in e8])
    if e9:
        fail("unexpected E9 sites: %s" % [hex(x) for x in e9])
    if lea:
        fail("unexpected LEA sites: %s" % [hex(x) for x in lea])
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
    print("verifier: all checks passed (6 excerpts, 475 bytes, 114 strict, "
          "census 5 E8 / 0 E9 / 0 LEA, MANIFEST 17/17)")


if __name__ == "__main__":
    main()
