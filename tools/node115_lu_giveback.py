#!/usr/bin/env python3
"""Static verifier for packet #243: node #115 lu give-back (FDE 0x63d8e70).

Byte reads only; the node binary is never executed. Checks SHA/size,
exhibit bytes, strict instruction counts, objdump regeneration, FDE
bounds, the single ret, the two internal calls (rel32), key stores and
dispatch bytes, the 0x200 arm's .rodata constant, jump-target closure
(except the one stated external tail jump), the full census for the
FDE entry, neighbour disjointness, and MANIFEST coverage.
"""

import hashlib
import os
import re
import struct
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
PACKET = os.path.join(ROOT, "research", "work-items",
                      "RE-001-node115-lu-giveback")

SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
SIZE = 105896032
FDE_START, FDE_END = 0x63d8e70, 0x63d906b

EXHIBITS = {
    "gb_entry": (0x63d8e70, 0x63d8e9d, 45, 12),
    "gb_size": (0x63d8e9d, 0x63d8f05, 104, 25),
    "gb_slot": (0x63d8f05, 0x63d8f55, 80, 18),
    "gb_tail": (0x63d8f55, 0x63d8f99, 68, 16),
    "gb_call": (0x63d8ffa, 0x63d901c, 34, 11),
    "gb_zero": (0x63d9020, 0x63d9058, 56, 11),
}

# Neighbour FDE ranges this packet cites but does not claim (all disjoint).
NEIGHBOURS = {
    "driver #234": (0x63b8d90, 0x63b8fd1),
    "gate #235": (0x63b85f0, 0x63b8820),
    "consume #236": (0x63ba600, 0x63ba672),
    "register #237": (0x63d94b0, 0x63d96db),
    "handoff #238": (0x63d8790, 0x63d88c4),
    "insert #239": (0x63b99d0, 0x63b9d0c),
    "probe #240": (0x63b9680, 0x63b968c),
    "remove #241": (0x63b9d10, 0x63ba5fd),
    "remove-entry #242": (0x63d8630, 0x63d8790),
    "tail target": (0x63d84e0, 0x63d8622),
    "caller FDE A": (0x63b7900, 0x63b7ee6),
    "caller FDE B": (0x63b7ef0, 0x63b8157),
    "caller FDE C": (0x63b8820, 0x63b8d85),
}

FAILURES = []


def check(name, cond, detail=""):
    print(("ok: " if cond else "FAIL: ") + name + ("" if cond else " " + detail))
    if not cond:
        FAILURES.append(name)


def off(va):
    return va - 0x1000


def objdump_lines(start, stop):
    out = subprocess.run(
        ["objdump", "-d", "--start-address=%s" % hex(start),
         "--stop-address=%s" % hex(stop), BIN],
        capture_output=True, text=True, check=True).stdout
    lines = []
    for ln in out.splitlines():
        m = re.match(r"^\s*([0-9a-f]+):\t([0-9a-f ]+)\t(\S.*)$", ln)
        if m:
            lines.append((int(m.group(1), 16), m.group(2).strip(),
                          m.group(3).strip()))
    return lines


def rel32(site, opcode):
    o = off(site)
    assert data[o] == opcode, (hex(site), hex(data[o]))
    return site + 5 + struct.unpack("<i", data[o + 1:o + 5])[0]


with open(BIN, "rb") as fh:
    data = fh.read()

check("binary sha", hashlib.sha256(data).hexdigest() == SHA)
check("binary size %d" % SIZE, len(data) == SIZE)

total_bytes = 0
total_strict = 0
for name, (s, e, nbytes, nstrict) in sorted(EXHIBITS.items()):
    with open(os.path.join(PACKET, name + ".hex")) as fh:
        raw = bytes.fromhex("".join(fh.read().split()))
    check("%s length" % name, len(raw) == nbytes, "%d != %d" % (len(raw), nbytes))
    check("%s bytes" % name, data[off(s):off(e)] == raw)
    with open(os.path.join(PACKET, name + ".objdump.txt")) as fh:
        stored = []
        for ln in fh:
            m = re.match(r"^\s*([0-9a-f]+):\t([0-9a-f ]+)\t(\S.*)$", ln)
            if m:
                stored.append((int(m.group(1), 16), m.group(2).split(),
                               m.group(3).strip()))
    regen = [(a, b.split(), m) for a, b, m in objdump_lines(s, e)]
    check("%s objdump regeneration" % name, stored == regen)
    check("%s strict %d" % (name, nstrict), len(regen) == nstrict,
          "%d lines" % len(regen))
    total_bytes += nbytes
    total_strict += nstrict
check("exhibits total 387 bytes", total_bytes == 387, str(total_bytes))
check("exhibits total 93 strict", total_strict == 93, str(total_strict))

# FDE bounds and entry.
check("FDE entry endbr64", data[off(FDE_START):off(FDE_START) + 4] == bytes.fromhex("f30f1efa"))
check("FDE size 507", FDE_END - FDE_START == 507)
check("int3 padding before FDE",
      data[off(0x63d8e67):off(0x63d8e70)] == b"\xcc" * 9)
check("int3 padding after FDE",
      data[off(0x63d906b):off(0x63d9070)] == b"\xcc\xcc\xcc\xcc\xcc")

# Ret / jump / call inventory from objdump mnemonics over the whole FDE.
lines = objdump_lines(FDE_START, FDE_END)
rets = [a for a, _, m in lines if m == "ret"]
check("single ret at 0x63d8f98", rets == [0x63d8f98], str([hex(r) for r in rets]))
calls = [(a, m) for a, _, m in lines if m.startswith("call")]
check("two internal calls",
      [a for a, _ in calls] == [0x63d8ea5, 0x63d9000],
      str([(hex(a), m) for a, m in calls]))
check("call 0x63d8ea5 rel32 -> size mapper",
      rel32(0x63d8ea5, 0xE8) == 0x63e8bf0)
check("call 0x63d9000 rel32 -> remove entry",
      rel32(0x63d9000, 0xE8) == 0x63d8630)
jmps = [(a, m) for a, _, m in lines if m.split()[0] in ("jmp", "je", "jne", "jb")]
bad = []
for a, m in jmps:
    tgt = int(m.split()[1], 16) if m.split()[1].startswith("63") else None
    if tgt is None:
        bad.append((hex(a), m))
    elif not (FDE_START <= tgt < FDE_END) and tgt != 0x63d84e0:
        bad.append((hex(a), m))
check("jump targets internal except stated tail jmp", not bad, str(bad))
check("tail jmp 0x63d9017 -> 0x63d84e0",
      data[off(0x63d9017)] == 0xE9 and
      0x63d901c + struct.unpack("<i", data[off(0x63d9017) + 1:off(0x63d9017) + 5])[0] == 0x63d84e0)

# Key dispatch / store bytes.
check("flag [block+0x23] := 1", data[off(0x63d8e84):off(0x63d8e84) + 4] == bytes.fromhex("c6462301"))
# je is 0f 84 rel32 (6 bytes); verify target directly.
o = off(0x63d8e8b)
check("zero dispatch target",
      data[o] == 0x0F and data[o + 1] == 0x84 and
      0x63d8e91 + struct.unpack("<i", data[o + 2:o + 6])[0] == 0x63d9020)
o = off(0x63d8e97)
check("0x200 dispatch target",
      data[o] == 0x0F and data[o + 1] == 0x84 and
      0x63d8e9d + struct.unpack("<i", data[o + 2:o + 6])[0] == 0x63d8fa0)
check("overflow stub r10d = 0x2970",
      data[off(0x63d9060):off(0x63d9060) + 6] == bytes.fromhex("41ba70290000"))
o = off(0x63d9066)
check("overflow stub jmp 0x63d8f05",
      data[o] == 0xE9 and
      0x63d906b + struct.unpack("<i", data[o + 1:o + 5])[0] == 0x63d8f05)
# 0x200 arm: movdqa rip-relative target 0x451800, constant (-1, -512).
o = off(0x63d8fa4)
disp = struct.unpack("<i", data[o + 4:o + 8])[0]
check("0x200 movdqa target 0x451800", 0x63d8fac + disp == 0x451800, hex(0x63d8fac + disp))
lo, hi = struct.unpack("<qq", data[0x451800:0x451800 + 16])
check("0x200 constant (-1, -512)", (lo, hi) == (-1, -512), str((lo, hi)))
check("0x200 slot base lea 0x1020",
      data[off(0x63d8fb2):off(0x63d8fb2) + 8].hex() == "488db43d20100000")
check("0x200 je to tail test 0x63d8f8c",
      data[off(0x63d8ff8)] == 0x74 and
      0x63d8ffa + struct.unpack("<b", data[off(0x63d8ff8) + 1:off(0x63d8ff8) + 2])[0] == 0x63d8f8c)
# Zero arm: lea 0x1050, jmp to tail test.
check("zero slot base lea 0x1050",
      data[off(0x63d9031):off(0x63d9031) + 8].hex() == "4c8d840f50100000")
check("zero jmp to tail test 0x63d8f7f",
      data[off(0x63d9053)] == 0xE9 and
      0x63d9058 + struct.unpack("<i", data[off(0x63d9053) + 1:off(0x63d9053) + 5])[0] == 0x63d8f7f)
# Tail tests.
check("tail cmpb [block+0x12]",
      data[off(0x63d8f7f):off(0x63d8f7f) + 4] == bytes.fromhex("807b1200"))
check("tail store [first-arg+0x418]",
      data[off(0x63d8f83):off(0x63d8f83) + 7] == bytes.fromhex("48898518040000"))
check("tail cmpb [block+0x13]",
      data[off(0x63d8f8c):off(0x63d8f8c) + 4] == bytes.fromhex("807b1300"))
# nopl gap starts.
for g in (0x63d8f99, 0x63d901c, 0x63d9058):
    check("nopl gap at %s" % hex(g), data[off(g):off(g) + 2] == bytes.fromhex("0f1f"))

# Exhibits inside FDE, pairwise disjoint, neighbour-disjoint.
for name, (s, e, _, _) in EXHIBITS.items():
    check("%s inside FDE" % name, FDE_START <= s and e <= FDE_END)
items = sorted(EXHIBITS.items(), key=lambda kv: kv[1][0])
overlap = []
for (n1, (s1, e1, _, _)), (n2, (s2, e2, _, _)) in zip(items, items[1:]):
    if s2 < e1:
        overlap.append((n1, n2))
check("exhibits pairwise disjoint", not overlap, str(overlap))
noverlap = []
for name, (s, e, _, _) in EXHIBITS.items():
    for nb, (ns, ne) in NEIGHBOURS.items():
        if s < ne and ns < e:
            noverlap.append((name, nb))
check("no neighbour overlap", not noverlap, str(noverlap))

# Census for the FDE entry address.
TEXT_LO, TEXT_HI = 0x1419300, 0x1419300 + 0x4FD88A0
seg = data[off(TEXT_LO):off(TEXT_HI)]
TGT = FDE_START
raw_e8, raw_e9, raw_lea = [], [], []
for i in range(len(seg) - 7):
    b = seg[i]
    va = TEXT_LO + i
    if b == 0xE8 and va + 5 + struct.unpack("<i", seg[i + 1:i + 5])[0] == TGT:
        raw_e8.append(va)
    elif b == 0xE9 and va + 5 + struct.unpack("<i", seg[i + 1:i + 5])[0] == TGT:
        raw_e9.append(va)
    elif b in (0x48, 0x4C) and seg[i + 1] == 0x8D and (seg[i + 2] & 0xC7) == 0x05:
        if va + 7 + struct.unpack("<i", seg[i + 3:i + 7])[0] == TGT:
            raw_lea.append(va)
confirmed = []
for va in raw_e8:
    ls = objdump_lines(va, va + 5)
    if ls and ls[0][2].startswith("call") and ls[0][0] == va:
        confirmed.append(va)
check("census E8 %s" % [hex(v) for v in confirmed],
      confirmed == [0x63b7af7, 0x63b7c30, 0x63b7cef, 0x63b7d8b,
                    0x63b7e0a, 0x63b808e, 0x63b8296, 0x63b892f],
      str([hex(v) for v in confirmed]))
check("census E9 empty", raw_e9 == [], str(raw_e9))
check("census LEA empty", raw_lea == [], str(raw_lea))
relocs = subprocess.run(["readelf", "--relocs", BIN],
                        capture_output=True, text=True, check=True).stdout
in_dyn = False
dyn_total = 0
dyn_hits = 0
for ln in relocs.splitlines():
    if ln.startswith("Relocation section"):
        in_dyn = ".rela.dyn" in ln
        continue
    if in_dyn and re.match(r"^[0-9a-f]{6,}\s", ln):
        dyn_total += 1
        if "63d8e70" in ln:
            dyn_hits += 1
check("rela.dyn 60723 entries", dyn_total == 60723, str(dyn_total))
check("census GOT empty", dyn_hits == 0, str(dyn_hits))

# MANIFEST coverage (17 entries; MANIFEST excludes itself).
with open(os.path.join(PACKET, "MANIFEST.sha256")) as fh:
    mlines = [ln.strip() for ln in fh if ln.strip()]
check("MANIFEST 17 entries", len(mlines) == 17, str(len(mlines)))
ok_hash = True
for ln in mlines:
    h, p = ln.split(None, 1)
    p = p.lstrip("*")
    path = os.path.normpath(os.path.join(PACKET, p))
    with open(path, "rb") as fh:
        if hashlib.sha256(fh.read()).hexdigest() != h:
            ok_hash = False
check("MANIFEST hashes match", ok_hash)

if FAILURES:
    print("verifier: FAILED (%d)" % len(FAILURES))
    sys.exit(1)
print("verifier: all checks passed (6 exhibits, 387 bytes, 93 strict, "
      "census 8 E8 sites, MANIFEST 17 entries)")
