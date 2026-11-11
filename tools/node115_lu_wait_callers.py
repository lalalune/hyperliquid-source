#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-wait-callers (packet #252).

Byte reads only; the node binary is never executed.
Checks: binary SHA/size, exhibit bytes, objdump regeneration, strict
mnemonic-line counts, cited-FDE entry bytes, exhibit call rel32s,
surveyed (non-exhibited) cross-check bytes, record-offset arithmetic,
full raw census (E8 sites, E9 sites, rip-relative LEA sites),
caller-FDE grouping via the repo's own .eh_frame parser, neighbour
disjointness (paths deduplicated by real path, ranges as a set, own
slug excluded), MANIFEST coverage.
"""
import glob
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(ROOT, "research/work-items/RE-001-node115-lu-wait-callers")
NODE = os.path.join(ROOT, "artifacts/node/115/hl-node")
SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
SIZE = 105896032
HELPER = 0x63BF680
TRYLOCK = 0x63F17B0
UNLOCK = 0x63F0B70

failures = []


def check(name, ok, extra=""):
    print(("ok: " if ok else "FAIL: ") + name + ((" " + str(extra)) if extra else ""))
    if not ok:
        failures.append(name)


def off(va):
    return va - 0x1000


data = open(NODE, "rb").read()
check("binary sha", hashlib.sha256(data).hexdigest() == SHA)
check("binary size", len(data) == SIZE)

records = json.load(open(os.path.join(PACKET, "records.json")))
exhibits = records["exhibits"]


def objdump_lines(lo, hi):
    out = subprocess.run(
        ["objdump", "-d", "--start-address=" + hex(lo), "--stop-address=" + hex(hi), NODE],
        capture_output=True, text=True).stdout
    lines = []
    for line in out.splitlines():
        m = re.match(r"\s+([0-9a-f]+):\t([0-9a-f ]+)\t(\S.*)", line)
        if m and lo <= int(m.group(1), 16) < hi:
            lines.append(line.strip())
    return lines


FDE_OF = {
    "g_wait": (0x63CF9D0, 0x63CFF1B),
    "r38_try": (0x6364280, 0x6364342),
    "r38_wait": (0x6364280, 0x6364342),
    "r18_try": (0x63B5A40, 0x63B5B3D),
    "r18_wait": (0x63B5A40, 0x63B5B3D),
    "r28_wait": (0x63EC7A0, 0x63EC900),
}
total_bytes = 0
total_strict = 0
for name, ex in sorted(exhibits.items()):
    lo = int(ex["range"][0], 16)
    hi = int(ex["range"][1], 16)
    raw = bytes.fromhex("".join(open(os.path.join(PACKET, name + ".hex")).read().split()))
    check(name + " length", len(raw) == ex["bytes"])
    check(name + " bytes", data[off(lo):off(hi)] == raw)
    regen = objdump_lines(lo, hi)
    saved = [l for l in open(os.path.join(PACKET, name + ".objdump.txt")).read().splitlines() if l.strip()]
    check(name + " objdump regeneration", regen == saved, (len(regen), len(saved)))
    check(name + " strict", len(regen) == ex["strict"], (len(regen), ex["strict"]))
    flo, fhi = FDE_OF[name]
    check(name + " inside FDE", flo <= lo and hi <= fhi)
    total_bytes += len(raw)
    total_strict += len(regen)
check("exhibits total bytes", total_bytes == 122, total_bytes)
check("exhibits total strict", total_strict == 23, total_strict)
ordered = sorted(exhibits, key=lambda n: int(exhibits[n]["range"][0], 16))
for a, b in zip(ordered, ordered[1:]):
    ha = int(exhibits[a]["range"][1], 16)
    lb = int(exhibits[b]["range"][0], 16)
    check("exhibits pairwise disjoint %s/%s" % (a, b), ha <= lb)

# Cited-FDE entry bytes and sizes.
check("g FDE size", 0x63CFF1B - 0x63CF9D0 == 1355)
check("g FDE entry endbr64", data[off(0x63CF9D0):off(0x63CF9D0) + 4] == bytes.fromhex("f30f1efa"))
check("r38 FDE size", 0x6364342 - 0x6364280 == 194)
check("r38 FDE entry endbr64", data[off(0x6364280):off(0x6364280) + 4] == bytes.fromhex("f30f1efa"))
check("r18 FDE size", 0x63B5B3D - 0x63B5A40 == 253)
check("r18 FDE entry endbr64", data[off(0x63B5A40):off(0x63B5A40) + 4] == bytes.fromhex("f30f1efa"))
check("r28 FDE size", 0x63EC900 - 0x63EC7A0 == 352)
check("r28 FDE entry push r14 (no endbr64)",
      data[off(0x63EC7A0):off(0x63EC7A0) + 2] == bytes.fromhex("4156"))


def rel32(site, tgt):
    o = off(site)
    rel = struct.unpack("<i", data[o + 1:o + 5])[0]
    return data[o] == 0xE8 and site + 5 + rel == tgt


for site, tgt, label in [
    (0x63CFEF2, HELPER, "g_wait call 1"), (0x63CFF0A, HELPER, "g_wait call 2"),
    (0x6364334, HELPER, "r38_wait call"), (0x63B5B2C, HELPER, "r18_wait call"),
    (0x63EC897, HELPER, "r28_wait call"),
    (0x63642CA, TRYLOCK, "r38_try trylock"), (0x63B5A5C, TRYLOCK, "r18_try trylock"),
]:
    check("rel32 " + label, rel32(site, tgt))

# Surveyed (non-exhibited) cross-checks: byte patterns, not claimed ranges.
check("r28_try lea bytes", data[off(0x63EC7B2):off(0x63EC7B2) + 7] == bytes.fromhex("4c8dade8280000"))
check("rel32 r28_try trylock", rel32(0x63EC7BC, TRYLOCK))
check("g_unlock flag-clear bytes", data[off(0x63CFEB4):off(0x63CFEB4) + 5] == bytes.fromhex("41c6416800"))
check("g_unlock mutex lea bytes", data[off(0x63CFEB9):off(0x63CFEB9) + 4] == bytes.fromhex("498d7940"))
check("rel32 g_unlock unlock", rel32(0x63CFEBD, UNLOCK))

# Record-offset arithmetic: mutex = record + 0x40, flag = record + 0x68.
check("g mutex/flag arithmetic", 0x67145A0 + 0x40 == 0x67145E0 and 0x67145A0 + 0x68 == 0x6714608
      and 0x6714520 + 0x40 == 0x6714560 and 0x6714520 + 0x68 == 0x6714588)
check("r38 mutex/flag arithmetic", 0x38 + 0x40 == 0x78 and 0x38 + 0x68 == 0xA0)
check("r18 mutex/flag arithmetic", 0x18 + 0x40 == 0x58 and 0x18 + 0x68 == 0x80)
check("r28 mutex/flag arithmetic", 0x28A8 + 0x40 == 0x28E8 and 0x28A8 + 0x68 == 0x2910)

# Full raw census over .text (file offsets 0x1418300..0x1418300+0x4fd88a0).
lo_off, hi_off = 0x1418300, 0x1418300 + 0x4FD88A0
e8, e9, lea = [], [], []
for o in range(lo_off, hi_off - 7):
    va = o + 0x1000
    if data[o] == 0xE8:
        rel = struct.unpack_from("<i", data, o + 1)[0]
        if va + 5 + rel == HELPER:
            e8.append(va)
    if data[o] == 0xE9:
        rel = struct.unpack_from("<i", data, o + 1)[0]
        if va + 5 + rel == HELPER:
            e9.append(va)
    if data[o] in (0x48, 0x4C, 0x49, 0x4D) and data[o + 1] == 0x8D and (data[o + 2] & 0xC7) == 0x05:
        disp = struct.unpack_from("<i", data, o + 3)[0]
        if va + 7 + disp == HELPER:
            lea.append(va)
check("census E8 sites", len(e8) == 474, len(e8))
check("census E9 sites", e9 == [], e9)
check("census rip-LEA sites", lea == [], lea)
check("census includes #250 caller-B sites", 0x63B92E3 in e8 and 0x63B92FB in e8)
check("census includes exhibit sites",
      all(s in e8 for s in (0x63CFEF2, 0x63CFF0A, 0x6364334, 0x63B5B2C, 0x63EC897)))

# Caller-FDE grouping via the repo's own .eh_frame parser.
sys.path.insert(0, os.path.join(ROOT, "tools"))
from fde_extents import eh_frame_records
from elf_index import sections
_, fdes = eh_frame_records(data, sections(data))
fdes = sorted(fdes, key=lambda f: f["start"])
starts = [f["start"] for f in fdes]
import bisect
groups = {}
for s in e8:
    i = bisect.bisect_right(starts, s) - 1
    f = fdes[i]
    assert f["start"] <= s < f["end"]
    groups.setdefault((f["start"], f["end"]), []).append(s)
import collections
dist = collections.Counter(len(v) for v in groups.values())
check("caller FDE count", len(groups) == 385, len(groups))
check("sites-per-FDE distribution",
      dist == collections.Counter({1: 348, 2: 19, 3: 9, 4: 4, 5: 1, 7: 2, 8: 1, 18: 1}),
      dict(dist))
check("grouped sites total", sum(len(v) for v in groups.values()) == 474)

# Neighbour disjointness: merged tree + sibling scout worktrees, real paths deduped.
def ranges_from(obj, out):
    if isinstance(obj, dict):
        for key in ("range", "fde"):
            v = obj.get(key)
            if isinstance(v, list) and len(v) == 2:
                try:
                    out.append((int(v[0], 16), int(v[1], 16)))
                except (ValueError, TypeError):
                    pass
        for v in obj.values():
            ranges_from(v, out)
    elif isinstance(obj, list):
        for v in obj:
            ranges_from(v, out)


paths = set()
for pat in (os.path.join(ROOT, "research/work-items/*/records.json"),
            os.path.join(os.path.dirname(ROOT), "hl-wt-calls*-115/research/work-items/*/records.json")):
    for p in glob.glob(pat):
        paths.add(os.path.realpath(p))
claimed = set()
for p in paths:
    if "RE-001-node115-lu-wait-callers" in p:
        continue
    try:
        d = json.load(open(p))
    except Exception:
        continue
    tmp = []
    ranges_from(d, tmp)
    claimed.update(tmp)
overlaps = []
for name, ex in exhibits.items():
    lo = int(ex["range"][0], 16)
    hi = int(ex["range"][1], 16)
    for a, b in claimed:
        if a < hi and lo < b:
            overlaps.append((name, hex(a), hex(b)))
check("disjoint from prior claimed ranges", overlaps == [], overlaps)
print("disjointness inputs: %d record files, %d unique claimed ranges" % (len(paths), len(claimed)))

# MANIFEST coverage: packet files + tools/tests with ../../../ prefix, excluding MANIFEST itself.
man = [l for l in open(os.path.join(PACKET, "MANIFEST.sha256")).read().splitlines() if l.strip()]
check("MANIFEST entries", len(man) == 17, len(man))
for line in man:
    h, p = line.split(None, 1)
    p = p.strip()
    fp = os.path.join(ROOT, p[9:]) if p.startswith("../../../") else os.path.join(PACKET, p)
    check("MANIFEST hash " + p, hashlib.sha256(open(fp, "rb").read()).hexdigest() == h)

if failures:
    print("FAILED: %d checks" % len(failures))
    sys.exit(1)
print("all checks passed")
