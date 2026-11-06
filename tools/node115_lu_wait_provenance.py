#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-wait-provenance (packet #253).

Byte reads only; the node binary is never executed.
Checks: binary SHA/size, exhibit bytes, objdump regeneration, strict
mnemonic-line counts, FDE bounds/entry/padding (via the repo's own
.eh_frame parser), all 18 helper-site rel32s, exhibit call/trylock
rel32s, surveyed (non-exhibited) cross-check bytes, record-offset
arithmetic for all 18 sites (mutex = record + 0x40, flag = record +
0x68, caller triple = record + 0x28/+0x30/+0x38), neighbour
disjointness (paths deduplicated by real path, ranges as a set, own
slug excluded, census/cited-only metadata ranges excluded as
counted-not-claimed), MANIFEST coverage.
"""
import bisect
import glob
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(ROOT, "research/work-items/RE-001-node115-lu-wait-provenance")
NODE = os.path.join(ROOT, "artifacts/node/115/hl-node")
SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
SIZE = 105896032
HELPER = 0x63BF680
TRYLOCK = 0x63F17B0
UNLOCK = 0x63F0B70
FDE_LO, FDE_HI = 0x63A5BF0, 0x63A6470

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
    check(name + " inside FDE", FDE_LO <= lo and hi <= FDE_HI)
    total_bytes += len(raw)
    total_strict += len(regen)
check("exhibits total bytes", total_bytes == 113, total_bytes)
check("exhibits total strict", total_strict == 26, total_strict)
ordered = sorted(exhibits, key=lambda n: int(exhibits[n]["range"][0], 16))
for a, b in zip(ordered, ordered[1:]):
    ha = int(exhibits[a]["range"][1], 16)
    lb = int(exhibits[b]["range"][0], 16)
    check("exhibits pairwise disjoint %s/%s" % (a, b), ha <= lb)

# FDE bounds/entry/padding via the repo's own .eh_frame parser.
sys.path.insert(0, os.path.join(ROOT, "tools"))
from fde_extents import eh_frame_records
from elf_index import sections
_, fdes = eh_frame_records(data, sections(data))
fdes = sorted(fdes, key=lambda f: f["start"])
starts = [f["start"] for f in fdes]
i = bisect.bisect_right(starts, FDE_LO) - 1
f = fdes[i]
check("FDE bounds", (f["start"], f["end"]) == (FDE_LO, FDE_HI), (hex(f["start"]), hex(f["end"])))
check("FDE size", FDE_HI - FDE_LO == 2176)
check("FDE entry endbr64", data[off(FDE_LO):off(FDE_LO) + 4] == bytes.fromhex("f30f1efa"))
prev, nxt = fdes[i - 1], fdes[i + 1]
check("padding before FDE is int3", prev["end"] == 0x63A5BEF
      and data[off(prev["end"]):off(FDE_LO)] == bytes.fromhex("cc"))
check("no padding after FDE", nxt["start"] == FDE_HI)
check("ret site", data[off(0x63A615B)] == 0xC3)


def rel32(site, tgt):
    o = off(site)
    rel = struct.unpack("<i", data[o + 1:o + 5])[0]
    return data[o] == 0xE8 and site + 5 + rel == tgt


SITES = [0x63A610A, 0x63A615F, 0x63A6178, 0x63A6191, 0x63A61A6, 0x63A61C0,
         0x63A61DA, 0x63A61F4, 0x63A620D, 0x63A6227, 0x63A6240, 0x63A63F8,
         0x63A640B, 0x63A641D, 0x63A642C, 0x63A643F, 0x63A6450, 0x63A6461]
for site in SITES:
    check("rel32 helper site " + hex(site), rel32(site, HELPER))
for site, tgt, label in [(0x63A610A, HELPER, "pv_loop_wait call"),
                         (0x63A6191, HELPER, "pv_ptr_wait call"),
                         (0x63A6461, HELPER, "pv_glob_wait call"),
                         (0x63A60FE, TRYLOCK, "pv_loop trylock"),
                         (0x63A6017, TRYLOCK, "pv_ptr trylock"),
                         (0x63A62A1, TRYLOCK, "pv_glob trylock")]:
    check("rel32 " + label, rel32(site, tgt))

# Surveyed (non-exhibited) cross-checks: byte patterns, not claimed ranges.
check("embedded 0x2928 wait mov bytes",
      data[off(0x63A61BD):off(0x63A61BD) + 3] == bytes.fromhex("4c89ff"))
check("embedded 0x2928 wait flag-set bytes",
      data[off(0x63A61CA):off(0x63A61CA) + 8] == bytes.fromhex("41c6819029000001"))
check("object table lea bytes",
      data[off(0x63A5CC3):off(0x63A5CC3) + 7] == bytes.fromhex("488d0df6391600"))
check("group descriptor lea bytes",
      data[off(0x63A607C):off(0x63A607C) + 4] == bytes.fromhex("4c8d7214"))
check("group stride add bytes",
      data[off(0x63A6126):off(0x63A6126) + 4] == bytes.fromhex("4983c628"))
check("dword-array stride add bytes",
      data[off(0x63A6120):off(0x63A6120) + 6] == bytes.fromhex("488344240804"))
check("loop stride add bytes",
      data[off(0x63A60C5):off(0x63A60C5) + 7] == bytes.fromhex("4881c5e0000000"))
check("tag save bytes", data[off(0x63A5BFA):off(0x63A5BFA) + 3] == bytes.fromhex("4989fd"))

# Record-offset arithmetic for all 18 sites: mutex = record + 0x40,
# flag = record + 0x68, triple = record + 0x28/+0x30/+0x38.
def hx(v):
    return int(v, 16) if isinstance(v, str) else v


for s in records["sites"]:
    rec, mut, fl = s["record"], s["mutex"], s["flag"]
    tri = s["triple"]
    if rec.startswith("r15") or rec.startswith("ptr") or rec.startswith("record"):
        # Symbolic records: check the offset relations textually.
        if "loop" in s["provenance"]:
            ok = (mut == "record+0x40" and fl == "record+0x68"
                  and tri == "r15+0x28/+0x30/+0x38")
        else:
            ok = (mut == "ptr+0x60" and fl == "ptr+0x88"
                  and tri == "ptr+0x48/+0x50/+0x58")
    elif rec.startswith("object"):
        base = hx(rec[6:])
        t = tri.split("/")
        ok = (hx(mut[6:]) == base + 0x40 and hx(fl[6:]) == base + 0x68
              and hx(t[0][6:]) == base + 0x28 and hx(t[1]) == base + 0x30
              and hx(t[2]) == base + 0x38)
    else:
        base = hx(rec)
        t = tri.split("/")
        ok = (hx(mut) == base + 0x40 and hx(fl) == base + 0x68
              and hx(t[0]) == base + 0x28 and hx(t[1]) == base + 0x30
              and hx(t[2]) == base + 0x38)
    check("record arithmetic site " + s["site"], ok)

# Neighbour disjointness: merged tree + sibling scout worktrees, real paths deduped.
# Census and cited-only metadata subtrees are NOT claims and are skipped:
# packet #252's census records this very FDE (0x63a5bf0..0x63a6470) as its
# "largest_caller_fde" while stating no byte of it is claimed; counting
# that metadata range as claimed would falsely block the follow-up #252
# itself invited. Cited FDEs are claimed by their owning packets, whose
# own records files are scanned independently.
META_KEYS = ("census", "cited_only_not_claimed", "largest_caller_fde", "arg_shape_census")


def ranges_from(obj, out, meta=False):
    if isinstance(obj, dict):
        if not meta:
            for key in ("range", "fde"):
                v = obj.get(key)
                if isinstance(v, list) and len(v) == 2:
                    try:
                        out.append((int(v[0], 16), int(v[1], 16)))
                    except (ValueError, TypeError):
                        pass
        for k, v in obj.items():
            ranges_from(v, out, meta or k in META_KEYS)
    elif isinstance(obj, list):
        for v in obj:
            ranges_from(v, out, meta)


paths = set()
for pat in (os.path.join(ROOT, "research/work-items/*/records.json"),
            os.path.join(os.path.dirname(ROOT), "hl-wt-calls*-115/research/work-items/*/records.json")):
    for p in glob.glob(pat):
        paths.add(os.path.realpath(p))
claimed = set()
for p in paths:
    if "RE-001-node115-lu-wait-provenance" in p:
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
