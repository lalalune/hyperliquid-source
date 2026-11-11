#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-wait-helper (packet #251).

Byte reads only; the node binary is never executed.
Checks: binary SHA/size, exhibit bytes, objdump regeneration, strict
mnemonic-line counts, FDE bounds, entry bytes, one ret site, all internal
call rel32s (including the GOT-indirect max-now helper), key bytes, jump
targets internal, full census (objdump mnemonic scan), neighbour
disjointness (paths deduplicated by real path, ranges as a set, own slug
excluded), MANIFEST coverage.
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
PACKET = os.path.join(ROOT, "research/work-items/RE-001-node115-lu-wait-helper")
NODE = os.path.join(ROOT, "artifacts/node/115/hl-node")
SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
SIZE = 105896032
LO, HI = 0x63bf680, 0x63bf7ee

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
    check(name + " inside FDE", LO <= lo and hi <= HI)
    total_bytes += len(raw)
    total_strict += len(regen)
check("exhibits total bytes", total_bytes == 329, total_bytes)
check("exhibits total strict", total_strict == 84, total_strict)
ordered = sorted(exhibits, key=lambda n: int(exhibits[n]["range"][0], 16))
for a, b in zip(ordered, ordered[1:]):
    ha = int(exhibits[a]["range"][1], 16)
    lb = int(exhibits[b]["range"][0], 16)
    check("exhibits pairwise disjoint %s/%s" % (a, b), ha <= lb)

check("FDE size", HI - LO == 366)
check("FDE entry endbr64", data[off(LO):off(LO) + 4] == bytes.fromhex("f30f1efa"))
check("padding before FDE is int3", data[off(0x63bf677):off(LO)] == b"\xcc" * 9)
check("padding after FDE is int3", data[off(HI):off(0x63bf7f0)] == b"\xcc" * 2)
check("next FDE starts at 0x63bf7f0 with endbr64",
      data[off(0x63bf7f0):off(0x63bf7f0) + 4] == bytes.fromhex("f30f1efa"))
check("one ret site", data[off(0x63bf71d)] == 0xC3)
check("mutex lea +0x40", data[off(0x63bf68e):off(0x63bf68e) + 4] == bytes.fromhex("488d6f40"))
check("spin-disable lea target 0x6511730",
      0x63bf6ac + struct.unpack("<i", data[off(0x63bf6a5) + 3:off(0x63bf6a5) + 7])[0] == 0x6511730)
check("spin-limit load target 0x64ffc98",
      0x63bf6c7 + struct.unpack("<i", data[off(0x63bf6c0) + 3:off(0x63bf6c0) + 7])[0] == 0x64ffc98)
check("ticket xadd bytes", data[off(0x63bf745):off(0x63bf745) + 5] == bytes.fromhex("f0410fc118"))
check("contended flag set bytes", data[off(0x63bf761):off(0x63bf761) + 6] == bytes.fromhex("41c644246801"))
check("GOT lea target 0x64df1e8",
      0x63bf775 + struct.unpack("<i", data[off(0x63bf76e) + 3:off(0x63bf76e) + 7])[0] == 0x64df1e8)
# The GOT slot is zero-filled in the file (RELATIVE reloc applied at
# load); verify the relocation entry itself instead of file bytes.
rela_txt = subprocess.run(["readelf", "-rW", NODE], capture_output=True, text=True).stdout
got_ok = any("64df1e8" in ln and "R_X86_64_RELATIVE" in ln and "63bfa70" in ln
             for ln in rela_txt.splitlines())
check("GOT slot reloc resolves to 0x63bfa70", got_ok)

calls = {
    0x63bf6ee: 0x63f17b0, 0x63bf730: 0x63bfcf0, 0x63bf73b: 0x63bfbf0,
    0x63bf750: 0x63f17b0, 0x63bf75c: 0x63f0b60, 0x63bf786: 0x63bfbf0,
    0x63bf796: 0x63bfc40, 0x63bf7a7: 0x63bfc20, 0x63bf7b2: 0x63bfc00,
    0x63bf7e2: 0x63bfbf0, 0x63bf7e9: 0x63f0d70,
}
for site, tgt in sorted(calls.items()):
    o = off(site)
    rel = struct.unpack("<i", data[o + 1:o + 5])[0]
    check("call %s -> %s" % (hex(site), hex(tgt)),
          data[o] == 0xE8 and site + 5 + rel == tgt)

# Jump targets internal (direct jumps only; the indirect call is not a jump).
full = objdump_lines(LO, HI)
bad_jumps = []
for line in full:
    m = re.match(r"([0-9a-f]+):\t[0-9a-f ]+\t(j\w+)\s+([0-9a-f]+)", line)
    if m:
        tgt = int(m.group(3), 16)
        if not (LO <= tgt < HI):
            bad_jumps.append((m.group(1), m.group(2), hex(tgt)))
check("jump targets internal", bad_jumps == [], bad_jumps)

# Full census via one objdump mnemonic scan of .text.
out = subprocess.run(["objdump", "-d", NODE], capture_output=True, text=True).stdout
e8, e9, lea = [], [], []
for line in out.splitlines():
    m = re.match(r"\s+([0-9a-f]+):\t[0-9a-f ]+\t(\S+)\s+(.*)", line)
    if not m:
        continue
    va = int(m.group(1), 16)
    mn, rest = m.group(2), m.group(3)
    if mn == "call":
        mm = re.match(r"([0-9a-f]+)\s", rest)
        if mm and int(mm.group(1), 16) == LO:
            e8.append(va)
    elif mn == "jmp":
        mm = re.match(r"([0-9a-f]+)\s", rest)
        if mm and int(mm.group(1), 16) == LO:
            e9.append(va)
    elif mn == "lea":
        mm = re.search(r"#\s*([0-9a-f]+)", rest)
        if mm and int(mm.group(1), 16) == LO:
            lea.append(va)
bad_rel = []
for va in e8:
    o = off(va)
    rel = struct.unpack("<i", data[o + 1:o + 5])[0]
    if data[o] != 0xE8 or va + 5 + rel != LO:
        bad_rel.append(hex(va))
check("census E8 rel32", bad_rel == [], bad_rel)
check("census E8 includes #250 sites", 0x63b92e3 in e8 and 0x63b92fb in e8)
check("census E9 empty", e9 == [], e9)
check("census LEA empty", lea == [], lea)
print("note: census E8 sites %d" % len(e8))
rela = subprocess.run(["readelf", "-rW", NODE], capture_output=True, text=True).stdout
in_dyn = False
dyn_count = 0
hits = 0
for line in rela.splitlines():
    m = re.match(r"Relocation section '(\S+)'", line)
    if m:
        in_dyn = (m.group(1) == ".rela.dyn")
        continue
    if in_dyn and re.match(r"\s*[0-9a-f]{8,}\s", line):
        dyn_count += 1
        if "63bf680" in line:
            hits += 1
check("rela.dyn entries", dyn_count == 60723, dyn_count)
check("rela.dyn hits 0", hits == 0, hits)

# Neighbour disjointness over the merged tree + prior worktrees.
def collect_ranges(path):
    try:
        r = json.load(open(path))
    except Exception:
        return []
    out = []

    def walk(o):
        if isinstance(o, dict):
            if "range" in o and isinstance(o["range"], list) and len(o["range"]) == 2:
                try:
                    out.append((int(o["range"][0], 16), int(o["range"][1], 16)))
                except Exception:
                    pass
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(r)
    if isinstance(r, dict) and isinstance(r.get("fde"), list) and len(r["fde"]) == 2:
        try:
            out.append((int(r["fde"][0], 16), int(r["fde"][1], 16)))
        except Exception:
            pass
    return out


paths = glob.glob(os.path.join(ROOT, "research/work-items/*/records.json"))
paths += glob.glob("/home/hatch/workspace/hl-wt-calls*/research/work-items/*/records.json")
ranges = set()
overlaps = []
for path in paths:
    if "lu-wait-helper" in path:
        continue
    rp = os.path.realpath(path)
    for (a, b) in collect_ranges(rp):
        ranges.add((a, b))
        if a < HI and LO < b:
            overlaps.append((path, hex(a), hex(b)))
        for ex in exhibits.values():
            elo = int(ex["range"][0], 16)
            ehi = int(ex["range"][1], 16)
            if a < ehi and elo < b:
                overlaps.append((path, hex(a), hex(b)))
print("note: disjointness unique ranges checked %d" % len(ranges))
check("no neighbour overlap", overlaps == [], overlaps[:3])

# MANIFEST coverage.
man = open(os.path.join(PACKET, "MANIFEST.sha256")).read().splitlines()
entries = []
for line in man:
    if not line.strip():
        continue
    h, p = line.split(None, 1)
    entries.append((h, p.strip()))
check("MANIFEST entries", len(entries) == 15, len(entries))
ok_hash = True
for h, p in entries:
    if p.startswith("../../../"):
        fp = os.path.join(ROOT, p[9:])
    else:
        fp = os.path.join(PACKET, p)
    if hashlib.sha256(open(fp, "rb").read()).hexdigest() != h:
        ok_hash = False
check("MANIFEST hashes match", ok_hash)

if failures:
    print("verifier: FAILED (%d)" % len(failures))
    sys.exit(1)
print("verifier: all checks passed (5 excerpts, 329 bytes, 84 strict, census %d E8 sites, MANIFEST 15 entries)" % len(e8))
