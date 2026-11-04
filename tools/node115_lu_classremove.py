#!/usr/bin/env python3
"""Static verifier for RE-001 node115 lu classremove packet.

Byte reads only; the node binary is never executed.
Checks: binary SHA/size, exhibit bytes, strict mnemonic counts,
objdump regeneration (header line stripped, as in packet #224),
FDE bounds, single ret, zero calls, all jump targets internal,
key stores, census (E8/E9/LEA/GOT), neighbour disjointness,
MANIFEST coverage.
"""
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(ROOT, "research", "work-items",
                      "RE-001-node115-lu-classremove")
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
SIZE = 105896032
FDE_LO, FDE_HI = 0x63b9D10, 0x63BA5FD
RET_SITE = 0x63B9F79
TARGET = 0x63B9D10

FAILURES = []


def check(name, cond, detail=""):
    print(("ok: " if cond else "FAIL: ") + name + ((" " + detail) if detail else ""))
    if not cond:
        FAILURES.append(name)


def va_off(va):
    return va - 0x1000


def objdump_lines(lo, hi):
    out = subprocess.run(
        ["objdump", "-d", "--start-address=" + hex(lo),
         "--stop-address=" + hex(hi), BIN],
        capture_output=True, text=True, check=True).stdout
    lines = [l for l in out.splitlines()
             if re.match(r"\s*[0-9a-f]+:\t", l)]
    strict = [l for l in lines
              if re.match(r"\s*[0-9a-f]+:\t[0-9a-f ]+\t\S", l)]
    return lines, strict


def main():
    with open(BIN, "rb") as f:
        data = f.read()
    check("binary sha", hashlib.sha256(data).hexdigest() == SHA)
    check("binary size %d" % SIZE, len(data) == SIZE)

    with open(os.path.join(PACKET, "records.json")) as f:
        records = json.load(f)
    exhibits = records["exhibits"]
    total_bytes = 0
    total_strict = 0
    for name, ex in exhibits.items():
        lo = int(ex["range"][0], 16)
        hi = int(ex["range"][1], 16)
        with open(os.path.join(PACKET, name + ".hex")) as f:
            raw = bytes.fromhex("".join(f.read().split()))
        check(name + " length", len(raw) == ex["bytes"] == hi - lo)
        check(name + " bytes", data[va_off(lo):va_off(hi)] == raw)
        with open(os.path.join(PACKET, name + ".objdump.txt")) as f:
            saved = f.read()
        lines, strict = objdump_lines(lo, hi)
        check(name + " objdump regeneration",
              saved == "\n".join(lines) + "\n")
        check(name + " strict %d" % ex["strict"], len(strict) == ex["strict"])
        total_bytes += len(raw)
        total_strict += len(strict)
    check("exhibits total 259 bytes", total_bytes == 259)
    check("exhibits total 71 strict", total_strict == 71)

    # Whole-FDE mnemonic scan.
    lines, _ = objdump_lines(FDE_LO, FDE_HI)
    check("FDE entry endbr64",
          data[va_off(FDE_LO):va_off(FDE_LO) + 4] == bytes.fromhex("f30f1efa"))
    check("FDE size 2285", FDE_HI - FDE_LO == 0x8ED)
    rets = [l for l in lines if re.search(r"\tret$", l)]
    check("single ret at 0x63b9f79",
          len(rets) == 1 and "63b9f79:" in rets[0])
    calls = [l for l in lines if re.search(r"\tcall", l)]
    check("zero calls in FDE", len(calls) == 0)
    bad_jumps = []
    for l in lines:
        m = re.search(r"\tjmp?\s+([0-9a-f]+)", l)
        if m:
            tgt = int(m.group(1), 16)
            if not (FDE_LO <= tgt < FDE_HI):
                bad_jumps.append(l.strip())
    check("jump targets internal", not bad_jumps, str(bad_jumps[:3]))

    # Key bytes.
    check("head==block je at 0x63b9d2b",
          data[va_off(0x63B9D2B):va_off(0x63B9D2B) + 6] ==
          bytes.fromhex("0f849f020000"))
    check("count reset [entry+8]:=0 at 0x63b9fe4",
          data[va_off(0x63B9FE4):va_off(0x63B9FE4) + 8] ==
          bytes.fromhex("48c7470800000000"))
    check("emptying store [entry]:=rdx at 0x63ba308",
          data[va_off(0x63BA308):va_off(0x63BA308) + 3] ==
          bytes.fromhex("488917"))
    check("ret byte at 0x63b9f79", data[va_off(RET_SITE)] == 0xC3)
    check("int3 padding before FDE",
          data[va_off(0x63B9D0C):va_off(FDE_LO)] == bytes.fromhex("cccccccc"))
    check("int3 padding after FDE",
          data[va_off(FDE_HI):va_off(0x63BA600)] == bytes.fromhex("cccccc"))

    # Census: .text scan (VA 0x1419300, offset 0x1418300, size 0x4fd7700).
    text_va, text_off, text_sz = 0x1419300, 0x1418300, 0x4FD7700
    e8, e9 = [], []
    i = 0
    while i < text_sz - 5:
        b = data[text_off + i]
        if b in (0xE8, 0xE9):
            rel = struct.unpack("<i", data[text_off + i + 1:text_off + i + 5])[0]
            if text_va + i + 5 + rel == TARGET:
                (e8 if b == 0xE8 else e9).append(text_va + i)
        i += 1
    check("census E8 ['0x63d870f']", e8 == [0x63D870F],
          str([hex(x) for x in e8]))
    check("census E9 empty", e9 == [])
    # LEA rip-relative scan.
    lea = []
    i = 0
    while i < text_sz - 7:
        b0, b1 = data[text_off + i], data[text_off + i + 1]
        if b0 in (0x48, 0x4C) and b1 == 0x8D:
            modrm = data[text_off + i + 2]
            if (modrm & 0xC7) == 0x05:
                disp = struct.unpack(
                    "<i", data[text_off + i + 3:text_off + i + 7])[0]
                if text_va + i + 7 + disp == TARGET:
                    lea.append(text_va + i)
        i += 1
    check("census LEA empty", lea == [])
    # Call-site rel32 confirmation.
    o = va_off(0x63D870F)
    rel = struct.unpack("<i", data[o + 1:o + 5])[0]
    check("E8 site 0x63d870f rel32",
          data[o] == 0xE8 and 0x63D870F + 5 + rel == TARGET)
    # .rela.dyn addends.
    out = subprocess.run(["readelf", "-r", BIN],
                         capture_output=True, text=True, check=True).stdout
    sec = out.split("Relocation section '.rela.dyn'")[1].split(
        "Relocation section")[0]
    entries = [l for l in sec.splitlines()
               if re.match(r"\s*[0-9a-f]+\s+[0-9a-f]+\s+\S+", l)]
    check("rela.dyn 60723 entries", len(entries) == 60723)
    hits = sum(1 for l in entries
               if len(l.split()) >= 3 and l.split()[2] == "63b9d10")
    check("census GOT empty", hits == 0)

    # Neighbour disjointness: exhibits inside FDE, no overlap with
    # any claimed exhibit range in the merged tree or recent worktrees.
    for name, ex in exhibits.items():
        lo = int(ex["range"][0], 16)
        hi = int(ex["range"][1], 16)
        check(name + " inside FDE", FDE_LO <= lo and hi <= FDE_HI)
    claimed = []
    for base in [os.path.join(ROOT, "research", "work-items")]:
        for dirpath, _, files in os.walk(base):
            if "records.json" in files:
                try:
                    with open(os.path.join(dirpath, "records.json")) as f:
                        rec = json.load(f)
                except (ValueError, OSError):
                    continue
                exs = rec.get("exhibits", rec) if isinstance(rec, dict) else rec
                items = exs.items() if isinstance(exs, dict) else []
                for _, ex in items:
                    try:
                        claimed.append((int(ex["range"][0], 16),
                                        int(ex["range"][1], 16)))
                    except (KeyError, TypeError, ValueError):
                        continue
    # Recent unmerged worktrees (same packet family).
    import glob
    for wt in glob.glob(os.path.expanduser("~/workspace/hl-wt-calls2[345]*-115")):
        for dirpath, _, files in os.walk(os.path.join(
                wt, "research", "work-items")):
            if "records.json" in files:
                try:
                    with open(os.path.join(dirpath, "records.json")) as f:
                        rec = json.load(f)
                except (ValueError, OSError):
                    continue
                exs = rec.get("exhibits", rec) if isinstance(rec, dict) else rec
                items = exs.items() if isinstance(exs, dict) else []
                for _, ex in items:
                    try:
                        claimed.append((int(ex["range"][0], 16),
                                        int(ex["range"][1], 16)))
                    except (KeyError, TypeError, ValueError):
                        continue
    overlap = []
    for name, ex in exhibits.items():
        lo = int(ex["range"][0], 16)
        hi = int(ex["range"][1], 16)
        for clo, chi in claimed:
            if lo < chi and clo < hi and (clo, chi) != (lo, hi):
                # Ignore this packet's own ranges (same worktree scan).
                if clo == lo and chi == hi:
                    continue
                overlap.append((name, hex(clo), hex(chi)))
    # The walk above includes this packet's own dir; filter self-ranges.
    own = {(int(ex["range"][0], 16), int(ex["range"][1], 16))
           for ex in exhibits.values()}
    overlap = [o for o in overlap
               if (int(o[1], 16), int(o[2], 16)) not in own]
    check("no neighbour overlap", not overlap, str(overlap[:5]))

    # MANIFEST coverage.
    with open(os.path.join(PACKET, "MANIFEST.sha256")) as f:
        manifest = [l.split() for l in f.read().splitlines() if l.strip()]
    check("MANIFEST 17 entries", len(manifest) == 17)
    ok = True
    for h, p in manifest:
        full = os.path.normpath(os.path.join(PACKET, p))
        if not os.path.exists(full):
            ok = False
            break
        with open(full, "rb") as f:
            if hashlib.sha256(f.read()).hexdigest() != h:
                ok = False
                break
    check("MANIFEST hashes match", ok)

    if FAILURES:
        print("verifier: %d check(s) FAILED" % len(FAILURES))
        return 1
    print("verifier: all checks passed (6 excerpts, 259 bytes, "
          "71 strict, census 1 E8 site, MANIFEST 17 entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
