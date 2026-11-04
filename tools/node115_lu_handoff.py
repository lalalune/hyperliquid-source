#!/usr/bin/env python3
"""Static verifier for the node #115 lu handoff packet
(RE-001-node115-lu-handoff). Byte reads only; the binary is never executed.

Checks: binary SHA-256/size, exhibit bytes, strict mnemonic counts,
objdump regeneration (header lines stripped, since they embed the
invoked path), FDE bounds, single ret, key stores and call rel32s,
tail-jump target, full census (E8/E9/LEA/GOT), neighbour disjointness,
MANIFEST coverage.
"""

import hashlib
import json
import os
import re
import struct
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(REPO, "research", "work-items", "RE-001-node115-lu-handoff")
NODE = os.path.join(REPO, "artifacts", "node", "115", "hl-node")

TARGET_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET_SIZE = 105896032
FDE_START = 0x63D8790
FDE_END = 0x63D88C4
RET_SITE = 0x63D87F7

EXHIBITS = {
    "hd_entry": (0x63D8790, 0x63D87F8, 104, 33),
    "hd_size": (0x63D8800, 0x63D8879, 121, 30),
    "hd_tail": (0x63D8879, 0x63D88A8, 47, 15),
    "hd_over": (0x63D88B0, 0x63D88C4, 20, 4),
}

CENSUS_E8 = [0x63D9232, 0x63D966A]

STRICT_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t\S")
ADDR_RE = re.compile(r"^\s*[0-9a-f]+:")

failures = []


def check(cond, msg):
    if cond:
        print("ok:", msg)
    else:
        print("FAIL:", msg)
        failures.append(msg)


def off(va):
    return va - 0x1000


def objdump_lines(start, end):
    out = subprocess.run(
        ["objdump", "-d", "--start-address=%s" % hex(start),
         "--stop-address=%s" % hex(end), NODE],
        capture_output=True, text=True, check=True).stdout
    return [line for line in out.splitlines() if ADDR_RE.match(line)]


def main():
    with open(NODE, "rb") as f:
        data = f.read()
    check(hashlib.sha256(data).hexdigest() == TARGET_SHA, "binary sha")
    check(len(data) == TARGET_SIZE, "binary size %d" % TARGET_SIZE)

    total_bytes = 0
    total_strict = 0
    for name, (start, end, nbytes, nstrict) in EXHIBITS.items():
        with open(os.path.join(PACKET, name + ".hex")) as f:
            raw = bytes.fromhex("".join(f.read().split()))
        check(len(raw) == nbytes, "%s length" % name)
        check(raw == data[off(start):off(start) + nbytes], "%s bytes" % name)
        with open(os.path.join(PACKET, name + ".objdump.txt")) as f:
            saved = [line for line in f.read().splitlines() if line.strip()]
        check(saved == objdump_lines(start, end), "%s objdump regeneration" % name)
        strict = sum(1 for line in saved if STRICT_RE.match(line))
        check(strict == nstrict, "%s strict %d" % (name, nstrict))
        total_bytes += nbytes
        total_strict += nstrict
    check(total_bytes == 292, "exhibits total 292 bytes")
    check(total_strict == 82, "exhibits total 82 strict")

    # FDE bounds: entry begins with push %r14 (no endbr64 here — the
    # #233 caution: FDE bounds come from .eh_frame, not endbr64 scans).
    check(data[off(FDE_START):off(FDE_START) + 4] == bytes.fromhex("41564155"),
          "FDE entry push r14, push r13")
    check(FDE_END - FDE_START == 308, "FDE size 308")
    check(data[off(RET_SITE)] == 0xC3, "single ret at 0x63d87f7")
    nret = 0
    for line in objdump_lines(FDE_START, FDE_END):
        if re.search(r"\tret$", line):
            nret += 1
    check(nret == 1, "exactly one ret in FDE")

    # Key bytes: [block+0x12] := 1 store; anchor store; nopl gaps unclaimed.
    check(data[off(0x63D87A2):off(0x63D87A2) + 4] == bytes.fromhex("c6461201"),
          "flag store [block+0x12] := 1")
    check(data[off(0x63D87E8):off(0x63D87E8) + 7] == bytes.fromhex("48899d80100000"),
          "anchor store [first-arg+0x1080] := block")
    check(data[off(0x63D87F8):off(0x63D8800)] == b"\x0f\x1f\x84\x00\x00\x00\x00\x00",
          "nopl padding between epilogue and size path")

    # Key calls by rel32: size mapping and entry probe; tail jump target.
    for site, want in ((0x63D8810, 0x63E8BF0), (0x63D8874, 0x63B9680)):
        check(data[off(site)] == 0xE8, "E8 at %s" % hex(site))
        rel = struct.unpack_from("<i", data, off(site) + 1)[0]
        check(site + 5 + rel == want, "call %s -> %s" % (hex(site), hex(want)))
    check(data[off(0x63D88A3)] == 0xE9, "E9 tail jump at 0x63d88a3")
    rel = struct.unpack_from("<i", data, off(0x63D88A3) + 1)[0]
    check(0x63D88A3 + 5 + rel == 0x63B99D0, "tail jump -> 0x63b99d0")

    # Full census over .text (VA - 0x1000 file mapping).
    out = subprocess.run(["readelf", "-W", "-S", NODE],
                         capture_output=True, text=True, check=True).stdout
    secs = {}
    for line in out.splitlines():
        m = re.match(r"\s*\[\s*\d+\]\s+(\S+)\s+\S+\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)", line)
        if m:
            secs[m.group(1)] = (int(m.group(2), 16), int(m.group(3), 16), int(m.group(4), 16))
    taddr, toff, tsize = secs[".text"]
    text = data[toff:toff + tsize]
    e8, e9, lea = [], [], []
    i = 0
    while i < len(text) - 8:
        b = text[i]
        if b == 0xE8:
            rel = struct.unpack("<i", text[i + 1:i + 5])[0]
            if taddr + i + 5 + rel == FDE_START:
                e8.append(taddr + i)
            i += 1
        elif b == 0xE9:
            rel = struct.unpack("<i", text[i + 1:i + 5])[0]
            if taddr + i + 5 + rel == FDE_START:
                e9.append(taddr + i)
            i += 1
        elif b in (0x48, 0x4C) and text[i + 1] == 0x8D and (text[i + 2] & 0xC7) == 0x05:
            disp = struct.unpack("<i", text[i + 3:i + 7])[0]
            if taddr + i + 7 + disp == FDE_START:
                lea.append(taddr + i)
            i += 1
        else:
            i += 1
    check(e8 == CENSUS_E8, "census E8 %s" % [hex(x) for x in e8])
    check(e9 == [], "census E9 empty")
    check(lea == [], "census LEA empty")
    for site in CENSUS_E8:
        rel = struct.unpack_from("<i", data, off(site) + 1)[0]
        check(site + 5 + rel == FDE_START, "E8 site %s rel32" % hex(site))
    raddr, roff, rsize = secs[".rela.dyn"]
    nrela = rsize // 24
    hits = 0
    for k in range(nrela):
        _o, _info, add = struct.unpack("<QQq", data[roff + k * 24:roff + k * 24 + 24])
        if add == FDE_START:
            hits += 1
    check(nrela == 60723, "rela.dyn 60723 entries")
    check(hits == 0, "census GOT empty")

    # Neighbour disjointness: exhibits inside FDE, no overlap with other
    # exhibits-bearing records in this worktree.
    for name, (start, end, _b, _s) in EXHIBITS.items():
        check(FDE_START <= start and end <= FDE_END, "%s inside FDE" % name)
    import glob as _glob
    own = os.path.join(PACKET, "records.json")
    overlap = []
    for path in _glob.glob(os.path.join(REPO, "research", "work-items", "*", "records.json")):
        if os.path.abspath(path) == os.path.abspath(own):
            continue
        try:
            rec = json.load(open(path))
        except Exception:
            continue
        ex = rec.get("exhibits", {}) if isinstance(rec, dict) else rec
        items = ex.items() if isinstance(ex, dict) else [
            (e.get("name", str(i)), e) for i, e in enumerate(ex)]
        for _n, e in items:
            try:
                r = e["range"]
                s, en = int(r[0], 16), int(r[1], 16)
            except Exception:
                continue
            for _n2, (s2, e2, _b, _s) in EXHIBITS.items():
                if s < e2 and s2 < en:
                    overlap.append(path)
    check(not overlap, "no neighbour overlap")

    # MANIFEST coverage.
    manifest = os.path.join(PACKET, "MANIFEST.sha256")
    with open(manifest) as f:
        entries = [line.split() for line in f if line.strip()]
    check(len(entries) == 13, "MANIFEST 13 entries")
    import hashlib as _h
    ok = True
    for _sha, rel in entries:
        p = os.path.normpath(os.path.join(PACKET, rel))
        if not os.path.exists(p):
            ok = False
            break
        with open(p, "rb") as f:
            if _h.sha256(f.read()).hexdigest() != _sha:
                ok = False
                break
    check(ok, "MANIFEST hashes match")

    if failures:
        print("verifier: %d checks failed" % len(failures))
        return 1
    print("verifier: all checks passed "
          "(4 excerpts, 292 bytes, 82 strict, census 2 E8 sites, MANIFEST 13 entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
