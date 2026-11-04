#!/usr/bin/env python3
"""Static verifier for the node #115 lu class-insert packet
(RE-001-node115-lu-classinsert). Byte reads only; the binary is never
executed.

Checks: binary SHA-256/size, exhibit bytes, strict mnemonic counts,
objdump regeneration (header lines stripped, since they embed the
invoked path), FDE bounds, two ret sites, zero calls, key stores,
jump targets internal, tail-jump source, full census (E8/E9/LEA/GOT),
neighbour disjointness, MANIFEST coverage.
"""

import glob
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(REPO, "research", "work-items", "RE-001-node115-lu-classinsert")
NODE = os.path.join(REPO, "artifacts", "node", "115", "hl-node")

TARGET_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET_SIZE = 105896032
FDE_START = 0x63B99D0
FDE_END = 0x63B9D0C
RET_SITES = (0x63B9A4C, 0x63B9CD7)

EXHIBITS = {
    "tl_entry": (0x63B99D0, 0x63B99F5, 37, 11),
    "tl_cmp": (0x63B99F5, 0x63B9A1E, 41, 11),
    "tl_insert": (0x63B9A1E, 0x63B9A4D, 47, 16),
    "tl_min": (0x63B9CC0, 0x63B9CD8, 24, 8),
    "tl_loop": (0x63B9A50, 0x63B9A7A, 42, 12),
    "tl_step": (0x63B9B10, 0x63B9B8A, 122, 30),
}

CENSUS_E9 = [0x63D88A3]

STRICT_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t\S")
ADDR_RE = re.compile(r"^\s*[0-9a-f]+:")
JUMP_RE = re.compile(r"\t(j\w+)\s+([0-9a-f]+)\s*(<|$)")

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
    check(total_bytes == 313, "exhibits total 313 bytes")
    check(total_strict == 88, "exhibits total 88 strict")

    # FDE bounds from .eh_frame (the #233 caution: bounds come from
    # .eh_frame, not from scanning for endbr64 — though this FDE does
    # start with endbr64).
    check(data[off(FDE_START):off(FDE_START) + 4] == bytes.fromhex("f30f1efa"),
          "FDE entry endbr64")
    check(FDE_END - FDE_START == 828, "FDE size 828")
    for site in RET_SITES:
        check(data[off(site)] == 0xC3, "ret at %s" % hex(site))
    fde_lines = objdump_lines(FDE_START, FDE_END)
    rets = [line for line in fde_lines if re.search(r"\tret$", line)]
    check(len(rets) == 2, "exactly two rets in FDE")
    calls = [line for line in fde_lines if re.search(r"\tcall\s", line)]
    check(not calls, "zero calls in FDE")

    # Jump targets: every direct jump inside the FDE lands inside it.
    # (The FDE has no tail jump of its own; all jumps are internal.)
    for line in fde_lines:
        m = JUMP_RE.search(line)
        if m:
            tgt = int(m.group(2), 16)
            check(FDE_START <= tgt < FDE_END,
                  "jump target %s internal" % hex(tgt))

    # Key bytes: block zeroing, count bump, tzcnt, min displacement.
    check(data[off(0x63B99E3):off(0x63B99E3) + 4] == bytes.fromhex("0f114628"),
          "block +0x28/+0x30 zeroed by movups")
    check(data[off(0x63B99EA):off(0x63B99EA) + 8] == bytes.fromhex("48c7411000000000"),
          "block +0x38 zeroed by movq $0")
    check(data[off(0x63B9A1E):off(0x63B9A1E) + 4] == bytes.fromhex("488b5f08"),
          "count load [entry+8]")
    check(data[off(0x63B9A26):off(0x63B9A26) + 4] == bytes.fromhex("48896f08"),
          "count store [entry+8] := count+1")
    check(data[off(0x63B9A57):off(0x63B9A57) + 5] == bytes.fromhex("f34c0fbcdd"),
          "tzcnt on count-1")
    check(data[off(0x63B9CC0):off(0x63B9CC0) + 4] == bytes.fromhex("48897110"),
          "min path [block+0x38] := head")
    check(data[off(0x63B9CCB):off(0x63B9CCB) + 8] == bytes.fromhex("48c7470800000000"),
          "min path [entry+8] := 0")
    # Padding around the FDE.
    check(data[off(0x63B99C8):off(0x63B99D0)] == b"\xcc" * 8,
          "int3 padding before FDE")
    check(data[off(0x63B9D0C):off(0x63B9D10)] == b"\xcc" * 4,
          "int3 padding after FDE")

    # Tail-jump source: the handoff's size path jumps here.
    check(data[off(0x63D88A3)] == 0xE9, "E9 tail jump at 0x63d88a3")
    rel = struct.unpack_from("<i", data, off(0x63D88A3) + 1)[0]
    check(0x63D88A3 + 5 + rel == FDE_START, "tail jump -> 0x63b99d0")

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
    check(e8 == [], "census E8 empty")
    check(e9 == CENSUS_E9, "census E9 %s" % [hex(x) for x in e9])
    check(lea == [], "census LEA empty")
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
    own = os.path.join(PACKET, "records.json")
    overlap = []
    for path in glob.glob(os.path.join(REPO, "research", "work-items", "*", "records.json")):
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
    check(len(entries) == 17, "MANIFEST 17 entries")
    ok = True
    for _sha, rel in entries:
        p = os.path.normpath(os.path.join(PACKET, rel))
        if not os.path.exists(p):
            ok = False
            break
        with open(p, "rb") as f:
            if hashlib.sha256(f.read()).hexdigest() != _sha:
                ok = False
                break
    check(ok, "MANIFEST hashes match")

    if failures:
        print("verifier: %d checks failed" % len(failures))
        return 1
    print("verifier: all checks passed "
          "(6 excerpts, 313 bytes, 88 strict, census 1 E9 site, MANIFEST 17 entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
