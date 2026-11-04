#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-entryprobe.

Checks, with byte reads only (the node binary is never executed):
  binary SHA-256/size, exhibit bytes, objdump regeneration, strict counts,
  FDE bounds (via .eh_frame), single ret, key bytes, caller-site context
  (call rel32s + test %al,%al, cited only), full census (E8/E9/LEA/GOT),
  neighbour disjointness, MANIFEST coverage.
"""
import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parents[1] / "research/work-items/RE-001-node115-lu-entryprobe"
BIN = Path(__file__).resolve().parents[1] / "artifacts/node/115/hl-node"
EXPECT_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
EXPECT_SIZE = 105896032
TEXT_VA, TEXT_OFF = 0x1419300, 0x1418300
TEXT_SIZE = 0x4FD7700
RELA_OFF, RELA_SIZE = 0x6BE8, 0x163CC8
TARGET = 0x63B9680
FDE_END = 0x63B968C

failures = []


def check(name, ok, detail=""):
    print(("ok: " if ok else "FAIL: ") + name + (f" ({detail})" if detail else ""))
    if not ok:
        failures.append(name)


def main():
    data = BIN.read_bytes()
    check("binary sha", hashlib.sha256(data).hexdigest() == EXPECT_SHA)
    check("binary size", len(data) == EXPECT_SIZE, f"{len(data)} bytes")

    records = json.loads((PACKET / "records.json").read_text())
    exhibits = records["exhibits"]
    total_bytes = 0
    total_strict = 0
    for name, spec in exhibits.items():
        start = int(spec["range"][0], 16)
        end = int(spec["range"][1], 16)
        raw = bytes.fromhex((PACKET / f"{name}.hex").read_text().split()[0])
        check(f"{name} length", len(raw) == spec["bytes"] == end - start,
              f"{len(raw)} bytes")
        check(f"{name} bytes", data[start - 0x1000:start - 0x1000 + len(raw)] == raw)
        out = subprocess.run(
            ["objdump", "-d", f"--start-address={hex(start)}",
             f"--stop-address={hex(end)}", str(BIN)],
            capture_output=True, text=True, check=True).stdout
        regen = [l for l in out.splitlines() if re.match(r"^\s*[0-9a-f]+:\t", l)]
        saved = (PACKET / f"{name}.objdump.txt").read_text().splitlines()
        check(f"{name} objdump regeneration", regen == saved)
        strict = sum(1 for l in saved
                     if len(l.split("\t")) >= 3
                     and l.split("\t")[2].strip()
                     and not re.fullmatch(r"[0-9a-f ]+", l.split("\t")[2].strip()))
        check(f"{name} strict", strict == spec["strict"], f"{strict}")
        total_bytes += len(raw)
        total_strict += strict
    check("exhibits total", total_bytes == 12 and total_strict == 4,
          f"{total_bytes} bytes, {total_strict} strict")

    # FDE bounds from .eh_frame (readelf output, not endbr64 scanning).
    frames = subprocess.run(
        ["readelf", "--debug-dump=frames-interp", str(BIN)],
        capture_output=True, text=True, check=True).stdout
    m = re.search(r"pc=0+63b9680\.\.0+63b968c", frames)
    check("FDE bounds", bool(m), "0x63b9680..0x63b968c")

    # Key bytes inside the FDE.
    fde = data[TARGET - 0x1000:FDE_END - 0x1000]
    check("key bytes endbr64", fde[:4] == bytes.fromhex("f30f1efa"))
    check("key bytes cmpq", fde[4:8] == bytes.fromhex("48833f00"))
    check("key bytes sete", fde[8:11] == bytes.fromhex("0f94c0"))
    check("key bytes ret", fde[11] == 0xC3)
    check("single ret", fde.count(b"\xc3") == 1)
    check("zero calls in FDE", 0xE8 not in fde)
    check("padding before", data[0x63B9674 - 0x1000:TARGET - 0x1000] == b"\xcc" * 12)
    check("padding after", data[FDE_END - 0x1000:0x63B9690 - 0x1000] == b"\xcc" * 4)

    # Caller-site context (cited only, not claimed exhibits).
    def call_target(site):
        o = TEXT_OFF + (site - TEXT_VA)
        return site + 5 + struct.unpack("<i", data[o + 1:o + 5])[0]

    for site in (0x63D8717, 0x63D8874):
        o = TEXT_OFF + (site - TEXT_VA)
        check(f"E8 at {hex(site)}", data[o] == 0xE8)
        check(f"call {hex(site)} -> 0x63b9680", call_target(site) == TARGET)
        t = TEXT_OFF + (site + 5 - TEXT_VA)
        check(f"test %al,%al after {hex(site)}", data[t:t + 2] == b"\x84\xc0")

    # Full census over .text.
    e8, e9, lea = [], [], []
    for va in range(TEXT_VA, TEXT_VA + TEXT_SIZE):
        o = TEXT_OFF + (va - TEXT_VA)
        b = data[o]
        if b == 0xE8:
            if va + 5 + struct.unpack("<i", data[o + 1:o + 5])[0] == TARGET:
                e8.append(va)
        elif b == 0xE9:
            if va + 5 + struct.unpack("<i", data[o + 1:o + 5])[0] == TARGET:
                e9.append(va)
        elif b in (0x48, 0x4C) and data[o + 1] == 0x8D and (data[o + 2] & 0xC7) == 0x05:
            if va + 7 + struct.unpack("<i", data[o + 3:o + 7])[0] == TARGET:
                lea.append(va)
    check("census E8", sorted(e8) == [0x63D8717, 0x63D8874],
          f"{[hex(x) for x in e8]}")
    check("census E9 empty", e9 == [])
    check("census LEA empty", lea == [])
    n_rela = RELA_SIZE // 24
    got = sum(1 for i in range(n_rela)
              if struct.unpack("<q", data[RELA_OFF + i * 24 + 16:RELA_OFF + i * 24 + 24])[0] == TARGET)
    check("rela.dyn entries", n_rela == 60723, f"{n_rela}")
    check("census GOT empty", got == 0)

    # Disjointness against merged-tree exhibit ranges.
    root = Path(__file__).resolve().parents[1]
    overlap = []
    for rec_path in (root / "research/work-items").glob("*/records.json"):
        try:
            rec = json.loads(rec_path.read_text())
        except Exception:
            continue
        ex = rec.get("exhibits", {}) if isinstance(rec, dict) else {}
        items = ex.items() if isinstance(ex, dict) else []
        for _, spec in items:
            if not isinstance(spec, dict):
                continue
            r = spec.get("range")
            if isinstance(r, list) and len(r) == 2:
                a, b = int(r[0], 16), int(r[1], 16)
                if a < FDE_END and TARGET < b and (a, b) != (TARGET, FDE_END):
                    overlap.append((str(rec_path), hex(a), hex(b)))
    check("no neighbour overlap", overlap == [], f"{overlap}")

    # MANIFEST coverage.
    manifest = (PACKET / "MANIFEST.sha256").read_text().splitlines()
    entries = {}
    for line in manifest:
        h, p = line.split(None, 1)
        entries[p.strip()] = h
    ok_manifest = True
    for p, h in entries.items():
        target = (PACKET / p).resolve() if not p.startswith("../../../") \
            else (root / p[9:])
        if not target.exists() or hashlib.sha256(target.read_bytes()).hexdigest() != h:
            ok_manifest = False
    check("MANIFEST hashes match", ok_manifest, f"{len(entries)} entries")
    check("MANIFEST coverage", len(entries) == 7, f"{len(entries)} entries")

    if failures:
        print(f"verifier: FAILED ({len(failures)} checks)")
        return 1
    print("verifier: all checks passed (1 excerpt, 12 bytes, 4 strict, "
          "census 2 E8 sites, MANIFEST 7 entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
