#!/usr/bin/env python3
"""Caller census for the node #115 RocksDB ZSTD streaming destructors.

Scans the whole .text of work/hl-node-115.bin for direct E8 calls, E9 tail
jumps and RIP-relative LEA references landing on each of the four target
functions, then validates every candidate site by decoding forward from its
enclosing FDE start with Capstone: a site only counts when it lands on a real
instruction boundary and the decoded instruction is the expected kind with
the expected target.  This rejects false positives from immediate bytes.

Usage: python3 census.py [--out DIR]   (defaults to the packet directory)
Writes callers.tsv (validated sites) and census.json (summary).
"""
import argparse
import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

import os
REPO = Path(os.environ.get("HL_REPO") or Path(__file__).resolve().parents[3])
BIN = REPO / "work" / "hl-node-115.bin"
ARTIFACT_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

TARGETS = {
    "0x5f03a10": "rocksdb::ZSTDStreamingCompress::~ZSTDStreamingCompress (D0)",
    "0x5f03a40": "rocksdb::ZSTDStreamingCompress::~ZSTDStreamingCompress (D1)",
    "0x5f014f0": "rocksdb::ZSTDStreamingUncompress::~ZSTDStreamingUncompress (D0)",
    "0x5f01520": "rocksdb::ZSTDStreamingUncompress::~ZSTDStreamingUncompress (D1)",
}


def load_text():
    out = subprocess.check_output(["readelf", "-SW", str(BIN)]).decode()
    m = re.search(r"\.text\s+PROGBITS\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)",
                  out)
    va, off, size = (int(m.group(i), 16) for i in (1, 2, 3))
    data = open(BIN, "rb").read()
    return va, off, data[off:off + size]


def load_fdes():
    """Return {fde_start_va: fde_end_va} from readelf --debug-dump=frames-interp."""
    out = subprocess.check_output(
        ["readelf", "--debug-dump=frames-interp", str(BIN)]).decode()
    fdes = {}
    for line in out.splitlines():
        m = re.search(r"FDE.*pc=([0-9a-f]+)\.\.([0-9a-f]+)", line)
        if m:
            fdes[int(m.group(1), 16)] = int(m.group(2), 16)
    return fdes


def fde_containing(fdes, starts, va):
    import bisect
    i = bisect.bisect_right(starts, va) - 1
    if i < 0:
        return None
    s = starts[i]
    return (s, fdes[s]) if s <= va < fdes[s] else None


def raw_scan(text_va, text):
    """Yield (site_va, kind, target_va) for raw E8/E9/LEA patterns."""
    n = len(text)
    for opcode, kind, width in ((0xE8, "call", 5), (0xE9, "jmp", 5)):
        i = 0
        while True:
            i = text.find(bytes([opcode]), i)
            if i < 0 or i + 5 > n:
                break
            disp = struct.unpack_from("<i", text, i + 1)[0]
            site = text_va + i
            yield site, kind, site + width + disp
            i += 1
    # 48 8d modrm rip-relative: mod=00 rm=101 -> modrm in 0x05..0x3d step 8
    i = 0
    while True:
        i = text.find(b"\x48\x8d", i)
        if i < 0 or i + 7 > n:
            break
        modrm = text[i + 2]
        if modrm & 0xC7 == 0x05:
            disp = struct.unpack_from("<i", text, i + 3)[0]
            site = text_va + i
            yield site, "lea", site + 7 + disp
        i += 1


def validate(text_va, text, fdes, starts, site, kind, target):
    """Decode from the enclosing FDE start; accept only a real instruction
    of the expected kind at `site` with the expected target."""
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    fde = fde_containing(fdes, starts, site)
    if fde is None:
        return None
    start, end = fde
    off = start - text_va
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False
    for insn in md.disasm(text[off:start - text_va + (end - start)], start):
        if insn.address == site:
            if kind == "call" and insn.mnemonic == "call":
                return insn
            if kind == "jmp" and insn.mnemonic == "jmp":
                return insn
            if kind == "lea" and insn.mnemonic == "lea":
                return insn
            return None
        if insn.address > site:
            return None
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(Path(__file__).resolve().parent))
    args = ap.parse_args()
    outdir = Path(args.out)
    data = open(BIN, "rb").read()
    if hashlib.sha256(data).hexdigest() != ARTIFACT_SHA256:
        print("artifact digest mismatch", file=sys.stderr)
        return 1
    text_va, text_off, text = load_text()
    fdes = load_fdes()
    starts = sorted(fdes)
    targets = {int(k, 16): v for k, v in TARGETS.items()}

    rows = []
    for site, kind, target in raw_scan(text_va, text):
        if target not in targets:
            continue
        insn = validate(text_va, text, fdes, starts, site, kind, target)
        if insn is None:
            continue
        fde = fde_containing(fdes, starts, site)
        rows.append({
            "target": f"0x{target:x}",
            "target_name": targets[target],
            "kind": kind,
            "site": f"0x{site:x}",
            "site_fde_start": f"0x{fde[0]:x}",
            "site_fde_end": f"0x{fde[1]:x}",
            "instruction": f"{insn.mnemonic} {insn.op_str}",
        })

    rows.sort(key=lambda r: (r["target"], r["site"]))
    with open(outdir / "callers.tsv", "w") as fh:
        fh.write("target\ttarget_name\tkind\tsite\tsite_fde_start\t"
                 "site_fde_end\tinstruction\n")
        for r in rows:
            fh.write("\t".join(r[k] for k in (
                "target", "target_name", "kind", "site", "site_fde_start",
                "site_fde_end", "instruction")) + "\n")

    summary = {f"0x{t:x}": {
        "name": name,
        "calls": sum(1 for r in rows if r["target"] == f"0x{t:x}"
                     and r["kind"] == "call"),
        "jumps": sum(1 for r in rows if r["target"] == f"0x{t:x}"
                     and r["kind"] == "jmp"),
        "lea_refs": sum(1 for r in rows if r["target"] == f"0x{t:x}"
                        and r["kind"] == "lea"),
    } for t, name in targets.items()}
    with open(outdir / "census.json", "w") as fh:
        json.dump({"artifact_sha256": ARTIFACT_SHA256,
                   "targets": summary,
                   "validated_sites": len(rows)}, fh, indent=1)
    for t, name in targets.items():
        s = summary[f"0x{t:x}"]
        print(f"0x{t:x} {name}: {s['calls']} calls, {s['jumps']} jumps, "
              f"{s['lea_refs']} lea refs")
    print("validated sites:", len(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
