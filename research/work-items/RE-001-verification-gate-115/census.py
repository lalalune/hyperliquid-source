#!/usr/bin/env python3
"""Reproduce every census in the RE-001-verification-gate-115 packet.

Run from the repository root:
  python3 research/work-items/RE-001-verification-gate-115/census.py

Reproduces, from work/hl-node-115.bin only:
  callers.tsv   -- every direct call site of the apply 0x60bedc0
                   (13 sites) and the serializer 0x60bb9a0 (16 sites),
                   from a byte-level E8 rel32 scan; neither function
                   is address-taken (no lea site targets either).
  frames.txt    -- the two FDE ranges, parsed from readelf output.
  literals.tsv  -- the three message literals the gate builds its
                   Status messages from, read from .rodata.

Section map (readelf -S): .rodata vaddr == file offset; .text file
offset == vaddr - 0x1000.  The gate's message literals live in
.rodata; the verification field is record+0xac, the type field
record+0xa8, the flags field record+0xb0.
"""

import re
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent.parent
BIN = ROOT / "work" / "hl-node-115.bin"

APPLY = 0x60BEDC0
SERIALIZER = 0x60BB9A0

TEXT_VADDR = 0x1419300
TEXT_OFF = 0x1418300
TEXT_SIZE = 0x4FD7700

# Message literals the gate concatenates into its Status messages.
LITERALS = {
    0x4373E9: "Deserializing the option ",
    0x437403: " is not supported",
    0x4477ED: "Error parsing:",
}


def read_rodata_str(data, vaddr, limit=200):
    raw = data[vaddr:vaddr + limit]
    end = raw.find(b"\x00")
    return raw[:end if end >= 0 else limit].decode("latin1")


def byte_scan_callers(text):
    targets = {APPLY: "apply", SERIALIZER: "serializer"}
    found = {k: [] for k in targets}
    for i in range(len(text) - 5):
        if text[i] == 0xE8:
            rel = struct.unpack_from("<i", text, i + 1)[0]
            ip = TEXT_VADDR + i
            for t in targets:
                if ip + 5 + rel == t:
                    found[t].append(ip)
    return found


def byte_scan_lea_sites(text):
    targets = {APPLY, SERIALIZER}
    found = {t: [] for t in targets}
    for m in re.finditer(rb"\x48\x8d", text):
        i = m.start()
        if i + 7 > len(text):
            continue
        modrm = text[i + 2]
        if (modrm & 0xC7) == 0x05:
            disp = struct.unpack_from("<i", text, i + 3)[0]
            site_va = TEXT_VADDR + i
            for t in targets:
                if site_va + 7 + disp == t:
                    found[t].append(site_va)
    return found


def parse_frames():
    out = subprocess.run(
        ["readelf", "--debug-dump=frames-interp",
         "work/hl-node-115.bin"],
        cwd=ROOT, capture_output=True, text=True, check=True).stdout
    fdes = []
    for line in out.splitlines():
        if "FDE" in line and "pc=" in line:
            pc = line.split("pc=")[1].strip()
            a, b = pc.split("..")
            fdes.append((int(a, 16), int(b, 16)))
    fdes.sort()
    want = [APPLY, SERIALIZER]
    rows = []
    for t in want:
        hit = [f for f in fdes if f[0] <= t < f[1]]
        assert len(hit) == 1, f"no unique FDE for {t:#x}: {hit}"
        rows.append(hit[0])
    return rows


def main():
    data = BIN.read_bytes()
    text = data[TEXT_OFF:TEXT_OFF + TEXT_SIZE]

    callers = byte_scan_callers(text)
    lea = byte_scan_lea_sites(text)
    with open(HERE / "callers.tsv", "w") as f:
        f.write("target\tsite\n")
        for t, sites in sorted(callers.items()):
            for s in sorted(sites):
                f.write(f"{t:#x}\t{s:#x}\n")
    for t, sites in sorted(callers.items()):
        print(f"callers of {t:#x}: {len(sites)}")
    for t, sites in sorted(lea.items()):
        print(f"lea sites of {t:#x}: {len(sites)}")
        assert not sites, f"unexpected lea site for {t:#x}"

    with open(HERE / "literals.tsv", "w") as f:
        f.write("address\tliteral\n")
        for addr, expected in sorted(LITERALS.items()):
            got = read_rodata_str(data, addr)
            assert got == expected, (hex(addr), got, expected)
            f.write(f"{addr:#x}\t{got}\n")
    print(f"literals.tsv: {len(LITERALS)} literals")

    frames = parse_frames()
    with open(HERE / "frames.txt", "w") as f:
        f.write("# FDE ranges for every function excerpted in this packet, "
                "from\n# readelf --debug-dump=frames-interp "
                "work/hl-node-115.bin\n")
        for a, b in frames:
            f.write(f"FDE pc={a:#x}..{b:#x}\n")
    print("frames.txt:", [f"{a:#x}..{b:#x}" for a, b in frames])
    return 0


if __name__ == "__main__":
    sys.exit(main())
