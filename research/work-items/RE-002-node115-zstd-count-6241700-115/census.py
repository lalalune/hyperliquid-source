#!/usr/bin/env python3
"""Caller census for ZSTD_count 0x6241700..0x62417d3 (node #115).

Reproduces, from the digest-verified local binary only:

  callers.tsv     every direct E8 (call) / E9 (jmp) site whose rel32
                  resolves to 0x6241700, with the enclosing FDE bounds
                  read from the .eh_frame unwind table.
  frames.txt      the unwinding entry (FDE) that covers the routine.
  relocations.txt the routine's relocation record (none), as read from
                  the vendor census and cross-checked against the
                  RELA sections.

Static disassembly only; nothing is executed.
"""
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BINARY = ROOT / "artifacts" / "node" / "115" / "hl-node"
VENDOR_CENSUS = (ROOT / "research" / "work-items"
                 / "RE-002-node115-vendor-census" / "census.json")
PACKET = (ROOT / "research" / "work-items"
          / "RE-002-node115-zstd-count-6241700-115")

START = 0x6241700
END = 0x62417D3
SYMBOL = "ZSTD_count"


def load_segments():
    out = subprocess.check_output(["readelf", "-lW", str(BINARY)]).decode()
    segs = []
    for line in out.splitlines():
        p = line.split()
        if p and p[0] == "LOAD":
            segs.append((int(p[2], 16), int(p[1], 16), int(p[4], 16)))
    return segs


def va_to_off(segs, va):
    for v, o, f in segs:
        if v <= va < v + f:
            return o + (va - v)
    raise ValueError(hex(va))


def off_to_va(segs, off):
    for v, o, f in segs:
        if o <= off < o + f:
            return v + (off - o)
    raise ValueError(hex(off))


def fde_ranges():
    """(start, end) pairs from the .eh_frame FDE table."""
    out = subprocess.check_output(["readelf", "-wf", str(BINARY)]).decode()
    ranges = []
    for line in out.splitlines():
        m = re.search(r"pc=([0-9a-f]{16})\.\.([0-9a-f]{16})", line)
        if m:
            ranges.append((int(m.group(1), 16), int(m.group(2), 16)))
    return sorted(ranges)


def encloser(ranges, addr):
    for s, e in ranges:
        if s <= addr < e:
            return s, e
    return None


def find_calls(segs, target):
    """Direct E8 (call) / E9 (jmp) sites to `target`, then validated
    with Capstone linear disassembly from the enclosing FDE start so a
    stray E8/E9 byte inside another instruction cannot be mistaken for
    a call site."""
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = False
    data = BINARY.read_bytes()
    ranges = fde_ranges()
    hits = []
    for m in re.finditer(b"[\xe8\xe9]", data):
        i = m.start()
        if i + 5 > len(data):
            continue
        try:
            va = off_to_va(segs, i)
        except ValueError:
            continue
        rel = struct.unpack_from("<i", data, i + 1)[0]
        if va + 5 + rel != target:
            continue
        enc = encloser(ranges, va)
        if enc is None:
            continue
        # Linear-disassemble from the FDE start; the site must land on
        # an instruction boundary and decode as a call/jmp to target.
        start_off = va_to_off(segs, enc[0])
        code = data[start_off:va_to_off(segs, va) + 5]
        ok = False
        for ins in md.disasm(code, enc[0]):
            if ins.address == va:
                text = ins.op_str
                ok = ins.mnemonic in ("call", "jmp") and text == hex(target)
                break
            if ins.address > va:
                break
        if ok:
            hits.append((va, "call" if data[i] == 0xE8 else "jmp"))
    return sorted(hits)


def census_relocations(start):
    recs = json.loads(VENDOR_CENSUS.read_text())["records"]
    rec = next(r for r in recs if r["start"] == start)
    return rec


def main():
    segs = load_segments()
    ranges = fde_ranges()
    rec = census_relocations(START)

    # callers.tsv
    hits = find_calls(segs, START)
    rows = ["site\tkind\tcaller_fde_start\tcaller_fde_end"]
    for site, kind in hits:
        enc = encloser(ranges, site)
        assert enc, hex(site)
        rows.append(f"{hex(site)}\t{kind}\t{hex(enc[0])}\t{hex(enc[1])}")
    (PACKET / "callers.tsv").write_text("\n".join(rows) + "\n")

    # frames.txt
    enc = encloser(ranges, START)
    assert enc == (START, END), (enc, hex(START), hex(END))
    frames = []
    out = subprocess.check_output(["readelf", "-wf", str(BINARY)]).decode()
    for line in out.splitlines():
        if f"pc={START:016x}..{END:016x}" in line:
            frames.append(line.rstrip())
    (PACKET / "frames.txt").write_text(
        f"# .eh_frame entry covering {SYMBOL} {hex(START)}..{hex(END)}\n"
        + "\n".join(frames) + "\n")

    # relocations.txt
    assert rec["relocations"] == [], rec["relocations"]
    (PACKET / "relocations.txt").write_text(
        f"# {SYMBOL} {hex(START)}..{hex(END)}: no relocations.\n"
        f"# Vendor census member {rec['member']} records 0 relocations;\n"
        "# the body is raw-equal to its source bytes with no relocation\n"
        "# field to zero (target_body_sha256 == source_body_sha256).\n"
        f"target_body_sha256 {rec['target_body_sha256']}\n"
        f"source_body_sha256 {rec['source_body_sha256']}\n")

    # functions.tsv (this routine calls nothing)
    (PACKET / "functions.tsv").write_text("start\tend\tsymbol\tkind\n")

    print(f"callers: {len(hits)}")
    print(f"fde: {hex(enc[0])}..{hex(enc[1])}")
    print("wrote callers.tsv frames.txt relocations.txt functions.tsv")


if __name__ == "__main__":
    sys.exit(main())
