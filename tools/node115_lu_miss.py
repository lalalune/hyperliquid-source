#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-miss (packet #215).

Checks, against node #115 only (never executes the binary):
  - binary SHA-256 / size
  - the 5 claimed excerpts (hex bytes + objdump lines + strict counts)
  - exact key bytes for claims outside the excerpts
  - call targets for the census spot sites and key callees
  - whole-file census for the miss handler
    (E8/E9 byte scan + records.json site list, LEA forms, .rela.dyn addends)
  - FDE bounds from .eh_frame (objdump --dwarf=frames)
  - MANIFEST.sha256 coverage

Exit 0 only when every check passes.
"""

import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
BIN = REPO / "artifacts" / "node" / "115" / "hl-node"
PACKET = REPO / "research" / "work-items" / "RE-001-node115-lu-miss"

EXPECT_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
EXPECT_SIZE = 105896032

# (name, start VA, end VA, strict mnemonics)
EXCERPTS = [
    ("mh_head", 0x63D9700, 0x63D9739, 18),
    ("mh_fast", 0x63D9830, 0x63D984F, 8),
    ("mh_insert", 0x63D9745, 0x63D97A1, 18),
    ("mh_lock", 0x63D97B5, 0x63D97D7, 9),
    ("mh_alloc", 0x63D97F3, 0x63D9813, 9),
]

# Exact bytes for claims outside the excerpts: (VA, hex).
KEY_BYTES = [
    (0x63D97AF, "c3"),                # handler: ret
    (0x63D97D7, "4983464001"),        # addq $1,0x40(%r14) (acquisitions)
    (0x63D97DC, "4d3b4638"),          # cmp 0x38(%r14),%r8 (last thread)
    (0x63D97E2, "4983463001"),        # addq $1,0x30(%r14) (switches)
    (0x63D97E7, "4d894638"),          # mov %r8,0x38(%r14)
    (0x63D97EB, "4d8b2f"),            # mov (%r15),%r13 (slot re-read)
    (0x63D9810, "498907"),            # mov %rax,(%r15) (slot install)
    (0x63D9813, "41c6467000"),        # movb $0x0,0x70(%r14) (success exit)
    (0x63D9848, "31c0"),              # xor %eax,%eax (strict NULL)
    (0x63D9857, "41c6467001"),        # movb $0x1,0x70(%r14) (contended)
    (0x63D9866, "41c6467000"),        # movb $0x0,0x70(%r14) (alloc-fail exit)
    (0x63D9874, "31c0"),              # xor %eax,%eax (alloc-fail NULL)
    (0x63AE248, "e9a0fdffff"),        # worker: jmp 0x63adfed (re-entry)
]

# (call site VA, expected target VA)
KEY_CALLS = [
    (0x63D9761, 0x63F0A70),   # handler -> memmove@plt
    (0x63D97C9, 0x63F17B0),   # handler -> pthread_mutex_trylock@plt
    (0x63D981C, 0x63F0B70),   # handler -> pthread_mutex_unlock@plt
    (0x63D986F, 0x63F0B70),   # handler -> pthread_mutex_unlock@plt
    (0x63D9852, 0x63BF680),   # handler -> contention helper
    (0x63D9803, 0x636B370),   # handler -> allocator
    (0x63AE239, 0x63D9700),   # worker -> miss handler
    (0x63ADE8D, 0x63D9700),   # census spot: sibling lookup
    (0x63AE627, 0x63D9700),   # census spot: alloc-mode site
    (0x634976B, 0x63D9700),   # census spot: insert-mode site
    (0x63EDEF6, 0x63D9700),   # census spot: insert-mode site
]

TARGET = 0x63D9700
EXPECT_E8 = 168


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def read_va(va, n):
    with open(BIN, "rb") as f:
        f.seek(va - 0x1000)
        return f.read(n)


def objdump_lines(start, stop):
    out = subprocess.run(
        ["objdump", "-d", f"--start-address={hex(start)}",
         f"--stop-address={hex(stop)}", str(BIN)],
        capture_output=True, text=True, check=True).stdout
    lines = []
    strict = 0
    for line in out.splitlines():
        m = re.match(r"\s*([0-9a-f]+):\t([0-9a-f ]+)\t(\S.*)?$", line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        if not (start <= addr < stop):
            continue
        lines.append(line.strip())
        if m.group(3):
            strict += 1
    return lines, strict


def check_binary():
    data = open(BIN, "rb").read()
    sha = hashlib.sha256(data).hexdigest()
    if sha != EXPECT_SHA:
        fail(f"binary sha {sha} != {EXPECT_SHA}")
    if len(data) != EXPECT_SIZE:
        fail(f"binary size {len(data)} != {EXPECT_SIZE}")
    print(f"binary sha ok ({EXPECT_SIZE} bytes)")
    return data


def check_excerpts():
    total_bytes = 0
    total_strict = 0
    for name, start, stop, strict in EXCERPTS:
        raw = read_va(start, stop - start)
        claimed = bytes.fromhex(
            (PACKET / f"{name}.hex").read_text().split()[0])
        if raw != claimed:
            fail(f"{name}: binary bytes != {name}.hex")
        lines, got_strict = objdump_lines(start, stop)
        stored = (PACKET / f"{name}.objdump.txt").read_text().splitlines()
        if lines != stored:
            fail(f"{name}: objdump lines != {name}.objdump.txt")
        if got_strict != strict:
            fail(f"{name}: strict {got_strict} != {strict}")
        total_bytes += stop - start
        total_strict += strict
    print(f"exhibits ok: {len(EXCERPTS)} excerpts, {total_bytes} bytes, "
          f"{total_strict} strict")
    return total_bytes, total_strict


def check_key_bytes():
    for va, hx in KEY_BYTES:
        got = read_va(va, len(bytes.fromhex(hx))).hex()
        if got != hx:
            fail(f"key bytes at {hex(va)}: {got} != {hx}")
    print(f"key bytes ok: {len(KEY_BYTES)} sites")


def check_key_calls():
    for site, target in KEY_CALLS:
        raw = read_va(site, 5)
        if raw[0] != 0xE8:
            fail(f"call at {hex(site)} is not E8")
        got = site + 5 + struct.unpack("<i", raw[1:5])[0]
        if got != target:
            fail(f"call at {hex(site)} -> {hex(got)} != {hex(target)}")
    print(f"key calls ok: {len(KEY_CALLS)} calls")


def scan_targets(data, op):
    t_off = TARGET - 0x1000
    hits = []
    i = data.find(bytes([op]))
    while i != -1:
        rel = struct.unpack("<i", data[i + 1:i + 5])[0]
        if i + 5 + rel == t_off:
            hits.append(i + 0x1000)
        i = data.find(bytes([op]), i + 1)
    return hits


def check_census(data):
    e8 = scan_targets(data, 0xE8)
    if len(e8) != EXPECT_E8:
        fail(f"census E8 {len(e8)} != {EXPECT_E8}")
    e9 = scan_targets(data, 0xE9)
    if e9:
        fail(f"census E9 nonzero: {[hex(h) for h in e9]}")
    # RIP-relative LEA forms: REX 48/4c, 8d, modrm 05/0d/15/1d/25/2d/35/3d.
    lea = []
    t_off = TARGET - 0x1000
    for rex in (0x48, 0x4C):
        for modrm in (0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D):
            pat = bytes([rex, 0x8D, modrm])
            i = data.find(pat)
            while i != -1:
                disp = struct.unpack("<i", data[i + 3:i + 7])[0]
                if i + 7 + disp == t_off:
                    lea.append(i + 0x1000)
                i = data.find(pat, i + 1)
    if lea:
        fail(f"census LEA nonzero: {[hex(h) for h in lea]}")
    # records.json site list must match the scan exactly.
    rec = json.loads((PACKET / "records.json").read_text())
    listed = sorted(int(s, 16) for s in rec["census_e8_sites"])
    if listed != sorted(e8):
        fail("records.json census_e8_sites != byte-scan sites")
    # .rela.dyn addends.
    out = subprocess.run(["readelf", "-r", str(BIN)],
                         capture_output=True, text=True, check=True).stdout
    m = re.search(r"Relocation section '\.rela\.dyn' at offset .* "
                  r"contains (\d+) entries", out)
    if not m or int(m.group(1)) != rec["census"]["rela_dyn_entries"]:
        fail(".rela.dyn entry count mismatch")
    if "63d9700" in out:
        fail(".rela.dyn mentions handler address")
    print(f"census ok: handler {EXPECT_E8} E8, 0 E9/LEA/GOT, "
          f"{rec['census']['rela_dyn_entries']} rela entries")


def check_fde():
    out = subprocess.run(
        ["objdump", "--dwarf=frames", str(BIN)],
        capture_output=True, text=True, check=True).stdout
    if "pc=00000000063d9700..00000000063d987b" not in out:
        fail("FDE bounds 0x63d9700..0x63d987b not found")
    print("FDE bounds ok: handler 379B")


def check_manifest():
    out = subprocess.run(
        ["sha256sum", "-c", "MANIFEST.sha256"],
        cwd=str(PACKET), capture_output=True, text=True)
    if out.returncode != 0:
        fail(f"MANIFEST check failed:\n{out.stdout}\n{out.stderr}")
    entries = [l for l in out.stdout.splitlines() if l.strip()]
    if len(entries) != 15:
        fail(f"MANIFEST entries {len(entries)} != 15")
    print("MANIFEST ok: 15/15 entries")


def main():
    data = check_binary()
    nbytes, nstrict = check_excerpts()
    check_key_bytes()
    check_key_calls()
    check_census(data)
    check_fde()
    check_manifest()
    print(f"verifier: all checks passed ({len(EXCERPTS)} excerpts, "
          f"{nbytes} bytes, {nstrict} strict, census {EXPECT_E8} E8 sites, "
          f"MANIFEST 15 entries)")


if __name__ == "__main__":
    main()
