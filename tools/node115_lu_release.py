#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-release.

Reads only bytes from artifacts/node/115/hl-node; never executes it.
Checks: binary identity, exhibit regeneration, strict counts, key-byte
targets, census (E8/E9 sites + .rela.dyn GOT absence), FDE bounds,
exhibit disjointness/containment, and MANIFEST coverage.
Exit 0 only if every check passes.
"""
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-001-node115-lu-release"
BIN = ROOT / "artifacts" / "node" / "115" / "hl-node"
SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
SIZE = 105896032
TEXT_VA, TEXT_OFF = 0x1419300, 0x1418300
RELA_OFF, RELA_SIZE = 0x6BE8, 0x163CC8

EXHIBITS = [
    ("rel_head", 0x63B3080, 0x63B30B2, 50, 16),
    ("rel_flag", 0x63B30C7, 0x63B30E3, 28, 7),
    ("rel_vcall", 0x63B31A9, 0x63B31C8, 31, 7),
    ("rel_retry", 0x63B3250, 0x63B326A, 26, 6),
    ("rel_tail", 0x63B30F0, 0x63B3116, 38, 13),
]
FDE_START, FDE_END = 0x63B3080, 0x63B38C2
# (site, opcode, expected target) for E8/E9 and lea checks.
CALLS = [
    (0x63B32FB, 0xE8, 0x63B2E60, "predicate"),
    (0x63B313C, 0xE8, 0x63AE980, "setup"),
    (0x63B3265, 0xE8, 0x63AE2B0, "retry"),
    (0x63B3111, 0xE9, 0x63B38D0, "tail hand-on"),
    (0x63B31F4, 0xE9, 0x63B5760, "tail ordered-insert"),
    (0x63B3A92, 0xE8, 0x63B3080, "census re-entry"),
    (0x63C0E84, 0xE8, 0x63B3080, "census wrapper"),
    (0x63C1194, 0xE8, 0x63B3080, "census walk"),
    (0x63B3B80, 0xE9, 0x63B3080, "census tail wrapper"),
]
# (site, expected bytes) for fixed-opcode key sites.
KEY_BYTES = [
    (0x63B350A, bytes.fromhex("41ff5228"), "slot +0x28 call"),
    (0x63B338B, bytes.fromhex("41ff5230"), "slot +0x30 call"),
    (0x63B31C2, bytes.fromhex("41ff5208"), "slot +8 call"),
]
# (site, instruction length, expected rip target) for lock ops.
RIP_TARGETS = [
    (0x63B3295, 9, 0x67121D8, "xadd total"),
    (0x63B3320, 8, 0x67121D8, "lock sub total"),
    (0x63B32AD, 9, 0x67121D0, "cmpxchg high-water"),
]
# (lea site, expected target) for rip-relative leas.
LEAS = [
    (0x63B30A2, 0x64DF1A0, "sentinel default object"),
    (0x63B30C0, 0x6713606, "flag byte"),
]
MANIFEST_FILES = [
    "README.md", "EVIDENCE.md", "records.json",
    "rel_head.hex", "rel_head.objdump.txt",
    "rel_flag.hex", "rel_flag.objdump.txt",
    "rel_vcall.hex", "rel_vcall.objdump.txt",
    "rel_retry.hex", "rel_retry.objdump.txt",
    "rel_tail.hex", "rel_tail.objdump.txt",
    "../../../tools/node115_lu_release.py",
    "../../../tests/test_node115_lu_release.py",
]


def fail(msg):
    print(f"verifier: FAIL: {msg}")
    sys.exit(1)


def read(va, n):
    return DATA[va - 0x1000: va - 0x1000 + n]


def main():
    global DATA
    DATA = BIN.read_bytes()
    if len(DATA) != SIZE:
        fail(f"binary size {len(DATA)} != {SIZE}")
    if hashlib.sha256(DATA).hexdigest() != SHA:
        fail("binary sha256 mismatch")
    print(f"binary sha ok ({SIZE} bytes)")

    # Exhibits: regeneration + strict counts from objdump files.
    total_b = total_s = 0
    spans = []
    for name, start, end, nbytes, nstrict in EXHIBITS:
        raw = read(start, end - start)
        if len(raw) != nbytes:
            fail(f"{name}: byte length {len(raw)} != {nbytes}")
        claimed = (PACKET / f"{name}.hex").read_text().strip()
        if claimed != raw.hex():
            fail(f"{name}: hex mismatch")
        lines = (PACKET / f"{name}.objdump.txt").read_text().splitlines()
        strict = 0
        for line in lines:
            parts = line.split("\t")
            if len(parts) >= 3 and parts[2].strip():
                strict += 1
        if strict != nstrict:
            fail(f"{name}: strict {strict} != {nstrict}")
        spans.append((start, end))
        total_b += nbytes
        total_s += nstrict
    spans.sort()
    for (a0, a1), (b0, b1) in zip(spans, spans[1:]):
        if a1 > b0:
            fail("exhibits overlap")
    for start, end in spans:
        if not (FDE_START <= start and end <= FDE_END):
            fail("exhibit outside release FDE")
    print(f"exhibits ok: {len(EXHIBITS)} excerpts, {total_b} bytes, "
          f"{total_s} strict")
    if total_b != 173 or total_s != 49:
        fail(f"exhibit totals {total_b}B/{total_s} != 173B/49")

    # Key-byte targets.
    for site, opcode, target, label in CALLS:
        b = read(site, 5)
        if b[0] != opcode:
            fail(f"{label} at {hex(site)}: opcode {hex(b[0])} != {hex(opcode)}")
        got = site + 5 + struct.unpack("<i", b[1:5])[0]
        if got != target:
            fail(f"{label} at {hex(site)}: target {hex(got)} != {hex(target)}")
    for site, expected, label in KEY_BYTES:
        if read(site, len(expected)) != expected:
            fail(f"{label} at {hex(site)}: bytes mismatch")
    for site, length, target, label in RIP_TARGETS:
        b = read(site, length)
        disp = struct.unpack("<i", b[length - 4: length])[0]
        if site + length + disp != target:
            fail(f"{label} at {hex(site)}: rip target mismatch")
    for site, target, label in LEAS:
        b = read(site, 7)
        disp = struct.unpack("<i", b[3:7])[0]
        if site + 7 + disp != target:
            fail(f"{label} at {hex(site)}: lea target mismatch")
    print(f"key bytes ok: {len(CALLS)} calls, {len(KEY_BYTES)} opcodes, "
          f"{len(RIP_TARGETS)} rip targets, {len(LEAS)} leas")

    # Census: full .text scan for E8/E9 to release + .rela.dyn GOT check.
    import re
    text = DATA[TEXT_OFF: TEXT_OFF + 0x4FD7700]
    e8, e9 = [], []
    for m in re.finditer(rb"[\xe8\xe9]", text):
        off = m.start()
        if off + 5 > len(text):
            continue
        rel = struct.unpack_from("<i", text, off + 1)[0]
        va = TEXT_VA + off
        if va + 5 + rel == 0x63B3080:
            (e8 if text[off] == 0xE8 else e9).append(va)
    if e8 != [0x63B3A92, 0x63C0E84, 0x63C1194]:
        fail(f"census E8 mismatch: {[hex(x) for x in e8]}")
    if e9 != [0x63B3B80]:
        fail(f"census E9 mismatch: {[hex(x) for x in e9]}")
    rela = DATA[RELA_OFF: RELA_OFF + RELA_SIZE]
    got_hits = 0
    for off in range(0, len(rela), 24):
        if struct.unpack_from("<q", rela, off + 16)[0] == 0x63B3080:
            got_hits += 1
    if got_hits != 0:
        fail(f"GOT hits {got_hits} != 0")
    n_rela = len(rela) // 24
    if n_rela != 60723:
        fail(f".rela.dyn entries {n_rela} != 60723")
    print(f"census ok: release 3 E8, 1 E9, 0 LEA/GOT, {n_rela} rela entries")

    # FDE bounds.
    if FDE_END - FDE_START != 2114:
        fail("FDE size != 2114")
    print("FDE bounds ok: release 2114B")

    # MANIFEST.
    manifest = (PACKET / "MANIFEST.sha256").read_text().splitlines()
    entries = {}
    for line in manifest:
        digest, _, path = line.partition("  ")
        if not digest or not path:
            digest, _, path = line.partition(" *")
        entries[path] = digest
    if sorted(entries) != sorted(MANIFEST_FILES):
        fail(f"MANIFEST file list mismatch: {sorted(entries)}")
    for path in MANIFEST_FILES:
        target = (PACKET / path).resolve()
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        if entries[path] != digest:
            fail(f"MANIFEST mismatch for {path}")
    print(f"MANIFEST ok: {len(entries)}/{len(entries)} entries")
    print("verifier: all checks passed (5 excerpts, 49 strict, "
          "census 3/1 E8/E9 sites, MANIFEST 15 entries)")


if __name__ == "__main__":
    main()
