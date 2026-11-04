#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-handon.

Reads only bytes from artifacts/node/115/hl-node; never executes it.
Checks: binary identity, exhibit regeneration, strict counts, key-byte
targets, census (E8/E9 sites + .rela.dyn GOT absence), FDE bounds,
exhibit disjointness/containment, and MANIFEST coverage.
Exit 0 only if every check passes.
"""
import hashlib
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-001-node115-lu-handon"
BIN = ROOT / "artifacts" / "node" / "115" / "hl-node"
SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
SIZE = 105896032
TEXT_VA, TEXT_OFF = 0x1419300, 0x1418300
RELA_OFF, RELA_SIZE = 0x6BE8, 0x163CC8

EXHIBITS = [
    ("ho_lock", 0x63B38D0, 0x63B3929, 89, 26),
    ("ho_loop", 0x63B3960, 0x63B3983, 35, 10),
    ("ho_join", 0x63B39A0, 0x63B39D7, 55, 11),
    ("ho_reenter", 0x63B3A76, 0x63B3A97, 33, 9),
    ("ho_acct", 0x63B3A97, 0x63B3ACD, 54, 9),
]
FDE_START, FDE_END = 0x63B38D0, 0x63B3AF1
# (site, opcode, expected target) for E8/E9 checks.
CALLS = [
    (0x63B3908, 0xE8, 0x63F17B0, "trylock PLT"),
    (0x63B3974, 0xE8, 0x63B1B60, "chain call"),
    (0x63B39B4, 0xE8, 0x63ADB50, "join call 1"),
    (0x63B39D2, 0xE8, 0x63B0560, "join call 2"),
    (0x63B3A1A, 0xE8, 0x63B1B60, "single call"),
    (0x63B3A33, 0xE8, 0x63BF680, "wait helper"),
    (0x63B3A50, 0xE8, 0x63C1C40, "probe 1"),
    (0x63B3A67, 0xE8, 0x63C1C40, "probe 2"),
    (0x63B3A7D, 0xE8, 0x63F0B70, "unlock call"),
    (0x63B3A92, 0xE8, 0x63B3080, "re-entry"),
    (0x63B3A00, 0xE9, 0x63F0B70, "unlock tail"),
    (0x63B3111, 0xE9, 0x63B38D0, "census release tail"),
    (0x63B3B13, 0xE9, 0x63B38D0, "census shim tail"),
]
# (site, expected bytes) for fixed-opcode key sites.
KEY_BYTES = [
    (0x63B3929, bytes.fromhex("49f70700000100"), "bit16 test"),
    (0x63B3932, bytes.fromhex("80bbe84b000000"), "dest+0x4be8 cmp"),
    (0x63B3949, bytes.fromhex("483dff3f0000"), "size cmp 0x3fff"),
    (0x63B39D7, bytes.fromhex("c6436800"), "flag clear"),
    (0x63B3B04, bytes.fromhex("4981600800f0ffff"), "shim andq node+8"),
    (0x63B3B0C, bytes.fromhex("498120ff7fffff"), "shim andq node[0]"),
]
MANIFEST_FILES = [
    "README.md", "EVIDENCE.md", "records.json",
    "ho_lock.hex", "ho_lock.objdump.txt",
    "ho_loop.hex", "ho_loop.objdump.txt",
    "ho_join.hex", "ho_join.objdump.txt",
    "ho_reenter.hex", "ho_reenter.objdump.txt",
    "ho_acct.hex", "ho_acct.objdump.txt",
    "../../../tools/node115_lu_handon.py",
    "../../../tests/test_node115_lu_handon.py",
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
            fail("exhibit outside hand-on FDE")
    print(f"exhibits ok: {len(EXHIBITS)} excerpts, {total_b} bytes, "
          f"{total_s} strict")
    if total_b != 266 or total_s != 65:
        fail(f"exhibit totals {total_b}B/{total_s} != 266B/65")

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
    print(f"key bytes ok: {len(CALLS)} calls, {len(KEY_BYTES)} opcodes")

    # Census: full .text scan for E8/E9 to hand-on + .rela.dyn GOT check.
    import re
    text = DATA[TEXT_OFF: TEXT_OFF + 0x4FD7700]
    e8, e9 = [], []
    for m in re.finditer(rb"[\xe8\xe9]", text):
        off = m.start()
        if off + 5 > len(text):
            continue
        rel = struct.unpack_from("<i", text, off + 1)[0]
        va = TEXT_VA + off
        if va + 5 + rel == 0x63B38D0:
            (e8 if text[off] == 0xE8 else e9).append(va)
    if e8 != [0x63B4AA1, 0x63B5186, 0x63B51A5, 0x63B545D, 0x63B54D8, 0x63C1F15]:
        fail(f"census E8 mismatch: {[hex(x) for x in e8]}")
    if e9 != [0x63B3111, 0x63B3B13]:
        fail(f"census E9 mismatch: {[hex(x) for x in e9]}")
    rela = DATA[RELA_OFF: RELA_OFF + RELA_SIZE]
    got_hits = 0
    for off in range(0, len(rela), 24):
        if struct.unpack_from("<q", rela, off + 16)[0] == 0x63B38D0:
            got_hits += 1
    if got_hits != 0:
        fail(f"GOT hits {got_hits} != 0")
    n_rela = len(rela) // 24
    if n_rela != 60723:
        fail(f".rela.dyn entries {n_rela} != 60723")
    print(f"census ok: hand-on 6 E8, 2 E9, 0 LEA/GOT, {n_rela} rela entries")

    # FDE bounds.
    if FDE_END - FDE_START != 545:
        fail("FDE size != 545")
    print("FDE bounds ok: hand-on 545B")

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
    print("verifier: all checks passed (5 excerpts, 65 strict, "
          "census 6/2 E8/E9 sites, MANIFEST 15 entries)")


if __name__ == "__main__":
    main()
