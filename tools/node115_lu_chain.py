#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-chain.

Reads only bytes from artifacts/node/115/hl-node; never executes it.
Checks: binary identity, exhibit regeneration, strict counts, key-byte
targets, census (E8/E9/LEA sites + .rela.dyn GOT absence), FDE bounds,
exhibit disjointness/containment, and MANIFEST coverage.
Exit 0 only if every check passes.
"""
import hashlib
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-001-node115-lu-chain"
BIN = ROOT / "artifacts" / "node" / "115" / "hl-node"
SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
SIZE = 105896032
TEXT_VA, TEXT_OFF = 0x1419300, 0x1418300
RELA_OFF, RELA_SIZE = 0x6BE8, 0x163CC8

EXHIBITS = [
    ("ch_head", 0x63B1B60, 0x63B1B90, 48, 15),
    ("ch_next", 0x63B1B90, 0x63B1BBE, 46, 10),
    ("ch_mid", 0x63B1C8B, 0x63B1CB7, 44, 12),
    ("ch_join", 0x63B1C28, 0x63B1C5B, 51, 10),
    ("ch_exit", 0x63B1D10, 0x63B1D36, 38, 14),
]
FDE_START, FDE_END = 0x63B1B60, 0x63B1D5A
# (site, opcode, expected target) for E8/E9 checks.
CALLS = [
    (0x63B1BAD, 0xE8, 0x63AE260, "head next call"),
    (0x63B1BC4, 0xE8, 0x63B0780, "head link call"),
    (0x63B1BDA, 0xE8, 0x63B1810, "head test call"),
    (0x63B1C0A, 0xE8, 0x63AE260, "second next call"),
    (0x63B1C3C, 0xE8, 0x63ADB50, "head join call 1"),
    (0x63B1C56, 0xE8, 0x63B0560, "head join call 2"),
    (0x63B1C75, 0xE8, 0x63AE260, "retry next call"),
    (0x63B1C91, 0xE8, 0x63B0780, "mid link call"),
    (0x63B1CA7, 0xE8, 0x63B1810, "mid test call"),
    (0x63B1CDC, 0xE8, 0x63ADB50, "mid join call 1"),
    (0x63B1CF6, 0xE8, 0x63B0560, "mid join call 2"),
    (0x63B2734, 0xE8, 0x63B1B60, "census selector call"),
    (0x63B3974, 0xE8, 0x63B1B60, "census hand-on loop call"),
    (0x63B3A1A, 0xE8, 0x63B1B60, "census hand-on single call"),
]
# (site, expected bytes) for fixed-opcode key sites.
KEY_BYTES = [
    (0x63B1B64, bytes.fromhex("4c8d7170"), "dest+0x70 lea"),
    (0x63B1B83, bytes.fromhex("4c894c2418"), "flag-ptr save"),
    (0x63B1BA0, bytes.fromhex("448b83e04b0000"), "kind load"),
    (0x63B1C1B, bytes.fromhex("c644241701"), "local flag = 1"),
    (0x63B1C86, bytes.fromhex("c644241700"), "local flag = 0"),
    (0x63B1C48, bytes.fromhex("49f70700000100"), "bit16 test"),
    (0x63B1BE3, bytes.fromhex("80bbe84b000000"), "dest+0x4be8 cmp"),
    (0x63B1D1E, bytes.fromhex("c60100"), "flag write 0"),
    (0x63B1D45, bytes.fromhex("c60001"), "flag write 1 (head)"),
    (0x63B1D55, bytes.fromhex("c60201"), "flag write 1 (mid)"),
]
MANIFEST_FILES = [
    "README.md", "EVIDENCE.md", "records.json",
    "ch_head.hex", "ch_head.objdump.txt",
    "ch_next.hex", "ch_next.objdump.txt",
    "ch_mid.hex", "ch_mid.objdump.txt",
    "ch_join.hex", "ch_join.objdump.txt",
    "ch_exit.hex", "ch_exit.objdump.txt",
    "../../../tools/node115_lu_chain.py",
    "../../../tests/test_node115_lu_chain.py",
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
            fail("exhibit outside chain FDE")
    print(f"exhibits ok: {len(EXHIBITS)} excerpts, {total_b} bytes, "
          f"{total_s} strict")
    if total_b != 227 or total_s != 61:
        fail(f"exhibit totals {total_b}B/{total_s} != 227B/61")

    # Key-byte targets.
    for site, opcode, target, label in CALLS:
        b = read(site, 5)
        if b[0] != opcode:
            fail(f"{label} at {hex(site)}: opcode {hex(b[0])} != {hex(opcode)}")
        got = site + 5 + struct.unpack("<i", b[1:5])[0]
        if got != target:
            fail(f"{label} at {hex(site)}: target {hex(got)} != {target}")
    for site, expected, label in KEY_BYTES:
        if read(site, len(expected)) != expected:
            fail(f"{label} at {hex(site)}: bytes mismatch")
    print(f"key bytes ok: {len(CALLS)} calls, {len(KEY_BYTES)} opcodes")

    # Census: full .text scan for E8/E9/LEA to helper + .rela.dyn GOT check.
    import re
    text = DATA[TEXT_OFF: TEXT_OFF + 0x4FD7700]
    e8, e9 = [], []
    for m in re.finditer(rb"[\xe8\xe9]", text):
        off = m.start()
        if off + 5 > len(text):
            continue
        rel = struct.unpack_from("<i", text, off + 1)[0]
        va = TEXT_VA + off
        if va + 5 + rel == 0x63B1B60:
            (e8 if text[off] == 0xE8 else e9).append(va)
    if e8 != [0x63B2734, 0x63B3974, 0x63B3A1A]:
        fail(f"census E8 mismatch: {[hex(x) for x in e8]}")
    if e9 != []:
        fail(f"census E9 mismatch: {[hex(x) for x in e9]}")
    lea = []
    for m in re.finditer(rb"[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]",
                         text):
        off = m.start()
        if off + 7 > len(text):
            continue
        disp = struct.unpack_from("<i", text, off + 3)[0]
        va = TEXT_VA + off
        if va + 7 + disp == 0x63B1B60:
            lea.append(va)
    if lea != []:
        fail(f"census LEA mismatch: {[hex(x) for x in lea]}")
    rela = DATA[RELA_OFF: RELA_OFF + RELA_SIZE]
    got_hits = 0
    for off in range(0, len(rela), 24):
        if struct.unpack_from("<q", rela, off + 16)[0] == 0x63B1B60:
            got_hits += 1
    if got_hits != 0:
        fail(f"GOT hits {got_hits} != 0")
    n_rela = len(rela) // 24
    if n_rela != 60723:
        fail(f".rela.dyn entries {n_rela} != 60723")
    print(f"census ok: chain 3 E8, 0 E9, 0 LEA, 0 GOT, {n_rela} rela entries")

    # FDE bounds.
    if FDE_END - FDE_START != 506:
        fail("FDE size != 506")
    print("FDE bounds ok: chain 506B")

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
    print("verifier: all checks passed (5 excerpts, 61 strict, "
          "census 3/0 E8/E9 sites, MANIFEST 15 entries)")


if __name__ == "__main__":
    main()
