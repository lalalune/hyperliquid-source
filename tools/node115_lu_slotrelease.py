#!/usr/bin/env python3
"""Static verifier for the node #115 lu slot-release packet (RE-001-node115-lu-slotrelease).

Byte reads only; never executes the node binary. Checks:
- binary SHA-256 and size,
- each exhibit .hex against the binary at its VA (.text VA - 0x1000),
- strict mnemonic-line counts of each .objdump.txt excerpt,
- key instruction bytes (entry endbr64, single ret, internal call
  opcodes and rel32 targets, bitmap rol/and sites, huge-path constants),
- FDE bounds (0x63b0780..0x63b0980, 512 bytes),
- census: 4 direct E8 callers, 0 E9, 0 LEA, 0 GOT (60,723 .rela.dyn entries),
- MANIFEST.sha256 coverage (15 entries, MANIFEST itself excluded).
"""

import hashlib
import json
import os
import re
import struct
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(REPO, "research", "work-items", "RE-001-node115-lu-slotrelease")
NODE = os.path.join(REPO, "artifacts", "node", "115", "hl-node")

TARGET_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET_SIZE = 105896032

RELEASE_START = 0x63B0780
RELEASE_END = 0x63B0980
RET_SITE = 0x63B08CF
CALLERS = (0x63B1BC4, 0x63B1C91, 0x63B26F1, 0x63B47CA)
INTERNAL_CALLS = {
    0x63B07A6: 0x63E8BF0,
    0x63B0847: 0x63ACB40,
    0x63B084F: 0x63ABCF0,
    0x63B0912: 0x63ABD00,
}

EXHIBITS = {
    "sr_entry": (0x63B0780, 0x63B07AE, 46, 15),
    "sr_index": (0x63B07C1, 0x63B07F7, 54, 15),
    "sr_acct": (0x63B0811, 0x63B0854, 67, 18),
    "sr_clear": (0x63B0854, 0x63B087C, 40, 9),
    "sr_cache": (0x63B08D0, 0x63B092B, 91, 24),
}

INSN_RE = re.compile(r"\s*[0-9a-f]+:\t[0-9a-f ]+\t(\S+)")
LEA_RE = re.compile(rb"\x48\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]")


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


def text_off(va):
    return va - 0x1000


def main():
    with open(NODE, "rb") as f:
        data = f.read()
    if len(data) != TARGET_SIZE:
        fail(f"binary size {len(data)} != {TARGET_SIZE}")
    sha = hashlib.sha256(data).hexdigest()
    if sha != TARGET_SHA:
        fail(f"binary sha {sha} != {TARGET_SHA}")
    print(f"binary sha ok ({len(data)} bytes)")

    total_bytes = 0
    total_strict = 0
    for name, (start, end, nbytes, strict) in EXHIBITS.items():
        with open(os.path.join(PACKET, name + ".hex")) as f:
            hexs = "".join(f.read().split())
        raw = bytes.fromhex(hexs)
        if len(raw) != nbytes:
            fail(f"{name}: hex length {len(raw)} != {nbytes}")
        got = data[text_off(start):text_off(end)]
        if got != raw:
            fail(f"{name}: bytes differ from binary at {hex(start)}")
        with open(os.path.join(PACKET, name + ".objdump.txt")) as f:
            lines = f.read().splitlines()
        count = sum(1 for line in lines if INSN_RE.match(line))
        if count != strict:
            fail(f"{name}: strict count {count} != {strict}")
        total_bytes += nbytes
        total_strict += strict
    print(f"exhibits ok: {len(EXHIBITS)} excerpts, {total_bytes} bytes, "
          f"{total_strict} strict")

    # Key bytes.
    if data[text_off(RELEASE_START):text_off(RELEASE_START) + 4] != bytes.fromhex("f30f1efa"):
        fail("entry is not endbr64")
    if data[text_off(RET_SITE)] != 0xC3:
        fail("single ret missing at 0x63b08cf")
    for site, target in INTERNAL_CALLS.items():
        off = text_off(site)
        if data[off] != 0xE8:
            fail(f"internal call {hex(site)} is not E8")
        rel = struct.unpack("<i", data[off + 1:off + 5])[0]
        if site + 5 + rel != target:
            fail(f"internal call {hex(site)} does not target {hex(target)}")
    # Bitmap clear: rol at 0x63b0867, and at 0x63b086a.
    if data[text_off(0x63B0867):text_off(0x63B0867) + 3] != bytes.fromhex("49d3c5"):
        fail("bitmap rol missing at 0x63b0867")
    if data[text_off(0x63B086A):text_off(0x63B086A) + 4] != bytes.fromhex("4e216cfd"):
        fail("bitmap and missing at 0x63b086a")
    # Huge path constants at 0x63b0950.
    if data[text_off(0x63B0950):text_off(0x63B0950) + 6] != bytes.fromhex("41b998250000"):
        fail("huge-path r9d constant missing at 0x63b0950")
    if data[text_off(0x63B0962):text_off(0x63B0962) + 6] != bytes.fromhex("41bfc7000000"):
        fail("huge-path r15d constant missing at 0x63b0962")
    for site in CALLERS:
        off = text_off(site)
        if data[off] != 0xE8:
            fail(f"caller {hex(site)} is not E8")
        rel = struct.unpack("<i", data[off + 1:off + 5])[0]
        if site + 5 + rel != RELEASE_START:
            fail(f"caller {hex(site)} does not target release helper")
    print(f"key bytes ok: {len(CALLERS)} sites")
    print(f"key calls ok: {len(INTERNAL_CALLS)} calls inside FDE")

    # FDE bounds.
    if RELEASE_END - RELEASE_START != 512:
        fail("FDE length mismatch")
    print("FDE bounds ok: release 512B")

    # Census: whole executable-segment E8/E9/LEA scan.
    # Exec segment: file offset 0x1418300, VA 0x1419300, size 0x4fd7700
    # (VA = file offset + 0x1000 throughout, matching .text VA - 0x1000).
    seg_off, seg_va, seg_size = 0x1418300, 0x1419300, 0x4FD7700
    seg = data[seg_off:seg_off + seg_size]
    e8 = []
    i = seg.find(b"\xe8")
    while i != -1:
        if i + 5 <= len(seg):
            rel = struct.unpack("<i", seg[i + 1:i + 5])[0]
            site = seg_va + i
            if site + 5 + rel == RELEASE_START:
                e8.append(site)
        i = seg.find(b"\xe8", i + 1)
    e9 = []
    i = seg.find(b"\xe9")
    while i != -1:
        if i + 5 <= len(seg):
            rel = struct.unpack("<i", seg[i + 1:i + 5])[0]
            site = seg_va + i
            if site + 5 + rel == RELEASE_START:
                e9.append(site)
        i = seg.find(b"\xe9", i + 1)
    lea = []
    for m in LEA_RE.finditer(seg):
        i = m.start()
        rel = struct.unpack("<i", seg[i + 3:i + 7])[0]
        site = seg_va + i
        if site + 7 + rel == RELEASE_START:
            lea.append(site)
    if sorted(e8) != sorted(CALLERS):
        fail(f"census E8 mismatch: {[hex(s) for s in e8]}")
    if e9 or lea:
        fail(f"census E9/LEA nonzero: {[hex(s) for s in e9 + lea]}")
    # GOT census via .rela.dyn addends (file offset 0x6be8, size 0x163cc8).
    rela_off, rela_size = 0x6BE8, 0x163CC8
    nrela = rela_size // 0x18
    got = 0
    for i in range(nrela):
        r_add = struct.unpack("<q", data[rela_off + i * 0x18 + 16:rela_off + i * 0x18 + 24])[0]
        if r_add == RELEASE_START:
            got += 1
    if got != 0:
        fail(f"census GOT nonzero: {got}")
    print(f"census ok: release {len(e8)} E8, 0 E9, 0 LEA, 0 GOT, "
          f"{nrela} rela entries")

    # MANIFEST coverage.
    import hashlib as _hl
    manifest = os.path.join(PACKET, "MANIFEST.sha256")
    entries = []
    with open(manifest) as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            digest, _, path = line.partition("  ")
            entries.append((digest, path))
    if len(entries) != 15:
        fail(f"MANIFEST entries {len(entries)} != 15")
    for digest, path in entries:
        if path == "MANIFEST.sha256":
            fail("MANIFEST lists itself")
        if path.startswith("../../../"):
            full = os.path.join(REPO, path[9:])
        else:
            full = os.path.join(PACKET, path)
        with open(full, "rb") as f:
            actual = _hl.sha256(f.read()).hexdigest()
        if actual != digest:
            fail(f"MANIFEST mismatch: {path}")
    print("MANIFEST ok: 15/15 entries")

    print(f"verifier: all checks passed ({len(EXHIBITS)} excerpts, "
          f"{total_bytes} bytes, {total_strict} strict, census "
          f"{len(e8)} E8 sites, MANIFEST 15 entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
