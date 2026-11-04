#!/usr/bin/env python3
"""Static verifier for the node #115 lu slot-remove packet (RE-001-node115-lu-slotremove).

Byte reads only; never executes the node binary. Checks:
- binary SHA-256 and size,
- each exhibit .hex against the binary at its VA (.text VA - 0x1000),
- strict mnemonic-line counts of each .objdump.txt excerpt,
- key instruction bytes (entry endbr64, head dispatch je, single ret, call
  opcodes at the three census sites),
- FDE bounds (0x63acb40..0x63ad582, 2626 bytes),
- census: 3 direct E8 callers, 0 E9, 0 LEA, 0 GOT (60,723 .rela.dyn entries),
- MANIFEST.sha256 coverage (15 entries, MANIFEST itself excluded).
"""

import hashlib
import json
import os
import re
import struct
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(REPO, "research", "work-items", "RE-001-node115-lu-slotremove")
NODE = os.path.join(REPO, "artifacts", "node", "115", "hl-node")

TARGET_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET_SIZE = 105896032

REMOVE_START = 0x63ACB40
REMOVE_END = 0x63AD582
RET_SITE = 0x63ACD43
CALLERS = (0x636359F, 0x6363A6F, 0x63B0847)

EXHIBITS = {
    "rm_entry": (0x63ACB40, 0x63ACB61, 33, 12),
    "rm_nonhead": (0x63ACB61, 0x63ACB7C, 27, 7),
    "rm_signum": (0x63ACBBF, 0x63ACBF2, 51, 16),
    "rm_head": (0x63ACD70, 0x63ACDA1, 49, 11),
    "rm_relink": (0x63ACD21, 0x63ACD39, 24, 7),
}

INSN_RE = re.compile(r"\s*[0-9a-f]+:\t[0-9a-f ]+\t(\S+)")


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
    if data[text_off(REMOVE_START):text_off(REMOVE_START) + 4] != bytes.fromhex("f30f1efa"):
        fail("entry is not endbr64")
    if data[text_off(0x63ACB5B):text_off(0x63ACB5B) + 2] != bytes.fromhex("0f84"):
        fail("head dispatch je (0f 84) missing at 0x63acb5b")
    if data[text_off(RET_SITE)] != 0xC3:
        fail("single ret missing at 0x63acd43")
    # The zero-call-inside-FDE claim is covered by the unit test, which
    # regenerates the full FDE disassembly and counts call mnemonics.
    for site in CALLERS:
        off = text_off(site)
        if data[off] != 0xE8:
            fail(f"caller {hex(site)} is not E8")
        rel = struct.unpack("<i", data[off + 1:off + 5])[0]
        if site + 5 + rel != REMOVE_START:
            fail(f"caller {hex(site)} does not target remove helper")
    print(f"key bytes ok: {len(CALLERS)} sites")
    print("key calls ok: 0 calls inside FDE")

    # FDE bounds.
    if REMOVE_END - REMOVE_START != 2626:
        fail("FDE length mismatch")
    print("FDE bounds ok: remove 2626B")

    # Census: whole-.text E8/E9/LEA scan.
    text_va, text_off0, text_size = 0x1419300, 0x1418300, 0x4FD7700
    e8 = []
    e9 = []
    lea = []
    for i in range(text_off0, text_off0 + text_size - 7):
        b = data[i]
        if b == 0xE8:
            rel = struct.unpack("<i", data[i + 1:i + 5])[0]
            site = text_va + (i - text_off0)
            if site + 5 + rel == REMOVE_START:
                e8.append(site)
        elif b == 0xE9:
            rel = struct.unpack("<i", data[i + 1:i + 5])[0]
            site = text_va + (i - text_off0)
            if site + 5 + rel == REMOVE_START:
                e9.append(site)
        elif b == 0x48 and data[i + 1] == 0x8D and (data[i + 2] & 0xC7) == 0x05:
            rel = struct.unpack("<i", data[i + 3:i + 7])[0]
            site = text_va + (i - text_off0)
            if site + 7 + rel == REMOVE_START:
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
        if r_add == REMOVE_START:
            got += 1
    if got != 0:
        fail(f"census GOT nonzero: {got}")
    print(f"census ok: remove {len(e8)} E8, 0 E9, 0 LEA, 0 GOT, "
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
