#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-slotinsert.

Checks, all read-only (the node binary is never executed):
  - binary SHA-256 and size for node #115
  - 5 claimed excerpts byte-match the binary at their VAs
  - strict mnemonic counts agree with records.json
  - key bytes: entry endbr64, +0x28/+0x38 zeroing, empty-slot je,
    count increment, tzcnt merge bound, insert-before [slot+8] = 0,
    both ret sites, and zero call instructions inside the FDE
  - census: 6 direct E8 to 0x63ac0d0, 0 E9, 0 LEA, 0 GOT
    (GOT via .rela.dyn addends, since RELATIVE slots are zero-filled)
  - FDE bounds 0x63ac0d0..0x63ac472 (930 bytes)
  - MANIFEST.sha256 15/15 entries
"""

import hashlib
import json
import os
import re
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PACKET = os.path.join(HERE, "..", "research", "work-items",
                      "RE-001-node115-lu-slotinsert")
BIN = os.path.join(HERE, "..", "artifacts", "node", "115", "hl-node")

EXPECT_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
EXPECT_SIZE = 105896032
FDE_START, FDE_END = 0x63AC0D0, 0x63AC472
TARGET = 0x63AC0D0
EXPECT_E8 = [0x635F3F7, 0x635F497, 0x636370D, 0x63637C7, 0x636A035, 0x63B0675]


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def va_to_off(va):
    return va - 0x1000


def main():
    with open(BIN, "rb") as f:
        data = f.read()
    if len(data) != EXPECT_SIZE:
        fail(f"binary size {len(data)} != {EXPECT_SIZE}")
    if hashlib.sha256(data).hexdigest() != EXPECT_SHA:
        fail("binary sha mismatch")
    print(f"binary sha ok ({EXPECT_SIZE} bytes)")

    with open(os.path.join(PACKET, "records.json")) as f:
        rec = json.load(f)

    total_bytes = 0
    total_strict = 0
    for name, ex in sorted(rec["exhibits"].items()):
        start = int(ex["range"][0], 16)
        end = int(ex["range"][1], 16)
        with open(os.path.join(PACKET, name + ".hex")) as f:
            claimed = bytes.fromhex("".join(f.read().split()))
        if len(claimed) != ex["bytes"] or len(claimed) != end - start:
            fail(f"{name}: length {len(claimed)} != range {end - start}")
        got = data[va_to_off(start):va_to_off(start) + len(claimed)]
        if got != claimed:
            fail(f"{name}: bytes differ from binary at {hex(start)}")
        with open(os.path.join(PACKET, name + ".objdump.txt")) as f:
            strict = 0
            for line in f:
                m = re.match(r"\s*[0-9a-f]+:\t[0-9a-f ]+?\t(.*)$", line)
                if m and m.group(1).strip():
                    strict += 1
        if strict != ex["strict"]:
            fail(f"{name}: strict {strict} != {ex['strict']}")
        total_bytes += len(claimed)
        total_strict += strict
    print(f"exhibits ok: {len(rec['exhibits'])} excerpts, "
          f"{total_bytes} bytes, {total_strict} strict")

    def check(va, want, label):
        got = data[va_to_off(va):va_to_off(va) + len(want)]
        if got != want:
            fail(f"{label} at {hex(va)}: {got.hex()} != {want.hex()}")

    check(0x63AC0D0, bytes.fromhex("f30f1efa"), "entry endbr64")
    check(0x63AC0E7, bytes.fromhex("0f114628"), "node+0x28 zero movups")
    check(0x63AC0EE, bytes.fromhex("48c7411000000000"), "node+0x38 zero movq")
    check(0x63AC0F9, bytes.fromhex("0f84e1020000"), "empty-slot je")
    check(0x63AC13C, bytes.fromhex("488b5f08"), "slot second-word load")
    check(0x63AC177, bytes.fromhex("f34c0fbce5"), "merge-bound tzcnt")
    check(0x63AC433, bytes.fromhex("48c7470800000000"), "insert-before slot+8 = 0")
    check(0x63AC16E, bytes.fromhex("c3"), "shared-exit ret")
    check(0x63AC443, bytes.fromhex("c3"), "insert-before ret")
    print("key bytes ok: 9 sites")

    out = subprocess.run(
        ["objdump", "-d", f"--start-address={hex(FDE_START)}",
         f"--stop-address={hex(FDE_END)}", BIN],
        capture_output=True, text=True, check=True).stdout
    calls = [l for l in out.splitlines() if re.search(r"\tcall\s", l)]
    if calls:
        fail(f"FDE contains call instructions: {calls[:3]}")
    print("key calls ok: 0 calls inside FDE")

    text_off = va_to_off(0x1419300)
    text_va, text_size = 0x1419300, 0x4FD7700
    text = data[text_off:text_off + text_size]
    e8, e9, lea = [], [], []
    for i in range(len(text) - 7):
        b = text[i]
        if b in (0xE8, 0xE9) and i + 5 <= len(text):
            rel = struct.unpack("<i", text[i + 1:i + 5])[0]
            if text_va + i + 5 + rel == TARGET:
                (e8 if b == 0xE8 else e9).append(text_va + i)
        if (b == 0x48 and text[i + 1] == 0x8D
                and (text[i + 2] & 0xC7) == 0x05):
            disp = struct.unpack("<i", text[i + 3:i + 7])[0]
            if text_va + i + 7 + disp == TARGET:
                lea.append(text_va + i)
    if sorted(e8) != sorted(EXPECT_E8):
        fail(f"census E8 {[hex(a) for a in e8]} != expected")
    if e9 or lea:
        fail(f"census E9/LEA nonzero: {[hex(a) for a in e9 + lea]}")
    rela_off, rela_size = 0x6BE8, 0x163CC8
    got_hits = []
    for k in range(rela_size // 24):
        off, info, add = struct.unpack(
            "<QQq", data[rela_off + k * 24:rela_off + k * 24 + 24])
        if add == TARGET:
            got_hits.append(off)
    if got_hits:
        fail(f"GOT addend hits: {[hex(o) for o in got_hits]}")
    print(f"census ok: insert 6 E8, 0 E9, 0 LEA, 0 GOT, "
          f"{rela_size // 24} rela entries")

    if FDE_END - FDE_START != 930:
        fail("FDE size mismatch")
    print("FDE bounds ok: insert 930B")

    man = os.path.join(PACKET, "MANIFEST.sha256")
    n = 0
    with open(man) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            digest, _, path = line.partition("  ")
            if not digest:
                digest, _, path = line.partition(" ")
            full = os.path.normpath(os.path.join(PACKET, path))
            with open(full, "rb") as fh:
                actual = hashlib.sha256(fh.read()).hexdigest()
            if actual != digest:
                fail(f"MANIFEST mismatch: {path}")
            n += 1
    if n != 15:
        fail(f"MANIFEST entries {n} != 15")
    print("MANIFEST ok: 15/15 entries")
    print("verifier: all checks passed "
          f"({len(rec['exhibits'])} excerpts, {total_strict} strict, "
          f"census 6 E8 sites, MANIFEST 15 entries)")


if __name__ == "__main__":
    main()
