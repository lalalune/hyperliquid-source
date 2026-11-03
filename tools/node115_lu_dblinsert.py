#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-dblinsert.

Checks, all read-only (the node binary is never executed):
  - binary SHA-256 and size for node #115
  - 5 claimed excerpts byte-match the binary at their VAs
  - strict mnemonic counts agree with records.json
  - key bytes: entry endbr64, global lea, head load, setb/sbb idiom,
    both slot-insert calls, both counters, tag shr, both ret sites,
    head replacement store
  - FDE calls: exactly 2 call instructions, both to 0x63ac0d0
  - census: 6 direct E8 to 0x6363660, 0 E9, 0 LEA, 0 GOT
    (GOT via .rela.dyn addends, since RELATIVE slots are zero-filled)
  - FDE bounds 0x6363660..0x63637e2 (386 bytes)
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
                      "RE-001-node115-lu-dblinsert")
BIN = os.path.join(HERE, "..", "artifacts", "node", "115", "hl-node")

EXPECT_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
EXPECT_SIZE = 105896032
FDE_START, FDE_END = 0x6363660, 0x63637E2
TARGET = 0x6363660
SLOT_INSERT = 0x63AC0D0
EXPECT_E8 = [0x63EA135, 0x63EA495, 0x63EAAD3,
             0x63EB134, 0x63EB20A, 0x63EB356]


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

    check(0x6363660, bytes.fromhex("f30f1efa"), "entry endbr64")
    check(0x6363670, bytes.fromhex("488d0525601a00"), "global lea")
    check(0x63636C2, bytes.fromhex("488bb5c0000000"), "head load")
    check(0x63636E3, bytes.fromhex("0f92c0"), "key setb")
    check(0x63636E9, bytes.fromhex("83d800"), "key sbb")
    check(0x636370D, bytes.fromhex("e8be890400"), "slot-insert call 1")
    check(0x6363712, bytes.fromhex("488385b800000001"), "slot counter +0xb8")
    check(0x636372B, bytes.fromhex("48c1ea1c"), "tag shr 28")
    check(0x6363788, bytes.fromhex("488385a800000001"), "head counter +0xa8")
    check(0x6363790, bytes.fromhex("48899dc0000000"), "head store +0xc0")
    check(0x63637C7, bytes.fromhex("e804890400"), "slot-insert call 2")
    check(0x6363720, bytes.fromhex("c3"), "insert-path ret")
    check(0x636379D, bytes.fromhex("c3"), "evict-path ret")
    print("key bytes ok: 13 sites")

    out = subprocess.run(
        ["objdump", "-d", f"--start-address={hex(FDE_START)}",
         f"--stop-address={hex(FDE_END)}", BIN],
        capture_output=True, text=True, check=True).stdout
    calls = []
    for l in out.splitlines():
        m = re.search(r"\tcall\s+([0-9a-f]+)", l)
        if m:
            calls.append(int(m.group(1), 16))
    if calls != [SLOT_INSERT, SLOT_INSERT]:
        fail(f"FDE calls {[hex(c) for c in calls]} != 2x slot-insert")
    print("key calls ok: exactly 2 calls, both to slot-insert 0x63ac0d0")

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
    print(f"census ok: dblinsert 6 E8, 0 E9, 0 LEA, 0 GOT, "
          f"{rela_size // 24} rela entries")

    if FDE_END - FDE_START != 386:
        fail("FDE size mismatch")
    print("FDE bounds ok: dblinsert 386B")

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
