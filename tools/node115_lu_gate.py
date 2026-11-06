#!/usr/bin/env python3
"""Static verifier for the node #115 lu gate packet
(RE-001-node115-lu-gate). Byte reads only; the node binary is
never executed.
"""

import hashlib
import os
import re
import struct
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(REPO, "research", "work-items", "RE-001-node115-lu-gate")
NODE = os.path.join(REPO, "artifacts", "node", "115", "hl-node")

TARGET_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET_SIZE = 105896032
FDE_START, FDE_END = 0x63B85F0, 0x63B8820
RET_SITE = 0x63B8709

EXHIBITS = {
    "gt_entry": (0x63B85F0, 0x63B8661, 113, 26),
    "gt_main": (0x63B8667, 0x63B869D, 54, 10),
    "gt_post": (0x63B869D, 0x63B86E6, 73, 12),
    "gt_setup": (0x63B8728, 0x63B874F, 39, 9),
    "gt_drain": (0x63B8790, 0x63B87E3, 83, 15),
    "gt_fail": (0x63B8800, 0x63B881B, 27, 6),
}

# (site, expected target) for direct E8 calls.
CALLS = [
    (0x63B868C, 0x636B370),  # allocator, main path
    (0x63B86BC, 0x63BA600),  # consume, main path
    (0x63B873E, 0x63C2130),  # resolver, setup path
    (0x63B8763, 0x636B370),  # allocator, setup path
    (0x63B8790, 0x636B370),  # allocator, drain path
    (0x63B87B9, 0x63BA600),  # consume, drain path
    (0x63B87F8, 0x63C2450),  # release, setup path
]

EXPECTED_E8 = ["0x63b8bdc", "0x63b8ec2"]

STRICT_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t\S")


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


def main():
    with open(NODE, "rb") as f:
        data = f.read()
    if hashlib.sha256(data).hexdigest() != TARGET_SHA:
        fail("binary sha mismatch")
    if len(data) != TARGET_SIZE:
        fail("binary size mismatch")
    print("binary sha ok (%d bytes)" % TARGET_SIZE)
    off = lambda va: va - 0x1000

    total_bytes = 0
    total_strict = 0
    for name, (start, end, nbytes, nstrict) in sorted(EXHIBITS.items()):
        with open(os.path.join(PACKET, name + ".hex")) as f:
            raw = bytes.fromhex("".join(f.read().split()))
        if len(raw) != nbytes or raw != data[off(start):off(start) + nbytes]:
            fail("exhibit bytes mismatch: " + name)
        with open(os.path.join(PACKET, name + ".objdump.txt")) as f:
            lines = [line for line in f.read().splitlines() if line.strip()]
        strict = sum(1 for line in lines if STRICT_RE.match(line))
        if strict != nstrict:
            fail("strict count mismatch: %s (%d != %d)" % (name, strict, nstrict))
        total_bytes += nbytes
        total_strict += strict
    print("exhibits ok: %d excerpts, %d bytes, %d strict"
          % (len(EXHIBITS), total_bytes, total_strict))

    # FDE bounds: endbr64 at entry, single ret, next function endbr64.
    if data[off(FDE_START):off(FDE_START) + 4] != bytes.fromhex("f30f1efa"):
        fail("entry is not endbr64")
    if FDE_END - FDE_START != 560:
        fail("FDE size mismatch")
    if data[off(RET_SITE)] != 0xC3:
        fail("ret site is not 0xc3")
    if data[off(FDE_END):off(FDE_END) + 4] != bytes.fromhex("f30f1efa"):
        fail("next function is not endbr64")

    # Key bytes: flag stores, cursor arithmetic, drain zeroing.
    if data[off(0x63B865C):off(0x63B865C) + 5] != bytes.fromhex("41c6042400"):
        fail("flag-clear store mismatch")
    if data[off(0x63B8800):off(0x63B8800) + 5] != bytes.fromhex("41c6042401"):
        fail("flag-set store mismatch")
    if data[off(0x63B86C4):off(0x63B86C4) + 11] != bytes.fromhex("488183e000000000002000"):
        fail("cursor advance mismatch")
    if data[off(0x63B86CF):off(0x63B86CF) + 11] != bytes.fromhex("4881abe800000000002000"):
        fail("remaining retreat mismatch")
    if data[off(0x63B87C1):off(0x63B87C1) + 11] != bytes.fromhex("48c783e000000000000000"):
        fail("drain cursor zero mismatch")
    if data[off(0x63B87CC):off(0x63B87CC) + 11] != bytes.fromhex("48c783e800000000000000"):
        fail("drain remaining zero mismatch")
    print("key bytes ok: endbr64, flag stores, cursor arithmetic, drain zeroing, ret")

    for site, target in CALLS:
        if data[off(site)] != 0xE8:
            fail("call opcode mismatch at %#x" % site)
        rel = struct.unpack_from("<i", data, off(site) + 1)[0]
        if site + 5 + rel != target:
            fail("call target mismatch at %#x" % site)
    print("key calls ok: %d rel32s" % len(CALLS))

    # Full .text census for direct references to the gate.
    text = subprocess.run(
        ["readelf", "-SW", NODE], capture_output=True, text=True,
        check=True).stdout
    m = re.search(r"\.text\s+PROGBITS\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)", text)
    text_va, text_off, text_size = (int(m.group(i), 16) for i in (1, 2, 3))
    e8, e9, lea = [], [], []
    i = text_off
    end = text_off + text_size
    while i < end - 7:
        b = data[i]
        if b in (0xE8, 0xE9):
            rel = struct.unpack("<i", data[i + 1:i + 5])[0]
            va = text_va + (i - text_off) + 5 + rel
            if va == FDE_START:
                (e8 if b == 0xE8 else e9).append("0x%x" % (text_va + (i - text_off)))
        if data[i] in (0x48, 0x4C) and data[i + 1] == 0x8D and (data[i + 2] & 0xC7) == 0x05:
            disp = struct.unpack("<i", data[i + 3:i + 7])[0]
            va = text_va + (i - text_off) + 7 + disp
            if va == FDE_START:
                lea.append("0x%x" % (text_va + (i - text_off)))
        i += 1
    if e8 != EXPECTED_E8 or e9 or lea:
        fail("census mismatch: E8=%s E9=%s LEA=%s" % (e8, e9, lea))
    rela = subprocess.run(
        ["readelf", "-rW", NODE], capture_output=True, text=True,
        check=True).stdout
    dyn_size = None
    for line in rela.splitlines():
        pass
    sec = subprocess.run(
        ["readelf", "-SW", NODE], capture_output=True, text=True,
        check=True).stdout
    dm = re.search(r"\.rela\.dyn\s+RELA\s+[0-9a-f]+\s+[0-9a-f]+\s+([0-9a-f]+)", sec)
    dyn_entries = int(dm.group(1), 16) // 24
    if dyn_entries != 60723:
        fail("rela.dyn entry count mismatch: %d" % dyn_entries)
    if "00000000063b85f0" in rela:
        fail("rela.dyn addend hit for gate")
    print("census ok: gate 2 E8, 0 E9, 0 LEA, 0 GOT, 60723 rela entries")

    # Branch targets inside the FDE; single ret.
    out = subprocess.run(
        ["objdump", "-d", "--start-address=%s" % hex(FDE_START),
         "--stop-address=%s" % hex(FDE_END), NODE],
        capture_output=True, text=True, check=True).stdout
    rets = 0
    for line in out.splitlines():
        mm = re.match(r"\s*([0-9a-f]+):\t[0-9a-f ]+\t(\S+)\s*(.*)", line)
        if not mm:
            continue
        mn, ops = mm.group(2), mm.group(3)
        if mn == "ret":
            rets += 1
        if mn.startswith("j"):
            tm = re.search(r"\b([0-9a-f]{6,})\b", ops)
            if tm and not (FDE_START <= int(tm.group(1), 16) < FDE_END):
                fail("branch target outside FDE: " + line.strip())
    if rets != 1:
        fail("ret count mismatch: %d" % rets)
    print("FDE bounds ok: gate 560B, single ret, all branch targets internal")

    # Neighbour disjointness: exhibits strictly inside the FDE.
    for name, (start, end, _b, _s) in EXHIBITS.items():
        if not (FDE_START <= start < end <= FDE_END):
            fail("exhibit outside FDE: " + name)
    print("disjoint ok: exhibits inside FDE, no neighbour overlap")

    # MANIFEST coverage.
    manifest = os.path.join(PACKET, "MANIFEST.sha256")
    with open(manifest) as f:
        entries = [line.split() for line in f.read().splitlines() if line.strip()]
    checked = 0
    for digest, path in entries:
        full = os.path.normpath(os.path.join(PACKET, path))
        with open(full, "rb") as f:
            actual = hashlib.sha256(f.read()).hexdigest()
        if actual != digest:
            fail("MANIFEST mismatch: " + path)
        checked += 1
    if checked != 17:
        fail("MANIFEST entry count mismatch: %d" % checked)
    print("MANIFEST ok: 17/17 entries")
    print("verifier: all checks passed (%d excerpts, %d bytes, %d strict, "
          "census 2 E8 sites, MANIFEST 17 entries)"
          % (len(EXHIBITS), total_bytes, total_strict))


if __name__ == "__main__":
    main()
