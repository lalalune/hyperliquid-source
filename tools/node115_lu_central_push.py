#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-central-push.

Reads only: the node #115 binary, the packet exhibits, and MANIFEST.sha256.
Never executes the binary. Exit 0 when every check passes.
"""

import hashlib
import os
import re
import struct
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(ROOT, "research", "work-items",
                       "RE-001-node115-lu-central-push")
BINARY = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
EXPECT_SHA = ("a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")

EXHIBITS = [
    ("push", 0x63C0340, 0x63C03E8, 45),
    ("flag_large", 0x63BD687, 0x63BD6B3, 13),
    ("flag_small", 0x63612E6, 0x6361313, 13),
    ("fallback_gate", 0x6360610, 0x636063A, 13),
]

KEY_BYTES = {
    0x63C0340: "f30f1efa",
    0x63C0351: "b9e8000000",
    0x63C0362: "488bb6a80a0100",
    0x63C0369: "e872ecfeff",
    0x63C0372: "f6c410",
    0x63C0377: "4881650800f0ffff",
    0x63C0383: "4825ffff0ff0",
    0x63C0389: "480d0000800e",
    0x63C0397: "f048295308",
    0x63C039C: "48f7450000400000",
    0x63C03A4: "488d4b18",
    0x63C03A8: "488db338f30000",
    0x63C03B5: "480f44f1",
    0x63C03BC: "4c8b4620",
    0x63C03CA: "41ffe0",
    0x63C03D0: "488bb3a80a0100",
    0x63C03DD: "e85ee9feff",
    0x63BD682: "e8b92c0000",
    0x63612E1: "e85af00500",
    0x63BD6AE: "e85d2ffaff",
    0x636130E: "e8fdf2ffff",
    0x6360620: "488b86400f0100",
    0x6360684: "488d93c80e0100",
    0x63606B7: "4c8d86e8290000",
    0x63BD730: "e80b2c0000",
    0x6363AB6: "e885c80500",
    0x636156E: "e8cded0500",
    0x63615E2: "e859ed0500",
    0x63616A1: "e89aec0500",
    0x63627A9: "e892db0500",
    0x6364E28: "e813b50500",
    0x635FBC5: "488db5b0290000",
}

EXPECT_E8 = [0x63612E1, 0x636156E, 0x63615E2, 0x63616A1, 0x63627A9,
             0x6363AB6, 0x6364E28, 0x63BD682, 0x63BD730]
TARGET = 0x63C0340

# Prior packets' exhibit ranges (not FDE citations); must stay disjoint.
PRIOR_RANGES = [
    (0x635C6D0, 0x635C886),   # #203 dispatch
    (0x635CDF8, 0x635CE47),   # #203 full
    (0x635CCE8, 0x635CD7F),   # #203 page
    (0x63EAEF0, 0x63EAF7E),   # #204 small_lock
    (0x63EB9D0, 0x63EBA48),   # #204 large_gate
    (0x63BD640, 0x63BD687),   # #204 push_large (ours starts at its end)
    (0x63EC019, 0x63EC068),   # #204 large_tail
    (0x635DE30, 0x635DEC6),   # #202 fast-path exhibit
    (0x5A8E3C0, 0x5A8E493),   # #202 free (211B, reported size)
    (0x5A8C9F0, 0x5A8CA2C),   # #202 drop9f0 (60B, reported size)
    (0x5A8C110, 0x5A8C14C),   # #202 drop110 (60B, reported size)
]


def fail(msg):
    print(f"verifier: FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def read_bytes(va, n):
    off = va - 0x1000
    with open(BINARY, "rb") as f:
        f.seek(off)
        data = f.read(n)
    if len(data) != n:
        fail(f"short read at {va:#x}")
    return data


def strict_count(start, end):
    out = subprocess.run(
        ["objdump", "-d", f"--start-address={hex(start)}",
         f"--stop-address={hex(end)}", BINARY],
        capture_output=True, text=True, check=True).stdout
    count = 0
    for line in out.splitlines():
        m = re.match(r"^\s*([0-9a-f]+):\t([0-9a-f ]+)\t(.*)$", line)
        if not m:
            continue
        va = int(m.group(1), 16)
        if not (start <= va < end):
            continue
        mnem = m.group(3).strip()
        if mnem and not re.fullmatch(r"[0-9a-f ]+", mnem):
            count += 1
    return count


def text_section():
    out = subprocess.run(["objdump", "-h", BINARY],
                         capture_output=True, text=True, check=True).stdout
    for line in out.splitlines():
        p = line.split()
        if len(p) >= 6 and p[1] == ".text":
            return int(p[3], 16), int(p[5], 16), int(p[2], 16)
    fail("no .text section")


def main():
    with open(BINARY, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    if digest != EXPECT_SHA:
        fail(f"binary SHA mismatch: {digest}")

    for name, start, end, expect_strict in EXHIBITS:
        with open(os.path.join(PACKET, f"{name}.hex")) as f:
            claimed = bytes.fromhex("".join(f.read().split()))
        if claimed != read_bytes(start, end - start):
            fail(f"{name}.hex does not regenerate from the binary")
        got = strict_count(start, end)
        if got != expect_strict:
            fail(f"{name} strict count {got} != {expect_strict}")

    for va, hexbytes in KEY_BYTES.items():
        want = bytes.fromhex(hexbytes)
        if read_bytes(va, len(want)) != want:
            fail(f"key bytes mismatch at {va:#x}")

    vma, off, size = text_section()
    with open(BINARY, "rb") as f:
        f.seek(off)
        data = f.read(size)
    e8, e9, lea = [], [], []
    i = 0
    while i < len(data) - 7:
        va = vma + i
        b = data[i]
        if b == 0xE8 and va + 5 + struct.unpack("<i", data[i + 1:i + 5])[0] == TARGET:
            e8.append(va)
        elif b == 0xE9 and va + 5 + struct.unpack("<i", data[i + 1:i + 5])[0] == TARGET:
            e9.append(va)
        if b == 0x48 and data[i + 1] == 0x8D and (data[i + 2] & 0xC7) == 0x05:
            if va + 7 + struct.unpack("<i", data[i + 3:i + 7])[0] == TARGET:
                lea.append(va)
        i += 1
    if e8 != EXPECT_E8:
        fail(f"E8 census mismatch: {[hex(x) for x in e8]}")
    if e9:
        fail(f"unexpected E9 sites: {[hex(x) for x in e9]}")
    if lea:
        fail(f"unexpected LEA sites: {[hex(x) for x in lea]}")

    out = subprocess.run(["readelf", "-r", BINARY],
                         capture_output=True, text=True, check=True).stdout
    for line in out.splitlines():
        if "R_X86_64_RELATIVE" in line:
            p = line.split()
            if len(p) >= 3:
                try:
                    if int(p[2], 16) == TARGET:
                        fail(f"unexpected GOT RELATIVE addend at {p[0]}")
                except ValueError:
                    pass

    for name, start, end, _ in EXHIBITS:
        for ps, pe in PRIOR_RANGES:
            if start < pe and ps < end:
                fail(f"{name} range overlaps prior range {ps:#x}..{pe:#x}")

    with open(os.path.join(PACKET, "MANIFEST.sha256")) as f:
        entries = [ln.split() for ln in f.read().splitlines() if ln.strip()]
    if len(entries) != 13:
        fail(f"MANIFEST has {len(entries)} entries, expected 13")
    for digest, rel in entries:
        path = os.path.normpath(os.path.join(PACKET, rel))
        with open(path, "rb") as f:
            if hashlib.sha256(f.read()).hexdigest() != digest:
                fail(f"MANIFEST hash mismatch for {rel}")

    print("verifier: all checks passed "
          f"({len(EXHIBITS)} excerpts, {len(KEY_BYTES)} key-byte sites, "
          f"census {len(e8)} E8 sites, MANIFEST 13/13)")


if __name__ == "__main__":
    main()
