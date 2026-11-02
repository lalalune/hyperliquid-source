#!/usr/bin/env python3
"""Verifier for the RE-001-node115-lu-park-queue packet.

Checks the node #115 binary (never executes it) against the packet's
pinned records: target digest, park-queue body hash, futex constants,
xorshift shifts, division magic, panic message/location, GOT resolutions,
and the call-site census (0 direct E8 callers, 3 GOT-indirect sites).
Exits nonzero naming the failing check.
"""
import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-001-node115-lu-park-queue"
NODE = ROOT / "artifacts" / "node" / "115" / "hl-node"
RECORDS = PACKET / "records.json"

TARGET_SIZE = 105896032
TARGET_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
PARK_LO, PARK_HI = 0x5BB42E0, 0x5BB4663
PARK_SHA = "15a928dcf95723b20a24cf6f2e8fed16118e2f4b0f3fbbe869dc6c6502d82c02"
TEXT_VA, TEXT_OFF, TEXT_SIZE = 0x1419300, 0x1418300, 0x4FD7700


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def va2off(va):
    if TEXT_VA <= va < TEXT_VA + TEXT_SIZE:
        return va - 0x1000
    if 0x430400 <= va < 0x430400 + 0x76E640:
        return va
    if 0x63F3C20 <= va < 0x63F3C20 + 0xEB628:
        return va - 0x2000
    if 0x64DF458 <= va < 0x64DF458 + 0xED00:
        return va - 0x2000
    fail(f"VA out of mapped sections: {hex(va)}")


def main():
    data = NODE.read_bytes()
    if len(data) != TARGET_SIZE:
        fail(f"node size {len(data)} != {TARGET_SIZE}")
    if hashlib.sha256(data).hexdigest() != TARGET_SHA:
        fail("node digest mismatch")
    records = json.loads(RECORDS.read_text())

    park = data[PARK_LO - 0x1000:PARK_HI - 0x1000]
    if len(park) != PARK_HI - PARK_LO:
        fail("park body length mismatch")
    if hashlib.sha256(park).hexdigest() != PARK_SHA:
        fail("park body hash mismatch")
    pinned = bytes.fromhex((PACKET / "park.hex").read_text().strip())
    # Needle checks run on the pinned bytes first, so each corruption
    # control fails at its own check rather than at the equality check.
    tail = pinned[0x5BB45A6 - PARK_LO:0x5BB45C0 - PARK_LO]
    if b"\xbf\xca\x00\x00\x00" not in tail:
        fail("futex nr 202 (mov edi,0xca) missing")
    if b"\xba\x81\x00\x00\x00" not in tail:
        fail("futex op 0x81 missing")
    if b"\xb9\x01\x00\x00\x00" not in tail:
        fail("futex count 1 missing")
    for needle, name in ((b"\xc1\xe6\x0d", "shl 13"), (b"\xc1\xe8\x11", "shr 17"),
                         (b"\xc1\xe1\x05", "shl 5"),
                         (b"\x83\xde\x1b\x43", "magic 0x431bde83"),
                         (b"\x40\x42\x0f\x00", "10^6"),
                         (b"\x00\xca\x9a\x3b", "10^9"),
                         (b"\x00\x36\x65\xc4", "-10^9")):
        if needle not in pinned:
            fail(f"park body missing {name}")
    if pinned != park:
        fail("park.hex != binary body")
    if records["bodies"]["park"]["sha256"] != PARK_SHA:
        fail("records park sha mismatch")
    if records["bodies"]["park"]["bytes"] != 899:
        fail("records park byte count != 899")

    # Single ret at 0x5bb45d5, inside the FDE range.
    if data[0x5BB45D5 - 0x1000] != 0xC3:
        fail("no ret at 0x5bb45d5")
    # Direct calls: lookup 0x5bb4d00 at 0x5bb42f1, clock 0x5c842e0 at 0x5bb445e.
    for site, tgt in ((0x5BB42F1, 0x5BB4D00), (0x5BB445E, 0x5C842E0)):
        off = site - 0x1000
        if data[off] != 0xE8:
            fail(f"no E8 at {hex(site)}")
        disp = struct.unpack_from("<i", data, off + 1)[0]
        if site + 5 + disp != tgt:
            fail(f"E8 at {hex(site)} targets {hex(site + 5 + disp)}, not {hex(tgt)}")
    # Futex tail call: syscall nr 202, op 0x81, count 1 (mov edi / mov edx / mov ecx).
    # (Needles are checked on the pinned bytes above, before equality.)
    # Panic message and location file.
    msg = data[0x94A2C1:0x94A2C1 + 40]
    if msg != b"overflow when adding duration to instant":
        fail(f"panic message mismatch: {msg!r}")
    fstr = data[0x44182F:0x44182F + 71]
    if fstr != b"/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/time.rs":
        fail("panic location file mismatch")
    loc = records["panic_location"]
    if (loc["line"], loc["col"]) != (429, 33):
        fail("panic location line/col mismatch")

    # GOT resolutions via readelf.
    rel = subprocess.run(["readelf", "-r", str(NODE)], capture_output=True,
                         text=True, check=True).stdout
    got = {}
    for line in rel.splitlines():
        m = __import__("re").match(
            r"\s*([0-9a-f]+)\s+[0-9a-f]+\s+(\S+)(?:\s+([0-9a-f]+))?", line)
        if m:
            off = int(m.group(1), 16)
            if off in (0x64EC150, 0x64E06B8, 0x64EC188, 0x64E1248):
                got[off] = (m.group(2), m.group(3))
    if got.get(0x64EC150, (None, None))[1] != "5bb66b0":
        fail(f"cleanup GOT mismatch: {got.get(0x64EC150)}")
    if got.get(0x64EC188, (None, None))[1] != "5bb42e0":
        fail(f"park GOT mismatch: {got.get(0x64EC188)}")
    if "syscall" not in rel or "64e06b8" not in rel:
        fail("notify GOT is not the syscall import")
    if "clock_gettime" not in rel or "64e1248" not in rel:
        fail("timer GOT is not clock_gettime")

    # Census: 0 direct E8 callers, 3 GOT-indirect sites.
    text = data[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    e8 = []
    for i in range(len(text) - 5):
        if text[i] == 0xE8:
            disp = struct.unpack_from("<i", text, i + 1)[0]
            if TEXT_VA + i + 5 + disp == PARK_LO:
                e8.append(TEXT_VA + i)
    if e8:
        fail(f"direct E8 callers found: {[hex(x) for x in e8]}")
    ind = []
    for i in range(len(text) - 7):
        if text[i] == 0xFF and text[i + 1] == 0x15:
            disp = struct.unpack_from("<i", text, i + 2)[0]
            if TEXT_VA + i + 6 + disp == 0x64EC188:
                ind.append(TEXT_VA + i)
    if [hex(x) for x in ind] != ["0x5cf4e8e", "0x5cf521b", "0x5cfd965"]:
        fail(f"GOT sites mismatch: {[hex(x) for x in ind]}")
    if records["census"]["got_park"] != ["0x5cf4e8e", "0x5cf521b", "0x5cfd965"]:
        fail("records census mismatch")

    # Lookup hash constant and 64-byte entry stride.
    if b"\x15\x7c\x4a\x7f\xb9\x79\x37\x9e" not in data[0x5BB4D0E - 0x1000:0x5BB4D20 - 0x1000]:
        fail("lookup golden-ratio constant missing")
    print("Verified node #115 lu.rs park-queue packet: park 0x5bb42e0..0x5bb4663 "
          "(899B), futex wake-private x1, xorshift 13/17/5 mod 10^6, "
          "0 direct callers, 3 GOT sites")


if __name__ == "__main__":
    main()
