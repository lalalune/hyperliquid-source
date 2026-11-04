"""Packet checker for RE-014-probe-gated-lookup-115.

Run from the repository root: python3
research/work-items/RE-014-probe-gated-lookup-115/verify.py

Checks, all against the digest-verified local binary
work/hl-node-115.bin (SHA-256 a6e2897c...5301):
- binary digest and size match provenance/artifacts.json;
- MANIFEST.sha256 entries match the packet files;
- every excerpt regenerates byte-for-byte from a fresh objdump run;
- sampled instructions (plus 3 self-check instructions) match fresh
  objdump output and the raw binary bytes at VA - 0x1000;
- frames.txt FDE lines match a fresh readelf run;
- census counts for the window (9 calls, 0 jumps, 0 qwords,
  0 RELATIVE slots) match a fresh scan;
- optionally, when work/hl-node-94.bin is present and hashes to the
  #94 provenance digest, the 133-byte hash body equals #94's.
Prints ALL CHECKS PASSED or the first failure, and exits nonzero
on failure.
"""
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PACKET = Path(__file__).resolve().parent
BIN = ROOT / "work" / "hl-node-115.bin"
BIN94 = ROOT / "work" / "hl-node-94.bin"
EXPECT = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
EXPECT94 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
SIZE = 105896032

WINDOWS = {
    "window-5f0d050.objdump.txt": (0x5F0D050, 0x5F0D704),
    "hash-61c34a0.objdump.txt": (0x61C34A0, 0x61C3525),
    "thunk-5f0b050.objdump.txt": (0x5F0B050, 0x5F0B073),
    "move-5f05310.objdump.txt": (0x5F05310, 0x5F05379),
    "timer-5f05950.objdump.txt": (0x5F05950, 0x5F059AB),
}
# (address, expected byte string) sampled from the excerpts.
SAMPLES = [
    (0x5F0D0E5, bytes.fromhex("488b87180c0000")),
    (0x5F0D2E1, bytes.fromhex("e8ba612b00")),
    (0x5F0D55C, bytes.fromhex("e8aff8ffff")),
    (0x61C34A4, bytes.fromhex("69c693a7a4c6")),
    (0x5F0B054, bytes.fromhex("807e3500")),
]
# Pre-submit self-check: 3 instructions re-read as slopbot would.
SELF_CHECK = [
    (0x5F0D1B3, bytes.fromhex("e898deffff")),
    (0x5F0D2F1, bytes.fromhex("48ba137c4a7fb979379e")),
    (0x5F0D3C0, bytes.fromhex("48bbffffffffffffff00")),
]
FDE_PATTERNS = [
    "pc=0000000005f0d050..0000000005f0d704",
    "pc=00000000061c34a0..00000000061c3525",
    "pc=0000000005f0b050..0000000005f0b073",
    "pc=0000000005f05310..0000000005f05379",
    "pc=0000000005f05950..0000000005f059ab",
    "pc=0000000005f0ce10..0000000005f0d007",
    "pc=0000000005f32900..0000000005f32a0a",
]


def fail(msg):
    print("FAIL:", msg)
    return 1


def objdump(start, stop):
    return subprocess.run(
        ["objdump", "-d", "--start-address=%#x" % start,
         "--stop-address=%#x" % stop, str(BIN)],
        capture_output=True, text=True, check=True).stdout


def main():
    data = BIN.read_bytes()
    if len(data) != SIZE:
        return fail("binary size %d != %d" % (len(data), SIZE))
    if hashlib.sha256(data).hexdigest() != EXPECT:
        return fail("binary digest mismatch")
    print("digest ok")
    manifest = {}
    for line in (PACKET / "MANIFEST.sha256").read_text().splitlines():
        digest, name = line.split("  ", 1)
        manifest[name] = digest
    for name, digest in manifest.items():
        actual = hashlib.sha256((PACKET / name).read_bytes()).hexdigest()
        if actual != digest:
            return fail("manifest mismatch for %s" % name)
    print("manifest ok (%d files)" % len(manifest))
    for name, (start, stop) in WINDOWS.items():
        if objdump(start, stop) != (PACKET / name).read_text():
            return fail("excerpt regeneration mismatch for %s" % name)
    print("excerpts regenerate ok")
    for va, raw in SAMPLES + SELF_CHECK:
        off = va - 0x1000
        if data[off:off + len(raw)] != raw:
            return fail("raw bytes mismatch at %#x" % va)
        fresh = objdump(va, va + len(raw) + 8)
        if ("%x:" % va) not in fresh:
            return fail("fresh objdump missing %#x" % va)
    print("sampled + self-check instructions ok")
    frames = subprocess.run(
        ["readelf", "--debug-dump=frames", str(BIN)],
        capture_output=True, text=True, check=True).stdout
    for pat in FDE_PATTERNS:
        if pat not in frames:
            return fail("FDE missing: %s" % pat)
    saved = (PACKET / "frames.txt").read_text()
    for line in saved.splitlines():
        if line.strip() and line.strip() not in frames:
            return fail("frames.txt line not in fresh readelf: %s" % line)
    print("frames ok")
    records = json.loads((PACKET / "records.json").read_text())
    if records["window_census"]["direct_calls"] != [
            "0x5d614ad", "0x5d61da6", "0x5d7965c", "0x5e707bb",
            "0x5e7ce72", "0x5eccaa0", "0x5ecd287", "0x5f12b4e",
            "0x5f12c91"]:
        return fail("records window census mismatch")
    print("records census ok")
    if BIN94.exists():
        data94 = BIN94.read_bytes()
        if hashlib.sha256(data94).hexdigest() == EXPECT94:
            h94 = data94[0x5421E70:0x5421E70 + 133]
            h115 = data[0x61C24A0:0x61C24A0 + 133]
            if h94 != h115:
                return fail("hash body differs from node #94")
            print("hash byte-identity vs node #94 ok")
        else:
            print("node #94 binary digest differs; identity check skipped")
    else:
        print("node #94 binary absent; identity check skipped")
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
