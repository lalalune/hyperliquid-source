#!/usr/bin/env python3
"""Verify the RE-001-report-builder-94 evidence packet.

Stdlib only. Run from the repository root:

    python3 research/work-items/RE-001-report-builder-94/verify.py \\
        --binary work/hl-node-94.bin

Checks, all against the digest-verified binary:
  1. the binary SHA-256 matches provenance/artifacts.json (node #94);
  2. every objdump excerpt regenerates byte-for-byte;
  3. MANIFEST.sha256 matches the packet files;
  4. records.json is semantic records only (no per-instruction
     mnemonic list);
  5. the recorded call/branch sites sit at their recorded addresses
     (first-byte spot checks);
  6. the digit-pair table reconstructs from the binary's .rodata
     vectors (in stack-copy order, with the final overlapping
     movups) as exactly "00".."99";
  7. the entry loop covers 14 entries x 3 phases, and the header
     keys are the four recorded statics.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

PACKET_DIR = Path(__file__).resolve().parent
REPO = PACKET_DIR.parents[2]
DEFAULT_BINARY = REPO / "artifacts" / "node" / "94" / "hl-node"
NODE94_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"

EXCERPTS = {
    "window.objdump.txt": ("0x5157d30", "0x5158ebe"),
    "cleanup.objdump.txt": ("0x5157c0c", "0x5157d30"),
    "teardown.objdump.txt": ("0x514bf60", "0x514bfd1"),
    "find.objdump.txt": ("0x5153a70", "0x5153bb6"),
    "insert.objdump.txt": ("0x5153650", "0x515383b"),
    "itoa.objdump.txt": ("0x4faf340", "0x4faf6ad"),
    "dblfmt.objdump.txt": ("0x514c050", "0x514c1b5"),
    "accessor.objdump.txt": ("0x514df50", "0x514df75"),
    "caller.objdump.txt": ("0x5159099", "0x51590c8"),
}

# (address, first byte) spot checks for the sites records.json pins.
# .text file offset = VA - 0x1000 for this binary.
SITES = [
    (0x5157D30, 0xF3),  # endbr64 at the window start
    (0x5157D77, 0xE8),  # call to the teardown 0x514bf60
    (0x5157DA8, 0xE8),  # call to the find-or-insert 0x5153a70
    (0x5157DB4, 0xE8),  # call to _M_assign (id entry)
    (0x5157DC4, 0xE8),  # call to the itoa 0x4faf340 (capacity)
    (0x5157DEF, 0xE8),  # call to the accessor 0x514df50
    (0x5157DF7, 0x0F),  # js to the unsigned-conversion arm
    (0x5157E2E, 0xE8),  # call to the double formatter 0x514c050
    (0x5157E61, 0xFF),  # indirect call *0x98(%rax) (clock dispatch)
    (0x5157E6F, 0x48),  # movabs secs magic 0x431bde82d7b634db
    (0x5157ED8, 0x48),  # per-entry loop head (index load)
    (0x51580F3, 0xE8),  # call to the count-key helper 0x515fca0
    (0x5158153, 0xE8),  # memcmp in the find-or-insert walk
    (0x51581EE, 0xE8),  # call to the insert callee 0x5153650
    (0x51584C3, 0xE8),  # call to the bytes-key helper 0x515fdf0
    (0x51586D1, 0xE8),  # call to the double formatter (percent)
    (0x5158889, 0x48),  # addq $1, index
    (0x5158894, 0x48),  # cmp $0xe, index (14 entries)
    (0x5158E52, 0xF3),  # first landing stub (endbr64)
    (0x5157C0C, 0x48),  # cleanup first entry
    (0x51590AB, 0xE8),  # sole caller: builder call in 0x5158ef0
]

# .rodata vectors in the order the window copies them onto the
# stack (rsp+0xa0 first); the last copy is a movups at rsp+0x159
# that overwrites the tail of the previous vector, so the table
# is the first 185 bytes of the concatenation plus the full
# 0x207210 vector.
TABLE_VECTORS = [0x204410, 0x205CC0, 0x209190, 0x2066D0, 0x2049D0,
                 0x205670, 0x207F50, 0x208B30, 0x2091A0, 0x2053C0,
                 0x208B40, 0x205CD0]
TABLE_TAIL_VECTOR = 0x207210


def fail(message):
    print("FAIL: %s" % message)
    sys.exit(1)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", default=str(DEFAULT_BINARY))
    args = ap.parse_args(argv)
    binary = Path(args.binary)
    data = binary.read_bytes()
    if hashlib.sha256(data).hexdigest() != NODE94_SHA256:
        fail("binary SHA-256 does not match provenance/artifacts.json")

    for name, (start, stop) in EXCERPTS.items():
        result = subprocess.run(
            ["objdump", "-d", "--start-address=%s" % start,
             "--stop-address=%s" % stop, str(binary)],
            capture_output=True, text=True)
        if result.returncode != 0:
            fail("objdump failed for %s" % name)
        if result.stdout != (PACKET_DIR / name).read_text():
            fail("excerpt %s does not regenerate byte-for-byte" % name)

    manifest = (PACKET_DIR / "MANIFEST.sha256").read_text().splitlines()
    for line in manifest:
        digest, name = line.split("  ", 1)
        path = PACKET_DIR / name
        if not path.exists():
            fail("MANIFEST lists missing file %s" % name)
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            fail("MANIFEST mismatch for %s" % name)

    records_text = (PACKET_DIR / "records.json").read_text()
    records = json.loads(records_text)
    if "mnemonic" in records_text or "instructions" in records:
        fail("records.json holds per-instruction detail, not "
             "semantic records only")

    for address, first_byte in SITES:
        if data[address - 0x1000] != first_byte:
            fail("site 0x%x first byte mismatch" % address)

    table = b"".join(data[v:v + 16] for v in TABLE_VECTORS)
    table = table[:185] + data[TABLE_TAIL_VECTOR:TABLE_TAIL_VECTOR + 16]
    expected = b"".join(b"%02d" % i for i in range(100))
    if table[:200] != expected:
        fail("digit-pair table does not reconstruct as 00..99")

    if records["entry_loop"]["count"] != 14:
        fail("entry loop count is not 14")
    if records["entry_loop"]["phases"] != ["count", "bytes", "percent"]:
        fail("entry loop phases are not count/bytes/percent")
    if records["header_keys"] != ["id", "capacity",
                                  "secs_for_last_collection",
                                  "secs_since_last_collection"]:
        fail("header keys mismatch")

    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
