#!/usr/bin/env python3
"""Verify the RE-001-counters-uptime-94 evidence packet.

Stdlib only. Run from the repository root:

    python3 research/work-items/RE-001-counters-uptime-94/verify.py \\
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
     vectors (in stack-address order, with the final overlapping
     movups) as exactly "00".."99";
  7. the entry loop covers 9 counters, and the uptime key is
     "db.uptime".
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
    "window.objdump.txt": ("0x5159180", "0x5159950"),
    "cleanup.objdump.txt": ("0x515914e", "0x5159180"),
    "find.objdump.txt": ("0x5153a70", "0x5153bb6"),
    "insert.objdump.txt": ("0x5153650", "0x515383b"),
    "dblfmt.objdump.txt": ("0x514c050", "0x514c1b5"),
    "strctor.objdump.txt": ("0x514b6d0", "0x514b7b3"),
    "compare.objdump.txt": ("0x514b340", "0x514b38e"),
    "moveassign.objdump.txt": ("0x514b4f0", "0x514b5c8"),
    "caller.objdump.txt": ("0x5159950", "0x5159968"),
}

# (address, first byte) spot checks for the sites records.json pins.
# .text file offset = VA - 0x1000 for this binary.
SITES = [
    (0x5159180, 0xF3),  # endbr64 at the window start
    (0x51591D0, 0x4D),  # loop head: mov (%r12),%r15
    (0x515926C, 0xE8),  # call to _M_construct (itoa string)
    (0x51593BD, 0x41),  # single-digit tail arm
    (0x51593C3, 0x49),  # global-map root load
    (0x515942F, 0xE8),  # call to the find-or-insert 0x5153a70
    (0x51594B9, 0x48),  # clock part entry: outer reload
    (0x5159528, 0xFF),  # indirect call *0x98(%rax) (third clock node)
    (0x5159544, 0xF2),  # cvtsi2sd (non-negative elapsed arm)
    (0x515956C, 0xE8),  # call to the double formatter 0x514c050
    (0x5159585, 0xE8),  # call to the string constructor 0x514b6d0
    (0x5159629, 0xE8),  # call to the string compare 0x514b340
    (0x515963D, 0xE8),  # call to the move-assign 0x514b4f0
    (0x5159768, 0x4B),  # two-digit tail arm
    (0x51597A6, 0xE8),  # call to throw_out_of_range ("map::at")
    (0x51598C1, 0x48),  # negative-elapsed unsigned-conversion arm
    (0x51598F6, 0xE8),  # call to the insert 0x5153650
    (0x515914E, 0x48),  # cleanup full entry
    (0x5159158, 0x4C),  # cleanup %f-only entry
    (0x515992B, 0xF3),  # first landing stub (endbr64)
    (0x5159958, 0xE8),  # sole caller: wrapper call to the window
]

# .rodata vectors in stack-address order (rsp+0x70 first); the last
# copy is a movups at rsp+0x129 that overwrites the tail of the
# previous vector, so the table is the first 185 bytes of the
# concatenation plus the full 0x207210 vector.
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

    if records["phase_1_counters"]["count"] != 9:
        fail("entry loop count is not 9")
    if records["constants"]["uptime_key"] != '"db.uptime" at 0x1eb2b6':
        fail("uptime key mismatch")

    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
