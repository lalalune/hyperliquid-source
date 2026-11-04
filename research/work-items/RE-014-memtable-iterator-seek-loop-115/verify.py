"""Packet checker for RE-014-memtable-iterator-seek-loop-115.

Run from the repository root:
    python3 research/work-items/RE-014-memtable-iterator-seek-loop-115/verify.py

Checks, all against the digest-verified work binary:
1. binary SHA-256 matches provenance/artifacts.json;
2. MANIFEST.sha256 entries match the packet files;
3. the excerpts regenerate byte-identically;
4. sampled instructions match a fresh objdump run and the raw binary
   (including 3 self-check instructions picked for this packet);
5. frames.txt rows match a fresh readelf frames-interp dump;
6. the caller census reproduces records.json;
7. the model test file passes under plain python3.
Prints ALL CHECKS PASSED or the first failure.
"""

import hashlib
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
BIN = "work/hl-node-115.bin"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

SAMPLES = {
    # VA -> expected instruction bytes (objdump text, lowercased, no spaces)
    0x5F09050: "f30f1efa",  # endbr64
    0x5F09180: "e81ba32b00",  # call hash 0x61c34a0
    0x5F0926F: "e88cf8ffff",  # call refresh 0x5f08b00
    0x5F09277: "4c8d3d62bbffff",  # lea known predicate 0x5f04de0
    0x5F093C7: "e824412b00",  # call varint 0x61bd4f0
    0x5F09525: "e846e1ffff",  # call reader 0x5f07670
    0x5F096BD: "e8de560c00",  # call report 0x5fceda0
    # self-check instructions (anti-low-quality gate)
    0x5F091AC: "430f180cc1",  # prefetcht0: probe prefetch
    0x5F091EE: "498b0cc9",  # mov (%r9,%rcx,8),%rcx: probe word load
    0x5F096FD: "e84ec2ffff",  # call timer destroy 0x5f05950
}


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


def main():
    data = open(os.path.join(ROOT, BIN), "rb").read()
    if hashlib.sha256(data).hexdigest() != DIGEST:
        fail("binary digest mismatch")
    prov = json.load(open(os.path.join(ROOT, "provenance/artifacts.json")))
    paths = [f for f in prov["files"] if f["path"] == "artifacts/node/115/hl-node"]
    if not paths or paths[0]["sha256"] != DIGEST:
        fail("provenance digest mismatch")
    records = json.load(open(os.path.join(HERE, "records.json")))
    if records["window"]["artifact_sha256"] != DIGEST:
        fail("records digest mismatch")
    # MANIFEST
    manifest = {}
    for line in open(os.path.join(HERE, "MANIFEST.sha256")):
        parts = line.split()
        if len(parts) == 2:
            manifest[parts[1]] = parts[0]
    for name, want in manifest.items():
        got = hashlib.sha256(open(os.path.join(HERE, name), "rb").read()).hexdigest()
        if got != want:
            fail("manifest mismatch for %s" % name)
    # Excerpt regeneration
    for name, (start, stop) in (
            ("window-5f09050.objdump.txt", (0x5F09050, 0x5F09850)),
            ("timer-5f05950.objdump.txt", (0x5F05950, 0x5F059AB)),
            ("refresh-5f08b00.objdump.txt", (0x5F08B00, 0x5F08C34))):
        out = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % start,
             "--stop-address=%#x" % stop, BIN],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout
        saved = open(os.path.join(HERE, name)).read()
        if out != saved:
            fail("excerpt %s does not regenerate" % name)
    # Sampled instructions byte-for-byte vs fresh objdump and raw binary
    out = subprocess.run(
        ["objdump", "-d", "--start-address=0x5f09050",
         "--stop-address=0x5f09850", BIN],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    for va, want in SAMPLES.items():
        m = re.search(r"^\s*%x:\t([0-9a-f ]+)\t" % va, out, re.M)
        if not m:
            fail("sample %s missing from fresh objdump" % hex(va))
        if m.group(1).replace(" ", "") != want:
            fail("sample %s objdump mismatch" % hex(va))
        off = va - 0x1000  # .text file offset = VA - 0x1000
        if data[off:off + len(bytes.fromhex(want))].hex() != want:
            fail("sample %s raw binary mismatch" % hex(va))
    # Frames rows vs fresh readelf dump
    frames = subprocess.run(
        ["readelf", "--debug-dump=frames-interp", BIN],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    saved = [ln for ln in open(os.path.join(HERE, "frames.txt")).read().splitlines() if ln]
    for row in saved:
        if row not in frames:
            fail("frames row missing from fresh readelf: %s" % row)
    # Census reproduces records.json
    census = subprocess.run(
        [sys.executable, os.path.join(HERE, "census.py"), BIN],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    m = re.search(r"direct calls: (.*)", census)
    calls = [] if m.group(1) == "(none)" else m.group(1).split()
    m = re.search(r"tail jumps: (.*)", census)
    tails = [] if m.group(1) == "(none)" else m.group(1).split()
    m = re.search(r"qword hits \(file offsets\): (.*)", census)
    hits = [] if m.group(1) == "(none)" else m.group(1).split()
    m = re.search(r"RELATIVE slots: (.*)", census)
    slots = [] if m.group(1) == "(none)" else m.group(1).split()
    cen = records["census"]
    if (calls != cen["direct_calls"] or tails != cen["tail_jumps"]
            or hits != cen["qword_hits_file_offsets"]
            or slots != cen["relative_slots"]):
        fail("census mismatch: %r" % census)
    # Model tests
    tests = subprocess.run(
        [sys.executable, os.path.join(ROOT, "tests",
                                      "test_memtable_iterator_seek_loop_115.py")],
        cwd=ROOT, capture_output=True, text=True,
    )
    if tests.returncode != 0:
        fail("model tests failed:\n" + tests.stdout + tests.stderr)
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
