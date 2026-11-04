"""Packet checker for RE-014-memtable-iterator-seek-gate-115.

Run from the repository root:
    python3 research/work-items/RE-014-memtable-iterator-seek-gate-115/verify.py

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
    0x5F08C40: "f30f1efa",  # endbr64
    0x5F08D37: "483b0d7a4a5e00",  # cmp slot 0x64ed7b8, %rcx: chain gate
    0x5F08DD5: "e8c6a62b00",  # call hash 0x61c34a0
    0x5F08EBF: "e83cfcffff",  # call refresh 0x5f08b00
    0x5F08DA8: "ff90a0000000",  # call *0xa0(%rax): chain predicate
    0x5F08DC4: "ff9098000000",  # call *0x98(%rax): probe transform
    # self-check instructions (anti-low-quality gate)
    0x5F08E02: "430f180cc1",  # prefetcht0: probe prefetch
    0x5F08E46: "498b0cc9",  # mov (%r9,%rcx,8),%rcx: probe word load
    0x5F08F75: "e8d6c9ffff",  # call timer destroy 0x5f05950
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
            ("window-5f08c40.objdump.txt", (0x5F08C40, 0x5F09047)),
            ("timer-5f05950.objdump.txt", (0x5F05950, 0x5F059AB))):
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
        ["objdump", "-d", "--start-address=0x5f08c40",
         "--stop-address=0x5f09047", BIN],
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
                                      "test_memtable_iterator_seek_gate_115.py")],
        cwd=ROOT, capture_output=True, text=True,
    )
    if tests.returncode != 0:
        fail("model tests failed:\n" + tests.stdout + tests.stderr)
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
