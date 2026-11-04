"""Packet checker for RE-001-arena-allocate-aligned-115.

Run from the repository root:
    python3 research/work-items/RE-001-arena-allocate-aligned-115/verify.py

Checks, all against the digest-verified work binary:
1. binary SHA-256 matches provenance/artifacts.json;
2. MANIFEST.sha256 entries match the packet files;
3. the excerpts regenerate byte-identically;
4. sampled instructions match a fresh objdump run and the raw binary
   (including 3 self-check instructions picked for this packet);
5. frames.txt rows match a fresh objdump frames dump;
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

EXCERPTS = [
    ("main-605d7b0.objdump.txt", "0x605d7b0", "0x605d926"),
    ("slow-605d6c0.objdump.txt", "0x605d6c0", "0x605d785"),
    ("stub-605d786.objdump.txt", "0x605d786", "0x605d7ab"),
]

SAMPLES = {
    # VA -> expected instruction bytes (objdump text, lowercased, no spaces)
    # main window
    0x605D7B0: "f30f1efa",  # endbr64
    0x605D7F0: "488b93c8080000",  # mov 0x8c8(%rbx),%rdx: cursor load
    0x605D817: "488993c8080000",  # mov %rdx,0x8c8(%rbx): cursor store
    0x605D88D: "e92efeffff",  # jmp slow window
    0x605D8AF: "e84cf7ffff",  # call grow 0x605d000
    0x605D8EB: "e8b014f7ff",  # call report 0x5fceda0
    # slow window
    0x605D6C0: "f30f1efa",  # endbr64
    0x605D6CF: "4c8bb710080000",  # mov 0x810(%rdi),%r14: hint load
    0x605D701: "e8bafcffff",  # call block callee 0x605d3c0
    # stub window
    0x605D786: "4c89ef",  # mov %r13,%rdi: string address for dispose
    0x605D789: "e822363900",  # call _M_dispose
    # self-check instructions (anti-low-quality gate)
    0x605D7F7: "4889ee",  # mov %rbp,%rsi: size into fast path
    0x605D8C2: "4989e5",  # mov %rsp,%r13: save string slot
    0x605D706: "4c89e2",  # mov %r12,%rdx: hint minus size setup
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
    if records["artifact_sha256"] != DIGEST:
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
    # Excerpt regeneration (all three excerpts)
    fresh = {}
    for name, start, stop in EXCERPTS:
        out = subprocess.run(
            ["objdump", "-d",
             "--start-address=" + start, "--stop-address=" + stop, BIN],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout
        fresh[name] = out
        saved = open(os.path.join(HERE, name)).read()
        if out != saved:
            fail("excerpt does not regenerate: %s" % name)
    # Sampled instructions byte-for-byte vs fresh objdump and raw binary
    out = "".join(fresh.values())
    for va, want in SAMPLES.items():
        m = re.search(r"^\s*%x:\t([0-9a-f ]+)\t" % va, out, re.M)
        if not m:
            fail("sample %s missing from fresh objdump" % hex(va))
        if m.group(1).replace(" ", "") != want:
            fail("sample %s objdump mismatch" % hex(va))
        off = va - 0x1000  # .text file offset = VA - 0x1000
        if data[off:off + len(bytes.fromhex(want))].hex() != want:
            fail("sample %s raw binary mismatch" % hex(va))
    # Frames rows vs fresh objdump frames dump
    frames = subprocess.run(
        ["objdump", "--dwarf=frames", BIN],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    saved = [ln for ln in open(os.path.join(HERE, "frames.txt")).read().splitlines() if ln]
    for row in saved:
        if row not in frames:
            fail("frames row missing from fresh objdump: %s" % row)
    # Census reproduces records.json
    census = subprocess.run(
        [sys.executable, os.path.join(HERE, "census.py"), BIN],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    blocks = {}
    current = None
    for line in census.splitlines():
        m = re.match(r"target (0x[0-9a-f]+)", line)
        if m:
            current = m.group(1)
            blocks[current] = {}
            continue
        m = re.match(r"  direct calls: (.*)", line)
        if m and current:
            blocks[current]["direct_calls"] = [] if m.group(1) == "(none)" else m.group(1).split()
        m = re.match(r"  tail jumps: (.*)", line)
        if m and current:
            blocks[current]["tail_jumps"] = [] if m.group(1) == "(none)" else m.group(1).split()
        m = re.match(r"  qword hits \(file offsets\): (.*)", line)
        if m and current:
            blocks[current]["qword_hits_file_offsets"] = [] if m.group(1) == "(none)" else m.group(1).split()
        m = re.match(r"  RELATIVE slots: (.*)", line)
        if m and current:
            blocks[current]["relative_slots"] = [] if m.group(1) == "(none)" else m.group(1).split()
    for key, target in (("main", "0x605d7b0"), ("slow", "0x605d6c0")):
        cen = records["census"][key]
        got = blocks.get(target)
        if got is None or any(got[k] != cen[k] for k in
                               ("direct_calls", "tail_jumps",
                                "qword_hits_file_offsets", "relative_slots")):
            fail("census mismatch for %s: %r" % (target, census))
    # Model tests pass
    tests = subprocess.run(
        [sys.executable, os.path.join(ROOT, "tests",
                                      "test_arena_allocate_aligned_115.py")],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    if "failed" in tests and "0 failed" not in tests:
        fail("model tests failed:\n%s" % tests)
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
