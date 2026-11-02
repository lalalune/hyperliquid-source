"""Packet checker for RE-001-min-scan-115.

Run from the repository root:
    python3 research/work-items/RE-001-min-scan-115/verify.py

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
    ("main-5f134b0.objdump.txt", "0x5f134b0", "0x5f135c1"),
    ("value-5f0a1d0.objdump.txt", "0x5f0a1d0", "0x5f0a1dc"),
    ("caller-5d8bd30.objdump.txt", "0x5d8bd30", "0x5d8bd9d"),
]

SAMPLES = {
    # VA -> expected instruction bytes (objdump text, lowercased, no spaces)
    0x5F134B0: "f30f1efa",  # endbr64
    0x5F134BE: "4c8b6f08",  # mov 0x8(%rdi),%r13: list sentinel
    0x5F134D8: "488b7b10",  # mov 0x10(%rbx),%rdi: node key record
    0x5F1352E: "49f7f0",  # div %r8: hash bucket division
    0x5F13580: "e84b6cffff",  # call 0x5f0a1d0: value callee
    0x5F1358A: "498d5424ff",  # lea -0x1(%r12),%rdx: min update
    0x5F13592: "4c0f43e0",  # cmovae %rax,%r12: take smaller
    0x5F135A6: "4c89e0",  # mov %r12,%rax: return minimum
    0x5F0A1D4: "488b87380c0000",  # mov 0xc38(%rdi),%rax: value load
    0x5D8BD5C: "e84f771800",  # call 0x5f134b0: caller scan call
    # self-check instructions (anti-low-quality gate)
    0x5F134EC: "488b4510",  # mov 0x10(%rbp),%rax: linear chain head
    0x5F13535: "4c8b0cd0",  # mov (%rax,%rdx,8),%r9: bucket slot
    0x5F134F5: "e986000000",  # jmp 0x5f13580: fallthrough to call path
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
    # Excerpt regeneration
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
    cen = records["census"]["main"]
    got = blocks.get("0x5f134b0")
    if got is None or any(got[k] != cen[k] for k in
                           ("direct_calls", "tail_jumps",
                            "qword_hits_file_offsets", "relative_slots")):
        fail("census mismatch for main: %r" % census)
    # Model tests pass
    tests = subprocess.run(
        [sys.executable, os.path.join(ROOT, "tests",
                                      "test_min_scan_115.py")],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    if "failed" in tests and "0 failed" not in tests:
        fail("model tests failed:\n%s" % tests)
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
