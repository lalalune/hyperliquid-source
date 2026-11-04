"""Packet checker for RE-001-destructor-pair-115.

Run from the repository root:
    python3 research/work-items/RE-001-destructor-pair-115/verify.py

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
    ("base-5f10180.objdump.txt", "0x5f10180", "0x5f101b2"),
    ("deleting-5f10d00.objdump.txt", "0x5f10d00", "0x5f10d3c"),
    ("member-605cc30.objdump.txt", "0x605cc30", "0x605cf73"),
]

SAMPLES = {
    # VA -> expected instruction bytes (objdump text, lowercased, no spaces)
    # base destructor window
    0x5F10180: "f30f1efa",  # endbr64
    0x5F10197: "488947a0",  # mov %rax,-0x60(%rdi): vptr install
    0x5F1019B: "e890ca1400",  # call member destroy 0x605cc30
    0x5F101AA: "e9110c4e00",  # jmp operator delete[] (tail)
    # deleting destructor window
    0x5F10D00: "f30f1efa",  # endbr64
    0x5F10D17: "488947a0",  # mov %rax,-0x60(%rdi): vptr install
    0x5F10D1B: "e810bf1400",  # call member destroy 0x605cc30
    0x5F10D29: "e892004e00",  # call operator delete[]
    0x5F10D31: "beb0090000",  # mov $0x9b0,%esi: object size
    0x5F10D37: "e944004e00",  # jmp sized operator delete
    # self-check instructions (anti-low-quality gate)
    0x5F101A0: "488b7b48",  # mov 0x48(%rbx),%rdi: array load
    0x5F10D20: "488b7b48",  # mov 0x48(%rbx),%rdi: array load
    0x605CC50: "488907",  # mov %rax,(%rdi): member vptr install
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
    if records["windows"]["base"]["artifact_sha256"] != DIGEST:
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
    out = (fresh["base-5f10180.objdump.txt"]
           + fresh["deleting-5f10d00.objdump.txt"]
           + fresh["member-605cc30.objdump.txt"])
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
    for key, target in (("base", "0x5f10180"), ("deleting", "0x5f10d00"),
                         ("member_destroy", "0x605cc30")):
        cen = records["census"][key]
        got = blocks.get(target)
        if got is None or any(got[k] != cen[k] for k in
                               ("direct_calls", "tail_jumps",
                                "qword_hits_file_offsets", "relative_slots")):
            fail("census mismatch for %s: %r" % (target, census))
    # Model tests pass
    test = subprocess.run(
        [sys.executable, "tests/test_object_destructor_pair_115.py"],
        cwd=ROOT, capture_output=True, text=True,
    )
    if test.returncode != 0:
        fail("model tests failed:\n%s%s" % (test.stdout, test.stderr))
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
