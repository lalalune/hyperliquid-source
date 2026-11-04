"""Packet checker for RE-001-shared-table-resize-115.

Run from the repository root:
    python3 research/work-items/RE-001-shared-table-resize-115/verify.py

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
    ("window-5f0b420.objdump.txt", "0x5f0b420", "0x5f0b5d2"),
    ("helper-5f0a1dc.objdump.txt", "0x5f0a1dc", "0x5f0a287"),
    ("dispose-5d35070.objdump.txt", "0x5d35070", "0x5d350bc"),
]

SAMPLES = {
    # VA -> expected instruction bytes (objdump text, lowercased, no spaces)
    0x5F0B420: "f30f1efa",  # endbr64
    0x5F0B438: "e8635f4e00",  # call hardware_concurrency PLT
    0x5F0B526: "f00fc102",  # lock xadd %eax,(%rdx): atomic decrement
    0x5F0B55C: "e9df584e00",  # jmp sized delete[] PLT
    # self-check instructions (anti-low-quality gate)
    0x5F0B462: "894b08",  # mov %ecx,0x8(%rbx): log field store
    0x5F0B5A0: "c7430803000000",  # movl $0x3,0x8(%rbx): small-path log
    0x5F0B4AB: "0f11440808",  # movups %xmm0,0x8(%rax,%rcx,1): zero-fill
    # (the movabs sentinel at 0x5f0b4d9 and the movabs at 0x5f0a1e7
    # wrap across objdump lines, so they are checked via the
    # verbatim excerpts, not this regex)
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
    out = fresh["window-5f0b420.objdump.txt"]
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
    # Model tests pass
    test = subprocess.run(
        [sys.executable, "tests/test_shared_table_resize_115.py"],
        cwd=ROOT, capture_output=True, text=True,
    )
    if test.returncode != 0:
        fail("model tests failed:\n%s%s" % (test.stdout, test.stderr))
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
