"""Packet checker for RE-001-hash64-61c38a0-115.

Run from the repository root:
    python3 research/work-items/RE-001-hash64-61c38a0-115/verify.py

Checks, all against the digest-verified work binary:
1. binary SHA-256 matches provenance/artifacts.json;
2. MANIFEST.sha256 entries match the packet files;
3. the excerpt regenerates byte-identically;
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

SAMPLES = {
    # VA -> expected instruction bytes (objdump text, lowercased, no spaces)
    0x61C38A0: "f30f1efa",  # endbr64: entry
    0x61C38A4: "4883fe10",  # cmp $0x10,%rsi: first length gate
    0x61C38BE: "48330f",  # xor (%rdi),%rcx: 9..16 arm's first lane
    0x61C38E8: "48c1e825",  # shr $0x25,%rax: avalanche shift 37
    0x61C3910: "4881fe80000000",  # cmp $0x80,%rsi: band gate 128
    0x61C3A88: "4881fef0000000",  # cmp $0xf0,%rsi: delegation gate
    0x61C3A95: "31d2",  # xor %edx,%edx: seed zeroed for the delegate
    0x61C3A97: "e994f7ffff",  # jmp 0x61c3230: the delegate exit
    0x61C3AB0: "4885f6",  # test %rsi,%rsi: the len-0 test
    0x61C3AE6: "81f2b8fe6c39",  # xor $0x396cfeb8,%edx: 1..3 arm key
    0x61C3B50: "e93bedffff",  # jmp 0x61c2890: the seedless exit
    0x61C3B58: "c3",  # ret: the len-0 return
    # self-check instructions (anti-low-quality gate)
    0x61C38D6: "4801f1",  # add %rsi,%rcx: 9..16 arm folds len in
    0x61C3B24: "bab179379e",  # mov $0x9e3779b1,%edx: 4..8 arm prime
    0x61C3A20: "488d5437f0",  # lea -0x10(%rdi,%rsi,1),%rdx: last pair
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
    out = subprocess.run(
        ["objdump", "-d", "--start-address=0x61c38a0",
         "--stop-address=0x61c3bb9", BIN],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    saved = open(os.path.join(HERE, "main.txt")).read()
    if out != saved:
        fail("excerpt does not regenerate")
    # Sampled instructions byte-for-byte vs fresh objdump and raw binary
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
        [sys.executable, "tests/test_hash64_61c38a0_115.py"],
        cwd=ROOT, capture_output=True, text=True,
    )
    if test.returncode != 0:
        fail("model tests failed:\n%s%s" % (test.stdout, test.stderr))
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
