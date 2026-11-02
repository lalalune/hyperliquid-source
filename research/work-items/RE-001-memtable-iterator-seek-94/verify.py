"""Packet checker for RE-001-memtable-iterator-seek-94.

Run from the repository root:
    python3 research/work-items/RE-001-memtable-iterator-seek-94/verify.py

Checks, all against the digest-verified work binary:
1. binary SHA-256 matches provenance/artifacts.json;
2. MANIFEST.sha256 entries match the packet files;
3. the window excerpt regenerates byte-identically;
4. sampled instructions match a fresh objdump run and the raw binary;
5. rodata strings match records.json;
6. frames.txt rows match work/fde94/node-94-fde.tsv;
7. the caller census reproduces records.json;
8. the model test file passes under plain python3.
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
BIN = "work/hl-node-94.bin"
DIGEST = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"

SAMPLES = {
    # VA -> expected instruction bytes (objdump text, lowercased, no spaces)
    0x5168A20: "f30f1efa",  # endbr64
    0x5168B23: "ff90a0000000",  # call *0xa0(%rax): probe gate virtual
    0x5168B3F: "ff9098000000",  # call *0x98(%rax): probe transform virtual
    0x5168B50: "e81ba32b00",  # call hash 0x5422e70
    0x5168C3F: "e88cf8ffff",  # call refresh 0x51684d0
    0x5168D97: "e824412b00",  # call varint decoder 0x541cec0
    0x5168EF5: "e846e1ffff",  # call reader 0x5167040
    0x516908D: "e8de560c00",  # call report 0x522e770
}


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


def main():
    data = open(os.path.join(ROOT, BIN), "rb").read()
    if hashlib.sha256(data).hexdigest() != DIGEST:
        fail("binary digest mismatch")
    prov = json.load(open(os.path.join(ROOT, "provenance/artifacts.json")))
    paths = [f for f in prov["files"] if f["path"] == "artifacts/node/94/hl-node"]
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
        ["objdump", "-d", "--start-address=0x5168a20",
         "--stop-address=0x5169220", BIN],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    saved = open(os.path.join(HERE, "window.txt")).read()
    if out != saved:
        fail("excerpt window.txt does not regenerate")
    # Sampled instructions byte-for-byte vs fresh objdump and raw binary
    for va, want in SAMPLES.items():
        m = re.search(r"\b%x:\t([0-9a-f ]+)\t" % va, out)
        if not m or not want.startswith(m.group(1).replace(" ", "")):
            fail("objdump sample mismatch at %#x" % va)
        if data[va - 0x1000:va - 0x1000 + len(want) // 2].hex() != want:
            fail("raw binary sample mismatch at %#x" % va)
    # Rodata strings (.rodata VA == file offset in this binary)
    report = records["advance"]["report_on_failed_check"]
    fmt = report["format"]
    if data[0x7E24F8:0x7E24F8 + len(fmt)] != fmt.encode():
        fail("report format string mismatch")
    fname = report["file"]
    if data[0x1FCA36:0x1FCA36 + len(fname)] != fname.encode():
        fail("report file string mismatch")
    # Frames
    tsv = {}
    for line in open(os.path.join(ROOT, "work/fde94/node-94-fde.tsv")):
        f = line.rstrip("\n").split("\t")
        tsv[f[0]] = line.rstrip("\n")
    for line in open(os.path.join(HERE, "frames.txt")):
        line = line.rstrip("\n")
        if line and tsv.get(line.split("\t")[0]) != line:
            fail("frames row mismatch: %s" % line.split("\t")[0])
    # Census reproduction
    census = subprocess.run(
        [sys.executable, os.path.join(HERE, "census.py")],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    if "direct calls: (none)" not in census:
        fail("census call list mismatch")
    if "tail jumps: (none)" not in census:
        fail("census tail list mismatch")
    if "qword hits (file offsets): 0x189240" not in census:
        fail("census qword list mismatch")
    if "RELATIVE slots: 0x575b260" not in census:
        fail("census slot list mismatch")
    # Model tests
    res = subprocess.run(
        [sys.executable, "tests/test_memtable_iterator_seek.py"],
        cwd=ROOT, capture_output=True, text=True,
    )
    if res.returncode != 0:
        fail("model tests failed:\n" + res.stdout)
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
