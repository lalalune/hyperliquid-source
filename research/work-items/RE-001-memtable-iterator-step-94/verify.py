"""Packet checker for RE-001-memtable-iterator-step-94.

Run from the repository root:
    python3 research/work-items/RE-001-memtable-iterator-step-94/verify.py

Checks, all against the digest-verified work binary:
1. binary SHA-256 matches provenance/artifacts.json;
2. MANIFEST.sha256 entries match the packet files;
3. window/key-provider/predicate excerpts regenerate byte-identically;
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
    0x5168160: "f30f1efa",  # endbr64
    0x51681C5: "ff5020",  # call *0x20(%rax): inner next virtual
    0x516833F: "e8fcecffff",  # call reader 0x5167040 (e8 fc ec ff ff)
    0x51683BD: "e8ae630c00",  # call report 0x522e770
    0x51657E0: "f30f1efa",  # key provider endbr64
    0x516581D: "e89e762b00",  # call varint decoder 0x541cec0
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
    for name, start, stop in [
        ("window.txt", 0x5168160, 0x51683FB),
        ("key_provider.txt", 0x51657E0, 0x516584B),
        ("predicate.txt", 0x51647B0, 0x51647C4),
    ]:
        out = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % start,
             "--stop-address=%#x" % stop, BIN],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout
        saved = open(os.path.join(HERE, name)).read()
        if out != saved:
            fail("excerpt %s does not regenerate" % name)
    # Sampled instructions byte-for-byte vs fresh objdump and raw binary
    dump = subprocess.run(
        ["objdump", "-d", "--start-address=0x5168160",
         "--stop-address=0x51683fb", BIN],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    dump += subprocess.run(
        ["objdump", "-d", "--start-address=0x51657e0",
         "--stop-address=0x516584b", BIN],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    for va, want in SAMPLES.items():
        m = re.search(r"\b%x:\t([0-9a-f ]+)\t" % va, dump)
        if not m or not want.startswith(m.group(1).replace(" ", "")):
            fail("objdump sample mismatch at %#x" % va)
        if data[va - 0x1000:va - 0x1000 + len(want) // 2].hex() != want:
            fail("raw binary sample mismatch at %#x" % va)
    # Rodata strings (.rodata VA == file offset in this binary)
    fmt = records["report"]["format"]
    if data[0x7E24F8:0x7E24F8 + len(fmt)] != fmt.encode():
        fail("report format string mismatch")
    fname = records["report"]["file"]
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
    if "RELATIVE slots: 0x575b270" not in census:
        fail("census slot list mismatch")
    # Model tests
    res = subprocess.run(
        [sys.executable, "tests/test_memtable_iterator_step.py"],
        cwd=ROOT, capture_output=True, text=True,
    )
    if res.returncode != 0:
        fail("model tests failed:\n" + res.stdout)
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
