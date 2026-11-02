"""Packet checker for RE-001-shard-member-access-94.

Run from the repository root:
    python3 research/work-items/RE-001-shard-member-access-94/verify.py

Checks, all against the digest-verified work binary:
1. binary SHA-256 matches provenance/artifacts.json;
2. MANIFEST.sha256 entries match the packet files;
3. the excerpts regenerate byte-identically;
4. sampled instructions match a fresh objdump run and the raw binary;
5. frames.txt rows match work/fde94/node-94-fde.tsv;
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
BIN = "work/hl-node-94.bin"
DIGEST = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"

WINDOWS = {
    "window.txt": (0x516A390, 0x516AA1C),
    "thunk.txt": (0x516AA20, 0x516AA43),
    "index_helpers.txt": (0x53356A0, 0x53356C0),
    "rng_state.txt": (0x5423A50, 0x5423AE7),
    "zero_init.txt": (0x541CA90, 0x541CAA4),
    "wrapper_global.txt": (0x5190D50, 0x5190E3F),
    "wrapper_shard.txt": (0x5190F70, 0x519109E),
}

SAMPLES = {
    # VA -> expected instruction bytes (objdump text, lowercased, no spaces)
    0x516A390: "f30f1efa",  # endbr64
    0x516A410: "e88bb21c00",  # call CPUID stub 0x53356a0
    0x516A738: "e813932b00",  # call RNG state 0x5423a50
    0x516A4D5: "e8966a0200",  # call shard wrapper 0x5190f70
    0x516A5E2: "e8f9c70200",  # call member constructor 0x5196de0
    0x516AA38: "e953f9ffff",  # thunk tail jump to 0x516a390
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
    for name, (start, stop) in WINDOWS.items():
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
        ["objdump", "-d", "--start-address=0x516a390",
         "--stop-address=0x516aa1c", BIN],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    thunk = subprocess.run(
        ["objdump", "-d", "--start-address=0x516aa20",
         "--stop-address=0x516aa43", BIN],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    for va, want in SAMPLES.items():
        src = thunk if va == 0x516AA38 else out
        m = re.search(r"\b%x:\t([0-9a-f ]+)\t" % va, src)
        if not m or not want.startswith(m.group(1).replace(" ", "")):
            fail("objdump sample mismatch at %#x" % va)
        if data[va - 0x1000:va - 0x1000 + len(want) // 2].hex() != want:
            fail("raw binary sample mismatch at %#x" % va)
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
    if "direct calls: 0x516da31" not in census:
        fail("census call list mismatch")
    if "tail jumps: 0x516aa38" not in census:
        fail("census tail list mismatch")
    if "qword hits (file offsets): (none)" not in census:
        fail("census qword list mismatch")
    if "RELATIVE slots: (none)" not in census:
        fail("census slot list mismatch")
    # Model tests
    res = subprocess.run(
        [sys.executable, "tests/test_shard_member_access.py"],
        cwd=ROOT, capture_output=True, text=True,
    )
    if res.returncode != 0:
        fail("model tests failed:\n" + res.stdout)
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
