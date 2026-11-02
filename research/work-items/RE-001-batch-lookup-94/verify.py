"""Packet checker for RE-001-batch-lookup-94.

Run from the repository root:
    python3 research/work-items/RE-001-batch-lookup-94/verify.py

Checks, all against the digest-verified work binary:
1. binary SHA-256 matches provenance/artifacts.json;
2. MANIFEST.sha256 entries match the packet files;
3. the excerpts regenerate byte-identically;
4. sampled instructions match a fresh objdump run and the raw binary
   (including three extra self-check instructions picked after the
   model was written, to mimic the pre-submit self-check);
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
    "window.txt": (0x516D110, 0x516DC97),
    "stub.txt": (0x516D0D4, 0x516D110),
}

SAMPLES = {
    # VA -> expected instruction bytes (objdump text, lowercased, no spaces)
    0x516D110: "f30f1efa",  # endbr64
    0x516D153: "488b87180c0000",  # mov host+0xc18
    0x516D18B: "e850051600",  # call perf helper 0x52cd6e0
    0x516D443: "e8285a2b00",  # call hash 0x5422e70
    0x516D758: "e883f0ffff",  # call driver 0x516c7e0
    0x516DA31: "e85ac9ffff",  # call sharded access 0x516a390
    0x516DA6C: "e85f480200",  # call transform 0x51922d0
    0x516D7D9: "e8427bffff",  # call timer destructor 0x5165320
    0x516D0DA: "ff5008",  # stub: call *0x8(%rax) member release
    # Pre-submit self-check extras (picked after the model was written):
    0x516D5F8: "e8e3001600",  # call perf helper 0x52cd6e0 (probe-pass path)
    0x516D8A5: "e8d62b4f00",  # call operator delete[]
    0x516DC7A: "e8b1274f00",  # call __stack_chk_fail
}


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


def file_for(va):
    for name, (start, stop) in WINDOWS.items():
        if start <= va < stop:
            return name
    return None


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
    dumps = {}
    for name, (start, stop) in WINDOWS.items():
        out = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % start,
             "--stop-address=%#x" % stop, BIN],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout
        dumps[name] = out
        saved = open(os.path.join(HERE, name)).read()
        if out != saved:
            fail("excerpt %s does not regenerate" % name)
    # Sampled instructions byte-for-byte vs fresh objdump and raw binary
    for va, want in SAMPLES.items():
        src = dumps[file_for(va)]
        m = re.search(r"\b%x:\t([0-9a-f ]+)\t" % va, src)
        if not m or m.group(1).replace(" ", "") != want:
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
    want_calls = "direct calls: 0x4fb3716 0x517244b"
    if want_calls not in census:
        fail("census call list mismatch")
    if "tail jumps: (none)" not in census:
        fail("census tail list mismatch")
    if "qword hits (file offsets): (none)" not in census:
        fail("census qword list mismatch")
    if "RELATIVE slots: (none)" not in census:
        fail("census slot list mismatch")
    if records["census"]["direct_calls"] != want_calls.split(": ", 1)[1].split():
        fail("records census mismatch")
    # Model tests
    res = subprocess.run(
        [sys.executable, "tests/test_batch_lookup.py"],
        cwd=ROOT, capture_output=True, text=True,
    )
    if res.returncode != 0:
        fail("model tests failed:\n" + res.stdout)
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
