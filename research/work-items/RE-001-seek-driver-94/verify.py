"""Packet checker for RE-001-seek-driver-94.

Run from the repository root:
    python3 research/work-items/RE-001-seek-driver-94/verify.py

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
    "window.txt": (0x516C7E0, 0x516C9D7),
    "generic_loop.txt": (0x51651E0, 0x51652AC),
}

SAMPLES = {
    # VA -> expected instruction bytes (objdump text, lowercased, no spaces)
    0x516C7E0: "f30f1efa",  # endbr64, driver entry
    0x516C8E5: "488d15f488ffff",  # lea known loop 0x51651e0
    0x516C90A: "483b15afba6000",  # cmp GOT 0x57783c0
    0x516C917: "ff9090000000",  # call *0x90(%rax)
    0x516C949: "ff5130",  # call *0x30(%rcx) initial seek
    0x516C95F: "e8cce7ffff",  # call Seek 0x516b130
    0x516C96E: "ff5020",  # call *0x20(%rax) advance
    0x516C9C8: "ffd2",  # call *%rdx (+0x98 direct)
    0x51651E0: "f30f1efa",  # endbr64, generic loop entry
    0x5165211: "483b15a8316100",  # cmp GOT 0x57783c0
    0x516524B: "ff5130",  # call *0x30(%rcx) initial seek
    0x516525F: "41ffd4",  # call *%r12 callback
    # Pre-submit self-check extras (picked after the model was written):
    0x516C8AC: "488bb8500a0000",  # mov 0xa50(%rax),%rdi
    0x516C920: "488b5508",  # mov 0x8(%rbp),%rdx slice start
    0x5165227: "498b5508",  # mov 0x8(%r13),%rdx slice start
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
        f = line.rstrip("\n").split("\t")
        if tsv.get(f[0]) != line.rstrip("\n"):
            fail("frames mismatch for %s" % f[0])
    # Census
    out = subprocess.run(
        ["python3", os.path.join(HERE, "census.py")],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    for call in records["census"]["direct_calls"]:
        if call not in out:
            fail("census missing call %s" % call)
    if "(none)" not in out.split("tail jumps:")[1].split("\n")[0]:
        fail("unexpected tail jumps")
    if records["census"]["relative_slots"]:
        fail("records claim RELATIVE slots but census found none")
    # Model tests
    out = subprocess.run(
        ["python3", os.path.join(ROOT, "tests/test_seek_driver.py")],
        cwd=ROOT, capture_output=True, text=True,
    )
    if out.returncode != 0:
        fail("model tests failed:\n" + out.stdout + out.stderr)
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
