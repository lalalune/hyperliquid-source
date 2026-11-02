"""Packet checker for RE-001-probe-gated-lookup-94.

Run from the repository root:
    python3 research/work-items/RE-001-probe-gated-lookup-94/verify.py

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
    "window.txt": (0x516CA20, 0x516D0D4),
    "driver.txt": (0x516C7E0, 0x516C9D7),
    "transform.txt": (0x51922D0, 0x51923DA),
    "move_helper.txt": (0x5164CE0, 0x5164D49),
    "timer_destructor.txt": (0x5165320, 0x516537B),
    "thunk.txt": (0x516AA20, 0x516AA43),
    "hash.txt": (0x5422E70, 0x5422EF5),
}

SAMPLES = {
    # VA -> expected instruction bytes (objdump text, lowercased, no spaces)
    0x516CA20: "f30f1efa",  # endbr64
    0x516CAB5: "488b87180c0000",  # mov host+0xc18
    0x516CB83: "e898deffff",  # call thunk 0x516aa20
    0x516CBB5: "e816570200",  # call transform 0x51922d0
    0x516CCB1: "e8ba612b00",  # call hash 0x5422e70
    0x516CF2C: "e8aff8ffff",  # call driver 0x516c7e0
    0x516CF78: "e8637dffff",  # call move helper 0x5164ce0
    0x516CDF7: "e82485ffff",  # call timer destructor 0x5165320
    0x516C95F: "e8cce7ffff",  # driver: call Seek 0x516b130
    0x51922F0: "e8abedffff",  # transform: call 0x51910a0
    0x5164D40: "e93bb74f00",  # move helper: jmp operator delete[]
    0x516AA35: "0fb6c9",  # thunk: movzbl %cl,%ecx
    # Pre-submit self-check extras (picked after the model was written):
    0x516CC7E: "ff90a0000000",  # call *0xa0(%rax) probe predicate
    0x516CD26: "498b0cc9",  # mov (%r9,%rcx,8),%rcx probe word
    0x516CE60: "48c1c80c",  # ror $0xc,%rax probe rotation
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
    want_calls = ("direct calls: 0x4fc0e7d 0x4fc1776 0x4fd902c 0x50d018b "
                  "0x50dc842 0x512c470 0x512cc57 0x517251e 0x5172661")
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
        [sys.executable, "tests/test_probe_gated_lookup.py"],
        cwd=ROOT, capture_output=True, text=True,
    )
    if res.returncode != 0:
        fail("model tests failed:\n" + res.stdout)
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
