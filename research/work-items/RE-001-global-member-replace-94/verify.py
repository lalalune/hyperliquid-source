"""Packet checker for RE-001-global-member-replace-94.

Run from the repository root:
    python3 research/work-items/RE-001-global-member-replace-94/verify.py

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
    "window.txt": (0x5169DA0, 0x516A2D9),
    "cleanup.txt": (0x5169CEA, 0x5169D9B),
}

SAMPLES = {
    # VA -> expected instruction bytes (objdump text, lowercased, no spaces)
    0x5169DA0: "f30f1efa",  # endbr64, replace entry
    0x5169DC4: "0fb687600a0000",  # movzbl host +0xa60 guard
    0x5169E00: "e88b664f00",  # call new (0x80 member)
    0x5169EAC: "48894550",  # mov result to member +0x50
    0x5169F39: "4c89abe00c0000",  # install new wrapper at host +0xce0
    0x5169F88: "e8232b2b00",  # call drain 0x541cab0 (old +0x98)
    0x516A06B: "e9d0634f00",  # tail-jump delete of the 0xe8 wrapper
    0x5169CEA: "488b7d70",  # cleanup: member +0x70 detail
    0x5169D05: "e8a62d2b00",  # cleanup: call drain 0x541cab0
    0x5169D2B: "e810674f00",  # cleanup: call delete (0x80 member)
    # Pre-submit self-check extras (picked after the model was written):
    0x5169E91: "88455a",  # mov +0x5a (host +0x31 XOR 1)
    0x5169F73: "e8c8644f00",  # call delete (+0xc0 array buffer)
    0x516A18E: "ffd0",  # call *%rax (+0x98 callback)
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
            ["objdump", "-d",
             "--start-address=%#x" % start,
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
        ["python3", os.path.join(ROOT, "tests/test_global_member_replace.py")],
        cwd=ROOT, capture_output=True, text=True,
    )
    if out.returncode != 0:
        fail("model tests failed:\n" + out.stdout + out.stderr)
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
