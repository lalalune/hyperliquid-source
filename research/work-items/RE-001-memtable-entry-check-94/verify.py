"""Packet checker for RE-001-memtable-entry-check-94.

Run from the repository root:
    python3 research/work-items/RE-001-memtable-entry-check-94/verify.py

Checks, all against the digest-verified work binary:
1. binary SHA-256 matches provenance/artifacts.json;
2. MANIFEST.sha256 entries match the packet files;
3. window/hex/nibble excerpts regenerate byte-identically;
4. sampled instructions match a fresh objdump run and the raw binary;
5. rodata strings and the failed-detail reconstruction match records.json;
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
    0x5167040: "f30f1efa",  # endbr64
    0x5167090: "e82b5e2b00",  # call varint decoder 0x541cec0
    0x516713C: "48ba0bd59bf472ad8ad2",  # movabs suffix seed
    0x51671CF: "663906",  # cmp %ax,(%rsi): width-2 compare
    0x51672DF: "48be206661696c65642e",  # movabs " failed."
    0x5427774: "8d5730",  # nibble helper: lea 0x30(%rdi)
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
        ("window.txt", 0x5167040, 0x5167B9B),
        ("hex_helper.txt", 0x5427800, 0x5427986),
        ("nibble_helper.txt", 0x5427770, 0x5427782),
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
        ["objdump", "-d", "--start-address=0x5167040",
         "--stop-address=0x5167b9b", BIN],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    dump += subprocess.run(
        ["objdump", "-d", "--start-address=0x5427770",
         "--stop-address=0x5427782", BIN],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    for va, want in SAMPLES.items():
        m = re.search(r"\b%x:\t([0-9a-f ]+)\t" % va, dump)
        # objdump wraps long instructions onto a continuation line,
        # so the first line may hold only a prefix of the bytes; the
        # raw-binary check below covers every byte.
        if not m or not want.startswith(m.group(1).replace(" ", "")):
            fail("objdump sample mismatch at %#x" % va)
        if data[va - 0x1000:va - 0x1000 + len(want) // 2].hex() != want:
            fail("raw binary sample mismatch at %#x" % va)
    # Rodata strings
    def s(va, n):
        return data[va:va + n]
    if s(0x7DD428, 45) != records["length_prefix"]["short_detail"].encode():
        fail("short detail string mismatch")
    if s(0x7DA9B8, 35) != records["length_prefix"]["decode_failure_detail"].encode():
        fail("no-length detail string mismatch")
    if s(0x7D6028, 34) != records["suffix"]["decode_failure_detail"].encode():
        fail("no-value detail string mismatch")
    failed = (
        s(0x208EA0, 16) + s(0x203D80, 16) + s(0x2046F0, 16)
        + s(0x206700, 13) + b" failed."
    )
    if failed.decode() != records["mismatch_detail"]["base"]:
        fail("failed detail reconstruction mismatch")
    if s(0x1E0A75, 25).decode() != "Unrecognized value type: ":
        fail("frag25 mismatch")
    if s(0x1E7FA9, 10).decode() != "User key: ":
        fail("frag10 mismatch")
    if s(0x1E5BA1, 5).decode() != "seq: ":
        fail("frag5 mismatch")
    if s(0x1EB19B, 2) != b". ":
        fail("frag tail mismatch")
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
    want_calls = " ".join(records["caller_census"]["direct_call_sites"])
    if ("direct calls: " + want_calls) not in census:
        fail("census call list mismatch")
    if "tail jumps: (none)" not in census:
        fail("census tail list mismatch")
    if "RELATIVE slots: (none)" not in census:
        fail("census slot list mismatch")
    # Model tests
    res = subprocess.run(
        [sys.executable, "tests/test_memtable_entry_check.py"],
        cwd=ROOT, capture_output=True, text=True,
    )
    if res.returncode != 0:
        fail("model tests failed:\n" + res.stdout)
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
