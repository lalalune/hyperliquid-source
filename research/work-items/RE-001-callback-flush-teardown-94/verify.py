"""Packet checker for RE-001-callback-flush-teardown-94.

Checks, all against the real binary (no synthetic fixtures):
1. work/hl-node-94.bin SHA-256 matches records.json.
2. MANIFEST.sha256 matches every packet file except itself.
3. Each excerpt regenerates byte-for-byte from a fresh objdump run
   (repository root, relative binary path).
4. Five sampled instructions match byte-for-byte against the fresh
   objdump output and the raw binary bytes.
5. frames.txt carries the FDE rows for the window and its four callees.
6. relocations.txt carries the RELATIVE row for the 0x575b310 slot.
7. The caller census matches records.json (0 direct calls, 0 tail
   jumps, 1 qword at file offset 0x189438), via census.py.
8. records.json parses and carries the window, census and layout keys.

Run from the repository root: python3 research/work-items/RE-001-callback-flush-teardown-94/verify.py
"""

import hashlib
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
PACKET = os.path.join(ROOT, "research", "work-items", "RE-001-callback-flush-teardown-94")
BINARY = os.path.join(ROOT, "work", "hl-node-94.bin")

WINDOWS = [
    ("window-5165b80.txt", 0x5165B80, 0x5165F18),
    ("callee-5164af0.txt", 0x5164AF0, 0x5164BC5),
    ("callee-5164da0.txt", 0x5164DA0, 0x5165048),
    ("callee-5165380.txt", 0x5165380, 0x5165549),
    ("callee-541cab0.txt", 0x541CAB0, 0x541CB01),
]

# (address, raw bytes) sampled from the excerpts.
SAMPLES = [
    (0x5165B80, bytes.fromhex("f30f1efa")),      # endbr64, window entry
    (0x5165DB3, bytes.fromhex("ff5308")),        # array callback call
    (0x5165DF6, bytes.fromhex("ffd0")),          # list head callback call
    (0x5165E10, bytes.fromhex("ff13")),          # tail node callback call
    (0x5165C04, bytes.fromhex("e877f7ffff")),    # tree teardown call
]

FRAME_STARTS = ["0x5165b80", "0x5164af0", "0x5164da0", "0x5165380", "0x541cab0"]

FAILURES = []


def check(label, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + label + ((" " + detail) if detail and not ok else ""))
    if not ok:
        FAILURES.append(label)


def main():
    sys.dont_write_bytecode = True
    with open(os.path.join(PACKET, "records.json")) as f:
        records = json.load(f)
    data = open(BINARY, "rb").read()
    digest = hashlib.sha256(data).hexdigest()
    check("binary digest matches records.json",
          digest == records["artifact"]["sha256"])

    manifest = {}
    with open(os.path.join(PACKET, "MANIFEST.sha256")) as f:
        for line in f:
            parts = line.split()
            if len(parts) == 2:
                manifest[parts[1]] = parts[0]
    manifest_ok = True
    for name in sorted(os.listdir(PACKET)):
        if name == "MANIFEST.sha256":
            continue
        path = os.path.join(PACKET, name)
        if not os.path.isfile(path):
            continue
        actual = hashlib.sha256(open(path, "rb").read()).hexdigest()
        if manifest.get(name) != actual:
            manifest_ok = False
    check("MANIFEST.sha256 matches packet files", manifest_ok)

    excerpts_ok = True
    for name, start, end in WINDOWS:
        out = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % start,
             "--stop-address=%#x" % end, "work/hl-node-94.bin"],
            cwd=ROOT, capture_output=True, text=True, check=True).stdout
        with open(os.path.join(PACKET, name)) as f:
            if f.read() != out:
                excerpts_ok = False
    check("excerpts regenerate byte-for-byte", excerpts_ok)

    samples_ok = True
    window_text = subprocess.run(
        ["objdump", "-d", "--start-address=0x5165b80",
         "--stop-address=0x5165f18", "work/hl-node-94.bin"],
        cwd=ROOT, capture_output=True, text=True, check=True).stdout
    for va, raw in SAMPLES:
        off = va - 0x1000  # objdump VA -> file offset, verified
        if data[off:off + len(raw)] != raw:
            samples_ok = False
        line = re.search(r"^\s*%x:\t([0-9a-f ]+)\t" % va, window_text,
                         re.MULTILINE)
        if not line or bytes.fromhex(line.group(1).strip()) != raw:
            samples_ok = False
    check("sampled instructions byte-for-byte", samples_ok)

    with open(os.path.join(PACKET, "frames.txt")) as f:
        frames = f.read()
    check("frames.txt carries all five FDE rows",
          all(s in frames for s in FRAME_STARTS))

    with open(os.path.join(PACKET, "relocations.txt")) as f:
        relocs = f.read()
    check("relocations.txt carries the 0x575b310 slot",
          "00000575b310" in relocs and "5165b80" in relocs)

    census = subprocess.run(
        [sys.executable, os.path.join(PACKET, "census.py")],
        cwd=ROOT, capture_output=True, text=True, check=True).stdout
    check("census matches records.json",
          "calls=0 jumps=0 qwords=1" in census
          and "0x189438" in census
          and records["census"]["direct_calls"] == []
          and records["census"]["qword_slots"] == ["0x575b310"])

    check("records.json carries window/census/layout",
          records["window"]["start"] == "0x5165b80"
          and "record_layout" in records
          and "dirty_flush" in records)

    if FAILURES:
        print("FAILURES: %s" % ", ".join(FAILURES))
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
