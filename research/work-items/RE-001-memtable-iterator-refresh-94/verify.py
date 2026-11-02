"""Packet checker for RE-001-memtable-iterator-refresh-94.

Checks, all against the real binary (no synthetic fixtures):
1. work/hl-node-94.bin SHA-256 matches records.json.
2. MANIFEST.sha256 matches every packet file except itself.
3. Each excerpt regenerates byte-for-byte from a fresh objdump run
   (repository root, relative binary path).
4. Sampled instructions match byte-for-byte against a fresh objdump
   run and the raw binary bytes.
5. frames.txt carries the FDE rows for the five windows and the predicate.
6. relocations.txt carries the RELATIVE slots for the windows and predicate.
7. The caller census matches records.json (via census.py).
8. records.json parses and carries the windows, layout and flow keys.

Run from the repository root:
  python3 research/work-items/RE-001-memtable-iterator-refresh-94/verify.py
"""

import hashlib
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
PACKET = os.path.join(ROOT, "research", "work-items", "RE-001-memtable-iterator-refresh-94")
BINARY = os.path.join(ROOT, "work", "hl-node-94.bin")

WINDOWS = [
    ("window-5167ba0.txt", 0x5167BA0, 0x5167CE7),
    ("window-5167cf0.txt", 0x5167CF0, 0x5167E37),
    ("window-5167e40.txt", 0x5167E40, 0x5167FC7),
    ("window-5167fd0.txt", 0x5167FD0, 0x5168157),
    ("window-51684d0.txt", 0x51684D0, 0x5168604),
    ("callee-51647b0.txt", 0x51647B0, 0x51647C4),
]

# (address, raw bytes) sampled from the excerpts.
SAMPLES = [
    (0x5167BA0, bytes.fromhex("f30f1efa")),      # window entry
    (0x5167C1C, bytes.fromhex("e81ff4ffff")),    # reader call, ba0
    (0x5167E40, bytes.fromhex("f30f1efa")),      # window entry, e40
    (0x5167FD0, bytes.fromhex("f30f1efa")),      # window entry, fd0
    (0x51684D0, bytes.fromhex("f30f1efa")),      # window entry, 84d0
    (0x5168537, bytes.fromhex("e804ebffff")),    # reader call, 84d0
    (0x51647B0, bytes.fromhex("f30f1efa")),      # predicate entry
    (0x51647B4, bytes.fromhex("0fb64758")),      # predicate ready load
    (0x5167F8D, bytes.fromhex("e9de670c00")),    # report tail call, e40
]

FRAME_STARTS = ["0x5167ba0", "0x5167cf0", "0x5167e40", "0x5167fd0",
                "0x51684d0", "0x51647b0"]

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
    check("binary digest matches records.json",
          hashlib.sha256(data).hexdigest() == records["artifact"]["sha256"])

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
        if manifest.get(name) != hashlib.sha256(open(path, "rb").read()).hexdigest():
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
    for va, raw in SAMPLES:
        off = va - 0x1000  # .text VA -> file offset, verified
        if data[off:off + len(raw)] != raw:
            samples_ok = False
        text = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % va,
             "--stop-address=%#x" % (va + 16), "work/hl-node-94.bin"],
            cwd=ROOT, capture_output=True, text=True, check=True).stdout
        line = re.search(r"^\s*%x:\t([0-9a-f ]+)\t" % va, text, re.MULTILINE)
        if not line or bytes.fromhex(line.group(1).strip()) != raw:
            samples_ok = False
    check("sampled instructions byte-for-byte", samples_ok)

    with open(os.path.join(PACKET, "frames.txt")) as f:
        frames = f.read()
    check("frames.txt carries all six FDE rows",
          all(s in frames for s in FRAME_STARTS))

    with open(os.path.join(PACKET, "relocations.txt")) as f:
        relocs = f.read()
    check("relocations.txt carries the window slots",
          all(s in relocs for s in
              ["00000575b248", "00000575b250", "00000575b268",
               "00000575b278", "0000057783d0"]))

    census = subprocess.run(
        [sys.executable, os.path.join(PACKET, "census.py")],
        cwd=ROOT, capture_output=True, text=True, check=True).stdout
    check("census matches records.json",
          "84d0 0x51684d0 calls=3" in census
          and "reader 0x5167040 calls=8" in census
          and "report 0x522e770 calls=341" in census
          and "ba0 0x5167ba0 calls=0" in census)

    check("records.json carries windows/layout/flow",
          len(records["windows"]) == 5
          and "iterator_layout" in records
          and "flow" in records
          and records["predicate"]["semantics"] == "ready_and_not_installed")

    if FAILURES:
        print("FAILURES: %s" % ", ".join(FAILURES))
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
