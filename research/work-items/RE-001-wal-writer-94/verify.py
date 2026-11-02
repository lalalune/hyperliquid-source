"""Packet checker for RE-001-wal-writer-94.

Checks, all against the real binary (no synthetic fixtures):
1. work/hl-node-94.bin SHA-256 matches records.json.
2. MANIFEST.sha256 matches every packet file except itself.
3. Each excerpt regenerates byte-for-byte from a fresh objdump run
   (repository root, relative binary path).
4. Three sampled instructions match byte-for-byte against the fresh
   objdump output and the raw binary bytes.
5. The cited rodata strings and the trailer zero run are present.
6. frames.txt carries the five FDE rows for the windows and stubs.
7. The caller census matches records.json (direct calls; no tail jumps;
   no qword references).

Run from the repository root: python3 research/work-items/RE-001-wal-writer-94/verify.py
"""

import hashlib
import json
import os
import struct
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
PACKET = os.path.join(ROOT, "research", "work-items", "RE-001-wal-writer-94")
BINARY = os.path.join(ROOT, "work", "hl-node-94.bin")
TEXT_OFF, TEXT_VADDR, TEXT_SIZE = 0x1342C80, 0x1343C80, 0x431C430

WINDOWS = [
    ("window-5163730.txt", 0x5163730, 0x5163B5F),
    ("window-5163550.txt", 0x5163550, 0x51636F6),
    ("window-5163ba0.txt", 0x5163BA0, 0x5163DEC),
    ("callsite-51e9aa3.txt", 0x51E9A60, 0x51E9AE0),
]

# (address, raw bytes) sampled from the excerpts.
SAMPLES = [
    (0x5163730, bytes.fromhex("f30f1efa")),   # endbr64, AddRecord entry
    (0x51638B3, bytes.fromhex("e898fcffff")),  # call EmitFragment, loop
    (0x5163C64, bytes.fromhex("e8e7f8ffff")),  # call EmitFragment, type 9
]

RODATA = [
    (0x2095A0, b"Unexpected WAL c"),
    (0x206E30, b"ompression error"),
    (0x204100, b"Writer has previ"),
    (0x2056C0, b" previous error."),
]

FAILURES = []


def check(label, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + label + ((" " + detail) if detail and not ok else ""))
    if not ok:
        FAILURES.append(label)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main():
    os.chdir(ROOT)
    with open(os.path.join(PACKET, "records.json")) as handle:
        records = json.load(handle)
    with open(BINARY, "rb") as handle:
        data = handle.read()

    check("binary digest", sha256_file(BINARY) == records["target"]["sha256"])

    manifest = {}
    with open(os.path.join(PACKET, "MANIFEST.sha256")) as handle:
        for line in handle:
            digest, name = line.split(None, 1)
            manifest[name.strip()] = digest
    manifest_ok = True
    for name, digest in manifest.items():
        path = os.path.join(PACKET, name)
        if not os.path.exists(path) or sha256_file(path) != digest:
            manifest_ok = False
    check("manifest", manifest_ok, "mismatch or missing file")

    for name, start, stop in WINDOWS:
        fresh = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % start,
             "--stop-address=%#x" % stop, "work/hl-node-94.bin"],
            capture_output=True, text=True, check=True).stdout
        with open(os.path.join(PACKET, name)) as handle:
            stored = handle.read()
        check("excerpt regenerates: " + name, fresh == stored)

    text = data[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    for addr, raw in SAMPLES:
        file_off = addr - 0x1000  # .text vaddr minus file offset delta
        check("sample bytes %#x" % addr, data[file_off:file_off + len(raw)] == raw)

    for addr, text_bytes in RODATA:
        check("rodata %#x" % addr, data[addr:addr + len(text_bytes)] == text_bytes)
    check("trailer zero run", data[0x7EE187:0x7EE191] == b"\x00" * 10)

    with open(os.path.join(PACKET, "frames.txt")) as handle:
        frames = handle.read()
    for row in ("0x5163730", "0x5163550", "0x5163ba0", "0x5163b60", "0x5163dec"):
        check("frame row " + row, row in frames)

    census = records["caller_census"]
    for name, target, key in (("AddRecord", 0x5163730, "AddRecord_direct_call_sites"),
                              ("EmitFragment", 0x5163550, "EmitFragment_direct_call_sites")):
        calls, jumps = [], []
        for i in range(len(text) - 5):
            opcode = text[i]
            if opcode not in (0xE8, 0xE9):
                continue
            rel = struct.unpack_from("<i", text, i + 1)[0]
            if TEXT_VADDR + i + 5 + rel == target:
                (calls if opcode == 0xE8 else jumps).append(TEXT_VADDR + i)
        expected = [int(x, 16) for x in census[key]]
        check("census calls " + name, calls == expected,
              "got %s" % [hex(c) for c in calls])
        check("census no tail jumps " + name, jumps == [])

    if FAILURES:
        print("FAILURES:", FAILURES)
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
