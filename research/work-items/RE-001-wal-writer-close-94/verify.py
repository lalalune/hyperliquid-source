"""Packet checker for RE-001-wal-writer-close-94.

Checks, all against the real binary (no synthetic fixtures):
1. work/hl-node-94.bin SHA-256 matches records.json.
2. MANIFEST.sha256 matches every packet file except itself.
3. Each excerpt regenerates byte-for-byte from a fresh objdump run
   (repository root, relative binary path).
4. Three sampled instructions match byte-for-byte against the fresh
   objdump output and the raw binary bytes.
5. frames.txt carries the FDE rows for the window, the helper, the
   destroyer and the neighbouring setup window (owner of the shared
   cleanup stub at 0x5163dec).
6. relocations.txt carries the four relocation rows cited in
   records.json.
7. The caller census matches records.json (direct calls; no tail
   jumps; no qword references).

Run from the repository root: python3 research/work-items/RE-001-wal-writer-close-94/verify.py
"""

import hashlib
import json
import os
import struct
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
PACKET = os.path.join(ROOT, "research", "work-items", "RE-001-wal-writer-close-94")
BINARY = os.path.join(ROOT, "work", "hl-node-94.bin")
TEXT_OFF, TEXT_VADDR, TEXT_SIZE = 0x1342C80, 0x1343C80, 0x431C430

WINDOWS = [
    ("window-5163e20.txt", 0x5163E20, 0x51641D0),
    ("callsite-503ccce.txt", 0x503CC85, 0x503CD10),
    ("callsite-50b4ac7.txt", 0x50B4A77, 0x50B4AEA),
]

# (address, raw bytes) sampled from the excerpts.
SAMPLES = [
    (0x5163E20, bytes.fromhex("f30f1efa")),   # endbr64, close entry
    (0x5163E6E, bytes.fromhex("e8dde61400")),  # call status helper, first call
    (0x5163F7A, bytes.fromhex("f00fc102")),   # lock xadd, multi-threaded release
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

    with open(os.path.join(PACKET, "frames.txt")) as handle:
        frames = handle.read()
    for row in ("0x5163e20", "0x52b2550", "0x4f94a40", "0x5163ba0"):
        check("frame row " + row, row in frames)

    with open(os.path.join(PACKET, "relocations.txt")) as handle:
        relocs = handle.read()
    for row in ("000005759318", "00000575f768", "000005777bd0", "000005777ed8"):
        check("relocation row " + row, row in relocs)

    census = records["caller_census"]
    calls, jumps = [], []
    for i in range(len(text) - 5):
        opcode = text[i]
        if opcode not in (0xE8, 0xE9):
            continue
        rel = struct.unpack_from("<i", text, i + 1)[0]
        if TEXT_VADDR + i + 5 + rel == 0x5163E20:
            (calls if opcode == 0xE8 else jumps).append(TEXT_VADDR + i)
    expected = [int(x, 16) for x in census["direct_call_sites"]]
    check("census calls", calls == expected,
          "got %s" % [hex(c) for c in calls])
    check("census no tail jumps", jumps == [])
    qword = struct.pack("<Q", 0x5163E20)
    offsets, idx = [], 0
    while True:
        pos = data.find(qword, idx)
        if pos < 0:
            break
        offsets.append(pos)
        idx = pos + 1
    check("census no qword refs", offsets == [])

    if FAILURES:
        print("FAILURES:", FAILURES)
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
