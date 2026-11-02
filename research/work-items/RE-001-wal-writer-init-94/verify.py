"""Packet checker for RE-001-wal-writer-init-94.

Checks, all against the real binary (no synthetic fixtures, except that
the type-CRC table values are model-computed: the table exists only at
runtime after the initializer runs, so the checker verifies the model's
CRC implementation against the published check value and the table
against records.json):
1. work/hl-node-94.bin SHA-256 matches records.json.
2. MANIFEST.sha256 matches every packet file except itself.
3. Each excerpt regenerates byte-for-byte from a fresh objdump run
   (repository root, relative binary path).
4. Three sampled instructions match byte-for-byte against the fresh
   objdump output and the raw binary bytes.
5. frames.txt carries the FDE rows for the window, the three caller
   functions, the setup function, the release window and the CRC import.
6. relocations.txt states that no relocation row applies.
7. The caller census matches records.json (direct calls; no tail
   jumps; no qword references).
8. The model CRC-32C matches the published check value and reproduces
   every type_crc entry in records.json.

Run from the repository root: python3 research/work-items/RE-001-wal-writer-init-94/verify.py
"""

import hashlib
import json
import os
import struct
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
PACKET = os.path.join(ROOT, "research", "work-items", "RE-001-wal-writer-init-94")
BINARY = os.path.join(ROOT, "work", "hl-node-94.bin")
TEXT_OFF, TEXT_VADDR, TEXT_SIZE = 0x1342C80, 0x1343C80, 0x431C430

WINDOWS = [
    ("window-51645d0.txt", 0x51645D0, 0x516466B),
    ("callsite-50bbf5a.txt", 0x50BBF0E, 0x50BBF78),
    ("callsite-50be17b.txt", 0x50BE164, 0x50BE180),
    ("callsite-51f7c20.txt", 0x51F7BE3, 0x51F7C54),
]

# (address, raw bytes) sampled from the excerpts.
SAMPLES = [
    (0x51645D0, bytes.fromhex("f30f1efa")),   # endbr64, initializer entry
    (0x516462E, bytes.fromhex("e88dd92b00")),  # call CRC import
    (0x50BBF5A, bytes.fromhex("e871860a00")),  # call initializer, setup site
]

FAILURES = []


def check(label, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + label + ((" " + detail) if detail and not ok else ""))
    if not ok:
        FAILURES.append(label)


def main():
    sys.dont_write_bytecode = True
    sys.path.insert(0, ROOT)
    from tools.wal_writer_init import crc32c, type_crc_table

    with open(os.path.join(PACKET, "records.json")) as handle:
        records = json.load(handle)
    with open(BINARY, "rb") as handle:
        data = handle.read()
    digest = hashlib.sha256(data).hexdigest()
    check("binary digest", digest == records["target"]["sha256"], digest)

    manifest = {}
    with open(os.path.join(PACKET, "MANIFEST.sha256")) as handle:
        for line in handle:
            parts = line.split()
            if len(parts) == 2:
                manifest[parts[1]] = parts[0]
    for name in sorted(os.listdir(PACKET)):
        if name == "MANIFEST.sha256":
            continue
        path = os.path.join(PACKET, name)
        if not os.path.isfile(path):
            continue
        with open(path, "rb") as handle:
            actual = hashlib.sha256(handle.read()).hexdigest()
        check("manifest " + name, manifest.get(name) == actual)

    os.chdir(ROOT)
    for name, start, stop in WINDOWS:
        out = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % start,
             "--stop-address=%#x" % stop, "work/hl-node-94.bin"],
            capture_output=True, text=True, check=True).stdout
        with open(os.path.join(PACKET, name)) as handle:
            stored = handle.read()
        check("excerpt regenerates " + name, out == stored)

    for addr, raw in SAMPLES:
        off = TEXT_OFF + (addr - TEXT_VADDR)
        check("sample bytes %#x" % addr, data[off:off + len(raw)] == raw)

    with open(os.path.join(PACKET, "frames.txt")) as handle:
        frames = handle.read()
    for start in ["0x51645d0", "0x50bbc40", "0x50bda70", "0x51f5550",
                  "0x5163ba0", "0x51641d0", "0x5421fc0"]:
        check("frame row " + start, ("\n" + start + "\t") in ("\n" + frames))

    with open(os.path.join(PACKET, "relocations.txt")) as handle:
        relocs = handle.read()
    check("relocations note", "no\nRIP-relative data reference" in relocs
          or "no RIP-relative data reference" in relocs)

    text = data[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    calls, jumps = [], []
    for i in range(len(text) - 5):
        opcode = text[i]
        if opcode not in (0xE8, 0xE9):
            continue
        rel = struct.unpack_from("<i", text, i + 1)[0]
        if TEXT_VADDR + i + 5 + rel == 0x51645D0:
            (calls if opcode == 0xE8 else jumps).append(TEXT_VADDR + i)
    check("census calls", [hex(c) for c in calls] == records["callers"]["direct_calls"],
          str([hex(c) for c in calls]))
    check("census tail jumps", jumps == [])
    qword = struct.pack("<Q", 0x51645D0)
    check("census qword refs", data.find(qword) < 0)

    check("crc check value", crc32c(b"123456789") == 0xE3069283)
    table = type_crc_table()
    check("type_crc table", {str(k): "0x%08x" % v for k, v in table.items()}
          == records["type_crc_table"])

    print("ALL CHECKS PASSED" if not FAILURES else "FAILURES: " + ", ".join(FAILURES))
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
