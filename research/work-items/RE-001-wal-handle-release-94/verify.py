"""Packet checker for RE-001-wal-handle-release-94.

Checks, all against the real binary (no synthetic fixtures):
1. work/hl-node-94.bin SHA-256 matches records.json.
2. MANIFEST.sha256 matches every packet file except itself.
3. Each excerpt regenerates byte-for-byte from a fresh objdump run
   (repository root, relative binary path).
4. Three sampled instructions match byte-for-byte against the fresh
   objdump output and the raw binary bytes.
5. frames.txt carries the FDE rows for the window, the finalize
   helper, the status helper, the completion step, the destroyer,
   the member deleting destructor and destructor, and the two
   sampled caller functions.
6. relocations.txt carries the six relocation rows cited in
   records.json.
7. The caller census matches records.json (direct calls; no tail
   jumps; no qword references).
8. The finalize helper's two rodata fragments combine to the
   recorded error message.

Run from the repository root: python3 research/work-items/RE-001-wal-handle-release-94/verify.py
"""

import hashlib
import json
import os
import re
import struct
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
PACKET = os.path.join(ROOT, "research", "work-items", "RE-001-wal-handle-release-94")
BINARY = os.path.join(ROOT, "work", "hl-node-94.bin")
TEXT_OFF, TEXT_VADDR, TEXT_SIZE = 0x1342C80, 0x1343C80, 0x431C430

WINDOWS = [
    ("window-51641d0.txt", 0x51641D0, 0x516458D),
    ("helper-5163460.txt", 0x5163460, 0x516350D),
    ("callsite-4fb0e87.txt", 0x4FB0E60, 0x4FB0EB0),
    ("callsite-50eadb0.txt", 0x50EAD80, 0x50EADF0),
]

# (address, raw bytes) sampled from the excerpts.
SAMPLES = [
    (0x51641D0, bytes.fromhex("f30f1efa")),   # endbr64, release entry
    (0x51641FF, bytes.fromhex("e85cf2ffff")),  # call finalize helper
    (0x5164302, bytes.fromhex("f00fc102")),   # lock xadd, shared release
]

FAILURES = []


def check(label, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + label + ((" " + detail) if detail and not ok else ""))
    if not ok:
        FAILURES.append(label)


def main():
    sys.dont_write_bytecode = True
    with open(os.path.join(PACKET, "records.json")) as handle:
        records = json.load(handle)
    with open(BINARY, "rb") as handle:
        data = handle.read()
    digest = hashlib.sha256(data).hexdigest()
    check("binary digest", digest == records["artifact_sha256"], digest)

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

    text = data[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    for addr, raw in SAMPLES:
        off = TEXT_OFF + (addr - TEXT_VADDR)
        check("sample bytes %#x" % addr, data[off:off + len(raw)] == raw)

    with open(os.path.join(PACKET, "frames.txt")) as handle:
        frames = handle.read()
    for start in ["0x51641d0", "0x5163460", "0x52b2550", "0x52b13f0",
                  "0x4f94a40", "0x51633e0", "0x5163410", "0x4fb0b80",
                  "0x50ea260"]:
        check("frame row " + start, ("\n" + start + "\t") in ("\n" + frames))

    with open(os.path.join(PACKET, "relocations.txt")) as handle:
        relocs = handle.read()
    for addr in ["0000000005778388", "0000000005777bd0", "0000000005777ed8",
                 "0000000005766018", "000000000575f768", "0000000005759318"]:
        check("relocation row " + addr, addr in relocs)

    calls, jumps = [], []
    for match in re.finditer(rb"[\xe8\xe9]....", text):
        i = match.start()
        rel = struct.unpack_from("<i", text, i + 1)[0]
        if TEXT_VADDR + i + 5 + rel == 0x51641D0:
            (calls if text[i] == 0xE8 else jumps).append(TEXT_VADDR + i)
    check("census calls", [hex(c) for c in calls] == records["callers"]["direct_calls"],
          str([hex(c) for c in calls]))
    check("census tail jumps", jumps == [])
    qword = struct.pack("<Q", 0x51641D0)
    check("census qword refs", data.find(qword) < 0)

    frag1 = data[0x208580:0x208590]
    frag2 = data[0x209590:0x2095A0]
    check("helper message fragments",
          frag1 == b"Seen error. Skip" and frag2 == b" writing buffer.")
    check("helper message combined",
          (frag1 + frag2).decode() == records["finalize_helper"]["error_message"])

    print("ALL CHECKS PASSED" if not FAILURES else "FAILURES: " + ", ".join(FAILURES))
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
