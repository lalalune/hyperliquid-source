"""Packet checker for RE-001-wal-replay-driver-94.

Checks, all against the digest-verified binary:
1. Every excerpt file matches a fresh objdump run (from the repo root,
   with the repo-relative binary path, so the header spelling matches).
2. records.json parses and carries the required semantic sections.
3. The pinned rodata strings match the binary at their addresses
   (first LOAD segment: file offset == vaddr).
4. The digit-pair table assembled from the 13 pinned rodata chunks
   (12 aligned copies plus the unaligned tail store) equals the
   "00".."99" pair sequence.
5. Four sampled instructions match the raw binary byte-for-byte
   (executable LOAD segment: file offset == vaddr - 0x1000).
6. The caller site encodes an e8 call to the window, and the census
   counts (1 direct call, 0 tail jumps, 0 qword refs) reproduce.

Usage:
    python3 research/work-items/RE-001-wal-replay-driver-94/verify.py
    python3 .../verify.py --packet-dir <dir> [--binary <path>]
"""
import argparse
import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

WINDOWS = {
    "window.txt": (0x520C120, 0x520D31D),
    "caller-site.txt": (0x520D580, 0x520D5C0),
}

SAMPLES = {
    0x520C120: bytes.fromhex("f30f1efa"),       # endbr64
    0x520CA74: bytes.fromhex("e8b7e2ffff"),     # replay step call (type 0)
    0x520C37B: bytes.fromhex("e8b0260200"),     # log dispatcher call
    0x520D244: bytes.fromhex("e88738f5ff"),     # rehash auxiliary call
}

REQUIRED_RECORD_KEYS = [
    "artifact", "window", "arguments", "unknown_type", "digit_table",
    "filename_builders", "cache_table", "cache_lookup", "cache_insert",
    "replay_calls", "status_copy", "post_replay_type0",
    "post_replay_type1", "error_chain", "callers", "unknowns",
    "not_claimed",
]

RODATA = {
    0x1DF471: b"File Type Not Known ",
    0x1F989E: b"db/wal_manager.cc",
    0x7D6168: b"[%s:381] [WalManger] Unknown file type %s",
    0x1E8058: b"%06llu.%s",
    0x1E5A60: b"/",
    0x202AC1: b"log",
}

DIGIT_CHUNKS = [
    0x204410, 0x205CC0, 0x209190, 0x2066D0, 0x2049D0, 0x205670,
    0x207F50, 0x208B30, 0x2091A0, 0x2053C0, 0x208B40, 0x205CD0,
    0x207210,
]

EXPECTED_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
TARGET = 0x520C120
CALLER_SITE = 0x520D5A9


def code_offset(vaddr):
    return vaddr - 0x1000


def rodata_offset(vaddr):
    return vaddr


def fail(msg):
    raise SystemExit(f"FAIL: {msg}")


def check_excerpts(packet, binary):
    for name, (lo, hi) in WINDOWS.items():
        path = packet / name
        if not path.exists():
            fail(f"missing excerpt {name}")
        fresh = subprocess.run(
            ["objdump", "-d", f"--start-address={lo:#x}",
             f"--stop-address={hi:#x}", str(binary)],
            capture_output=True, text=True, check=True).stdout
        if path.read_text() != fresh:
            fail(f"excerpt {name} differs from a fresh objdump run")


def check_records(packet):
    records = json.loads((packet / "records.json").read_text())
    for key in REQUIRED_RECORD_KEYS:
        if key not in records:
            fail(f"records.json missing section {key}")
    if "mnemonic" in json.dumps(records):
        fail("records.json must carry semantic records only")
    if records["artifact"]["sha256"] != EXPECTED_SHA256:
        fail("records.json artifact digest mismatch")
    return records


def check_rodata(binary_bytes):
    for addr, want in RODATA.items():
        off = rodata_offset(addr)
        got = binary_bytes[off:off + len(want)]
        if got != want:
            fail(f"rodata at {addr:#x}: got {got!r}, want {want!r}")


def check_digit_table(binary_bytes):
    table = bytearray(200)
    for i, chunk in enumerate(DIGIT_CHUNKS[:12]):
        off = rodata_offset(chunk)
        table[i * 16:(i + 1) * 16] = binary_bytes[off:off + 16]
    # Unaligned tail store: 16 bytes from the last chunk land at
    # table offset 185 (the second character of pair 92 onwards).
    tail = binary_bytes[rodata_offset(DIGIT_CHUNKS[12]):
                        rodata_offset(DIGIT_CHUNKS[12]) + 16]
    table[185:200] = tail[:15]
    want = "".join(f"{i:02d}" for i in range(100)).encode()
    if bytes(table) != want:
        fail(f"digit table assembly mismatch: {bytes(table[:64])!r}...")


def check_samples(binary_bytes):
    for addr, want in SAMPLES.items():
        got = binary_bytes[code_offset(addr):code_offset(addr) + len(want)]
        if got != want:
            fail(f"sample at {addr:#x}: got {got.hex()}, want {want.hex()}")


def check_census(binary_bytes):
    import numpy as np
    toff, tvaddr, tsize = 0x1342C80, 0x1343C80, 0x431C430
    text = np.frombuffer(binary_bytes[toff:toff + tsize], dtype=np.uint8)
    found = {}
    for op, name in ((0xE8, "call"), (0xE9, "jmp")):
        idx = np.flatnonzero(text[:-5] == op)
        b = text.astype(np.int32)
        rel = b[idx + 1] | (b[idx + 2] << 8) | (b[idx + 3] << 16) | (b[idx + 4] << 24)
        rel = np.where(rel >= 2**31, rel - 2**32, rel)
        src = tvaddr + idx
        found[name] = [int(s) for s in src[src + 5 + rel == TARGET]]
    if found["call"] != [CALLER_SITE]:
        fail(f"census calls mismatch: {found['call']}")
    if found["jmp"]:
        fail(f"census tail jumps mismatch: {found['jmp']}")
    qword = struct.pack("<Q", TARGET)
    if binary_bytes.find(qword) >= 0:
        fail("census found an unexpected qword reference")
    site = binary_bytes[code_offset(CALLER_SITE):code_offset(CALLER_SITE) + 5]
    if site != bytes.fromhex("e872ebffff"):
        fail(f"caller site bytes mismatch: {site.hex()}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--packet-dir", default=None)
    parser.add_argument("--binary", default="work/hl-node-94.bin")
    args = parser.parse_args()
    packet = Path(args.packet_dir) if args.packet_dir else Path(__file__).resolve().parent
    binary = Path(args.binary)
    binary_bytes = binary.read_bytes()
    if hashlib.sha256(binary_bytes).hexdigest() != EXPECTED_SHA256:
        fail("binary digest mismatch")
    check_excerpts(packet, binary)
    check_records(packet)
    check_rodata(binary_bytes)
    check_digit_table(binary_bytes)
    check_samples(binary_bytes)
    check_census(binary_bytes)
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    sys.exit(main())
