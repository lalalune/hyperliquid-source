"""Packet checker for RE-001-wal-flush-driver-94.

Checks, all against the digest-verified binary:
1. Every excerpt file matches a fresh objdump run (from the repo root,
   with the repo-relative binary path, so the header spelling matches).
2. records.json parses and carries the required semantic sections.
3. The log strings in records.json match the binary's rodata at the
   lea targets.
4. Three sampled instructions match the raw binary byte-for-byte.
5. Both caller sites encode an e8 call to the window, and the census
   counts (2 direct calls, 0 tail jumps, 0 qword refs) reproduce.

Usage:
    python3 research/work-items/RE-001-wal-flush-driver-94/verify.py
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
    "window.txt": (0x50EBFB0, 0x50EC9D7),
    "caller-sites.txt": (0x4FD2600, 0x4FD2630),
    "caller-site-2.txt": (0x50EE6A0, 0x50EE6E0),
}

SAMPLES = {
    0x50EBFB0: bytes.fromhex("f30f1efa"),       # endbr64
    0x50EC61E: bytes.fromhex("e83d3f0700"),     # sweep call
    0x50EC2D1: bytes.fromhex("e88adfffff"),     # handler call
}

REQUIRED_RECORD_KEYS = [
    "artifact", "window", "arguments", "result_struct", "entry_sequence",
    "sweep_path", "main_path", "collection", "context", "phase_A",
    "phase_B", "phase_G", "per_item_loop", "post_loop", "marking_loop",
    "teardown", "callers", "db_fields", "unknowns", "not_claimed",
]

TEXT_BASE = 0x1343C80
SEG_OFF = 0x1342C80
SEG_END = 0x5660250
TARGET = 0x50EBFB0


def file_offset(vaddr):
    return vaddr - 0x1000 if vaddr >= TEXT_BASE else vaddr


def cstr(data, vaddr):
    off = file_offset(vaddr)
    end = data.index(b"\x00", off)
    return data[off:end].decode()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--packet-dir", default=None)
    parser.add_argument("--binary", default="work/hl-node-94.bin")
    args = parser.parse_args()
    packet = Path(args.packet_dir) if args.packet_dir else Path(
        __file__).resolve().parent
    repo = packet.parent.parent.parent
    binary = Path(args.binary)
    if not binary.is_absolute():
        binary = repo / binary
    data = binary.read_bytes()
    failures = []

    if hashlib.sha256(data).hexdigest() != (
            "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575"
            "eff1c0459f"):
        failures.append("binary digest mismatch")

    for name, (start, stop) in WINDOWS.items():
        fresh = subprocess.run(
            ["objdump", "-d", f"--start-address={start:#x}",
             f"--stop-address={stop:#x}", "work/hl-node-94.bin"],
            cwd=repo, capture_output=True, text=True).stdout
        if fresh != (packet / name).read_text():
            failures.append(f"excerpt mismatch: {name}")

    try:
        records = json.loads((packet / "records.json").read_text())
    except json.JSONDecodeError as exc:
        print(f"FAIL: records.json does not parse: {exc}")
        return 1
    for key in REQUIRED_RECORD_KEYS:
        if key not in records:
            failures.append(f"records.json missing key: {key}")

    # Log strings at the lea targets.
    if cstr(data, 0x7D5458) != records["main_path"]["log_call"]["format"]:
        failures.append("main log format mismatch")
    if cstr(data, 0x7E1960) != records["main_path"]["log_call"]["file"]:
        failures.append("log file string mismatch")
    if cstr(data, 0x7E6FB0) != (
            "[%s:1621] Unable to release oldest log due to "
            "uncommitted transaction"):
        failures.append("sweep log string mismatch")

    # Sampled instructions byte-for-byte against the raw binary.
    for addr, raw in SAMPLES.items():
        off = file_offset(addr)
        if data[off:off + len(raw)] != raw:
            failures.append(f"sample mismatch at {addr:#x}")

    # Caller census: recorded sites encode e8 calls to the window,
    # and a full segment scan reproduces the counts.
    for site in ("0x4fd2622", "0x50ee6d1"):
        v = int(site, 16)
        off = file_offset(v)
        if data[off] != 0xE8:
            failures.append(f"call site {site} is not an e8 call")
        elif v + 5 + struct.unpack_from("<i", data, off + 1)[0] != TARGET:
            failures.append(f"call site {site} does not target the window")
    try:
        import numpy as np
        seg = np.frombuffer(data[SEG_OFF:SEG_END], dtype=np.uint8)
        for op in (0xE8, 0xE9):
            idx = np.where(seg[:-4] == op)[0]
            # Rebuild rel32 values from the four following bytes.
            rel = (seg[idx + 1].astype(np.int64)
                   | (seg[idx + 2].astype(np.int64) << 8)
                   | (seg[idx + 3].astype(np.int64) << 16)
                   | (seg[idx + 4].astype(np.int64) << 24))
            rel = np.where(rel >= 1 << 31, rel - (1 << 32), rel)
            targets = SEG_OFF + idx + 0x1000 + 5 + rel
            hits = [hex(int(SEG_OFF + i + 0x1000))
                    for i, t in zip(idx, targets) if t == TARGET]
            if op == 0xE8 and sorted(hits) != ["0x4fd2622", "0x50ee6d1"]:
                failures.append(f"e8 census mismatch: {hits}")
            if op == 0xE9 and hits:
                failures.append(f"unexpected tail jumps: {hits}")
    except ImportError:
        failures.append("numpy unavailable; census scan skipped")
    qword = struct.pack("<Q", TARGET)
    if data.find(qword) != -1:
        failures.append("unexpected qword reference to the window")

    # MANIFEST hashes.
    manifest = (packet / "MANIFEST.sha256").read_text().splitlines()
    for line in manifest:
        digest, name = line.split("  ", 1)
        if hashlib.sha256((packet / name).read_bytes()).hexdigest() != digest:
            failures.append(f"MANIFEST mismatch: {name}")

    if failures:
        print("FAIL:")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
