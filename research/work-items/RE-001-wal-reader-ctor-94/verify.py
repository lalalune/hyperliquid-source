"""Packet checker for RE-001-wal-reader-ctor-94.

Checks, all against the digest-verified binary:
1. Every excerpt file matches a fresh objdump run (from the repo root,
   with the repo-relative binary path, so the header spelling matches).
2. records.json parses and carries the required semantic sections.
3. Four sampled instructions match the raw binary byte-for-byte.

Usage:
    python3 research/work-items/RE-001-wal-reader-ctor-94/verify.py
    python3 .../verify.py --packet-dir <dir> [--binary <path>]
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

WINDOWS = {
    "window.txt": (0x51632F0, 0x51633DE),
    "cleanup.txt": (0x51632CC, 0x51632EB),
    "caller-replay.txt": (0x520B46B, 0x520B4A3),
    "caller-first.txt": (0x50CA0A0, 0x50CA0F1),
}

SAMPLES = {
    0x51632F0: bytes.fromhex("f30f1efa"),
    0x5163354: bytes.fromhex("e897d14f00"),
    0x5163335: bytes.fromhex("83420801"),
    0x51633C8: bytes.fromhex("f083420801"),
}

REQUIRED_RECORD_KEYS = [
    "window", "arguments", "fields", "vtable", "refcount",
    "taken_slot", "buffer", "string_field", "callers", "consumers",
    "cleanup_stub",
]


def file_offset(vaddr):
    return vaddr - 0x1000 if vaddr >= 0x1343C80 else vaddr


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--packet-dir", default=None)
    parser.add_argument("--binary", default="work/hl-node-94.bin")
    args = parser.parse_args()
    # packet = research/work-items/<item>; repo root is three levels up.
    packet = Path(args.packet_dir) if args.packet_dir else Path(
        __file__).resolve().parent
    repo = packet.parent.parent.parent
    binary = Path(args.binary)
    if not binary.is_absolute():
        binary = repo / binary
    failures = []

    for name, (start, stop) in WINDOWS.items():
        fresh = subprocess.run(
            ["objdump", "-d", f"--start-address={start:#x}",
             f"--stop-address={stop:#x}", "work/hl-node-94.bin"],
            cwd=repo, capture_output=True, text=True).stdout
        stored = (packet / name).read_text()
        if fresh != stored:
            failures.append(f"excerpt mismatch: {name}")

    try:
        records = json.loads((packet / "records.json").read_text())
    except json.JSONDecodeError as exc:
        failures.append(f"records.json does not parse: {exc}")
        records = {}
    for key in REQUIRED_RECORD_KEYS:
        if key not in records:
            failures.append(f"records.json missing key: {key}")

    data = binary.read_bytes()
    for vaddr, expected in SAMPLES.items():
        off = file_offset(vaddr)
        if data[off:off + len(expected)] != expected:
            failures.append(f"sample mismatch at {vaddr:#x}")

    if failures:
        print("CHECKS FAILED:")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
