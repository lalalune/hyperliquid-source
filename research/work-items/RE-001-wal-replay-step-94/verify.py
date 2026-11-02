"""Packet checker for RE-001-wal-replay-step-94.

Checks, all against the digest-verified binary:
1. Every excerpt file matches a fresh objdump run (from the repo root,
   with the repo-relative binary path, so the header spelling matches).
2. records.json parses and carries the required semantic sections.
3. The pinned rodata strings match the binary at their lea targets
   (first LOAD segment: file offset == vaddr).
4. Three sampled instructions match the raw binary byte-for-byte
   (executable LOAD segment: file offset == vaddr - 0x1000).
5. Both caller sites encode an e8 call to the window, and the census
   counts (2 direct calls, 0 tail jumps, 0 qword refs) reproduce.

Usage:
    python3 research/work-items/RE-001-wal-replay-step-94/verify.py
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
    "window.txt": (0x520AD30, 0x520C053),
    "caller-site-1.txt": (0x520CA50, 0x520CA90),
    "caller-site-2.txt": (0x520CD50, 0x520CD90),
}

SAMPLES = {
    0x520AD30: bytes.fromhex("f30f1efa"),       # endbr64
    0x520B54F: bytes.fromhex("e88c63f5ff"),     # logical-record read call
    0x520BD85: bytes.fromhex("e8660e0100"),     # record apply call
}

REQUIRED_RECORD_KEYS = [
    "artifact", "window", "arguments", "entry_calls", "state_object",
    "basename", "cf_filter", "gate", "reader_construction", "record_read",
    "short_path", "long_path", "read_fail_path", "status_field_copy",
    "teardown_rule", "callers", "unknowns", "not_claimed",
]

RODATA = {
    0x1F3693: b"/\\",
    0x1E32AC: b"log record too small",
    0x1F989E: b"db/wal_manager.cc",
    0x1F831A: b"(ignoring error) ",
    0x7E1A98: b"[%s:461] [WalManager] %s%s: dropping %d bytes; %s",
    0x7D66E0: b"%s: __pos (which is %zu) > this->size() (which is %zu)",
}

EXPECTED_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
TARGET = 0x520AD30


def code_offset(vaddr):
    return vaddr - 0x1000


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--packet-dir", default=None)
    ap.add_argument("--binary", default="work/hl-node-94.bin")
    args = ap.parse_args()
    packet = Path(args.packet_dir) if args.packet_dir else Path(__file__).resolve().parent
    binary = Path(args.binary)
    failures = []

    data = binary.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA256:
        failures.append(f"binary digest mismatch: {digest}")

    for name, (start, stop) in WINDOWS.items():
        fresh = subprocess.run(
            ["objdump", "-d",
             f"--start-address={start:#x}", f"--stop-address={stop:#x}",
             str(binary)],
            capture_output=True, text=True, check=True,
        ).stdout
        stored = (packet / name).read_text()
        if fresh != stored:
            failures.append(f"excerpt mismatch: {name}")

    records = json.loads((packet / "records.json").read_text())
    for key in REQUIRED_RECORD_KEYS:
        if key not in records:
            failures.append(f"records.json missing key: {key}")

    for vaddr, text in RODATA.items():
        off = vaddr  # first LOAD segment maps vaddr 1:1
        if data[off:off + len(text)] != text:
            failures.append(f"rodata mismatch at {vaddr:#x}")

    for vaddr, raw in SAMPLES.items():
        off = code_offset(vaddr)
        if data[off:off + len(raw)] != raw:
            failures.append(f"sample mismatch at {vaddr:#x}")

    # Caller census: e8 direct calls, e9 tail jumps, qword refs.
    # Code lives in the executable LOAD segment (file offsets
    # 0x1342c80..0x5660250, vaddr = offset + 0x1000).
    calls, tails = [], []
    for opcode, bucket in ((0xE8, calls), (0xE9, tails)):
        i = 0x1342C80
        while True:
            j = data.find(bytes([opcode]), i, 0x5660250)
            if j < 0 or j + 5 > len(data):
                break
            disp = struct.unpack_from("<i", data, j + 1)[0]
            site = j + 0x1000
            if site + 5 + disp == TARGET:
                bucket.append(site)
            i = j + 1
    qwords = []
    needle = struct.pack("<Q", TARGET)
    start = 0
    while True:
        j = data.find(needle, start)
        if j < 0:
            break
        qwords.append(j)
        start = j + 1
    if calls != [0x520CA74, 0x520CD74]:
        failures.append(f"direct-call census mismatch: {[hex(c) for c in calls]}")
    if tails:
        failures.append(f"tail jumps found: {[hex(t) for t in tails]}")
    if qwords:
        failures.append(f"qword refs found: {len(qwords)}")

    for name in ("caller-site-1.txt", "caller-site-2.txt"):
        text = (packet / name).read_text()
        if "call   520ad30" not in text:
            failures.append(f"caller site lacks e8 call to window: {name}")

    if failures:
        print("CHECKS FAILED")
        for failure in failures:
            print(f" - {failure}")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
