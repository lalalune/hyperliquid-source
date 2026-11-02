"""Reproduce the caller census for window 0x520e1b0.

Run from the repository root:
  python3 research/work-items/RE-001-wal-replay-orchestrator-94/census.py

Scans .text (vaddr 0x1343c80, file offset 0x1342c80) for e8/e9
rel32 instructions targeting 0x520e1b0, and scans the whole file for
the 8-byte little-endian value 0x520e1b0.
"""
import struct
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[3]
BIN = ROOT / "work/hl-node-94.bin"
TEXT_OFFSET = 0x1342C80
TEXT_VADDR = 0x1343C80
TEXT_SIZE = 0x431C430
TARGET = 0x520E1B0


def main():
    data = BIN.read_bytes()
    text = data[TEXT_OFFSET:TEXT_OFFSET + TEXT_SIZE]
    arr = np.frombuffer(text, dtype=np.uint8)
    for op in (0xE8, 0xE9):
        idx = np.where(arr[:-5] == op)[0]
        rel = (arr[idx + 1].astype(np.int32)
               | (arr[idx + 2].astype(np.int32) << 8)
               | (arr[idx + 3].astype(np.int32) << 16)
               | (arr[idx + 4].astype(np.int32) << 24)).astype(np.int64)
        tgt = TEXT_VADDR + idx + 5 + rel
        hits = idx[tgt == TARGET]
        print(f"{hex(op)}: {[hex(TEXT_VADDR + int(i)) for i in hits]}")
    q = np.frombuffer(data, dtype=np.uint64)
    hits = np.where(q == TARGET)[0]
    print("qword refs:", [hex(int(h) * 8) for h in hits])


if __name__ == "__main__":
    main()
