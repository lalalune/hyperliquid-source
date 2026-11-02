"""Caller census for node #94 window 0x51628f0.

Scans .text (file offset 0x1342c80, vaddr 0x1343c80, size 0x431c430;
file offset = vaddr - 0x1000) for E8 direct calls and E9 tail jumps
whose rel32 target is the window, scans the whole file for 8-byte
little-endian qword references to the window, and scans .rela.dyn for
RELA entries whose addend is the window. Prints one JSON object.

Run from the repository root:
  python3 research/work-items/RE-001-wal-record-scan-94/census.py
"""
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BIN = ROOT / "work/hl-node-94.bin"
TEXT_OFF = 0x1342C80
TEXT_SIZE = 0x431C430
TARGET = 0x51628F0


def main():
    raw = BIN.read_bytes()
    text = raw[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    calls = []
    jumps = []
    for opcode, bucket in ((0xE8, calls), (0xE9, jumps)):
        start = 0
        while True:
            i = text.find(bytes([opcode]), start)
            if i < 0:
                break
            start = i + 1
            if i + 5 > len(text):
                break
            rel = struct.unpack_from("<i", text, i + 1)[0]
            instr_va = i + 0x1343C80
            if instr_va + 5 + rel == TARGET:
                bucket.append(instr_va)
    qwords = []
    pat = struct.pack("<Q", TARGET)
    start = 0
    while True:
        j = raw.find(pat, start)
        if j < 0:
            break
        qwords.append(j)
        start = j + 1
    rela = []
    for off, size in ((0x6BC0, 0x1D4E10), (0x1DB9D0, 0x1A10)):
        for i in range(size // 24):
            ro, ri, ra = struct.unpack_from("<QQq", raw, off + i * 24)
            if ra == TARGET:
                rela.append({"offset": hex(ro), "type": ri & 0xFFFFFFFF,
                             "sym": ri >> 32})
    print(json.dumps({
        "window": hex(TARGET),
        "direct_calls": [hex(c) for c in calls],
        "tail_jumps": [hex(c) for c in jumps],
        "qword_file_offsets": [hex(o) for o in qwords],
        "rela_addend_entries": rela,
    }, indent=2))


if __name__ == "__main__":
    main()
