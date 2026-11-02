"""Caller census for RE-001-memtable-iterator-refresh-94.

Per-byte opcode scanning is unreliable when a regex match window swallows a
later opcode, so this scan enumerates every 0xe8/0xe9 byte position in
.text (via bytes.find, not a regex) and checks its rel32 target. RELATIVE
slots come from parsing .rela.dyn directly.

Run from the repository root:
  python3 research/work-items/RE-001-memtable-iterator-refresh-94/census.py
"""

import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
BINARY = os.path.join(ROOT, "work", "hl-node-94.bin")

TARGETS = {
    0x5167BA0: "ba0",
    0x5167CF0: "cf0",
    0x5167E40: "e40",
    0x5167FD0: "fd0",
    0x51684D0: "84d0",
    0x51647B0: "predicate",
    0x5167040: "reader",
    0x522E770: "report",
}


def main():
    sys.dont_write_bytecode = True
    data = open(BINARY, "rb").read()
    base_va, base_off, size = 0x1343C80, 0x1342C80, 0x431D5D0
    text = data[base_off:base_off + size]
    positions = []
    for opcode in (0xE8, 0xE9):
        i = 0
        while True:
            j = text.find(bytes([opcode]), i)
            if j < 0:
                break
            positions.append((j, opcode))
            i = j + 1
    positions.sort()
    found = {name: ([], []) for name in TARGETS.values()}
    for j, opcode in positions:
        if j + 5 > len(text):
            continue
        target = base_va + j + 5 + struct.unpack_from("<i", text, j + 1)[0]
        if target in TARGETS:
            found[TARGETS[target]][0 if opcode == 0xE8 else 1].append(hex(base_va + j))
    for target, name in TARGETS.items():
        calls, tails = found[name]
        print("%s %s calls=%d %s tails=%d %s" % (name, hex(target), len(calls), calls, len(tails), tails))
    rela_base, rela_end = 0x6BC0, 0x1DB9D0
    for k in range((rela_end - rela_base) // 24):
        off, info, add = struct.unpack_from("<QQq", data, rela_base + k * 24)
        if info == 8 and add in TARGETS:
            print("rela %s slot=%s entry=%s" % (TARGETS[add], hex(off), hex(rela_base + k * 24)))


if __name__ == "__main__":
    main()
