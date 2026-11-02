"""Caller census for node #94 window 0x4fa87a0.

Reproduces the reachability record in records.json:
  1. a full .text scan for E8 (call) and E9 (jmp) rel32 instructions
     whose target is 0x4fa87a0 -- expected: none;
  2. a scan of the .rela.dyn table for R_X86_64_RELATIVE entries
     (type 8) whose addend is 0x4fa87a0 -- expected: four vtable
     slots, each at virtual index 106 of its vtable (the slot two
     entries past the vtable's RTTI slot, i.e. the first function
     slot plus 106 * 8 bytes).

Run from the repository root:
  python3 research/work-items/RE-001-wal-replay-gate-94/census.py
"""
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BIN = ROOT / "work/hl-node-94.bin"
TARGET = 0x4FA87A0
TEXT_VADDR = 0x1343C80
TEXT_FILE_OFFSET = 0x1342C80
TEXT_SIZE = 0x431C430
RELA_OFFSET = 0x6BC0
RELA_SIZE = 0x1D4E10


def main():
    raw = BIN.read_bytes()
    text = raw[TEXT_FILE_OFFSET:TEXT_FILE_OFFSET + TEXT_SIZE]
    direct = []
    for i in range(len(text) - 5):
        op = text[i]
        if op in (0xE8, 0xE9):
            rel = struct.unpack_from("<i", text, i + 1)[0]
            va = TEXT_VADDR + i
            if va + 5 + rel == TARGET:
                direct.append((hex(va), "call" if op == 0xE8 else "jmp"))
    print("direct sites:", direct)
    slots = []
    rel_entries = {}
    for i in range(RELA_SIZE // 24):
        off, info, add = struct.unpack_from("<QQq", raw, RELA_OFFSET + i * 24)
        if (info & 0xFFFFFFFF) == 8:
            rel_entries[off] = add & (2 ** 64 - 1)
            if add == TARGET:
                slots.append(off)
    print("vtable slots:", [hex(s) for s in sorted(slots)])
    # A vtable's first function slot is two slots past the run start
    # pattern used here: offset-to-top (no relocation) at -16, RTTI
    # relocation at -8, first function at the vtable pointer itself.
    # Each slot below is checked against the consecutive RELATIVE run
    # that contains it: the first function slot is the second entry
    # of the run (run[0] is the RTTI relocation).
    ordered = sorted(rel_entries)
    for slot in sorted(slots):
        idx = ordered.index(slot)
        # walk back to the run start
        start = idx
        while start > 0 and ordered[start - 1] == ordered[start] - 8:
            start -= 1
        first_fn = ordered[start + 1]
        vindex = (slot - first_fn) // 8
        print(f"slot {hex(slot)}: vtable pointer {hex(first_fn)}, "
              f"virtual index {vindex}, byte offset {hex(slot - first_fn)}")
    assert direct == [], "unexpected direct call/jump site"
    assert len(slots) == 4, f"expected 4 vtable slots, got {len(slots)}"
    print("CENSUS OK")


if __name__ == "__main__":
    main()
