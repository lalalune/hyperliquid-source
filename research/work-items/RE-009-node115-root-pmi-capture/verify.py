"""Recheck compact root-capture evidence using only the pinned ELF bytes."""

from pathlib import Path
import hashlib
import re
import sys

sys.path.insert(0, str(Path.cwd() / "tools"))
from abci_hash_slots_115 import bind
from elf_index import unwind_index
from fde_extents import eh_frame_records
from freeze_snapshot_115 import read_va, relative_relocations

TARGET = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

SLOTS = [(54, 0x42b0)]
TABLE, SIZE, METHOD = 0x64a87c8, 21, 0x4d3f050
CALLS = {
    0x4d3f0a2: 0x64e4d98, 0x4d3f0bf: 0x64e4da0, 0x4d3f0e2: 0x64df560,
    0x4d3f130: 0x64df560, 0x4d3f151: 0x64df538,
    0x43025f0: 0x64df4f8, 0x41f8050: 0x64df600,
}
RELOCATIONS = {
    0x64e4d98: 0x43025f0, 0x64df4f8: 0x141a020,
    0x64e4da0: 0x41f8050, 0x64df600: 0x141b9b0,
    0x64df560: 0x14196d0, 0x64df538: 0x14199b0,
}
KEYS = [(0x5677fd7, b"pmi")]
CONSTANTS = [(0x4d3f0f9, 1), (0x4d3f147, 0)]
PINS = {
    0x4d3f063: "803f01", 0x4d3f07d: "48837e1002", 0x4d3f088: "48ffc7",
    0x4d3f0c5: "3c04", 0x4d3f0cd: "4883c318", 0x4d3f11a: "488d5818",
    0x141b9e3: "8b7710", 0x141b9e6: "89740a10", 0x141b9ea: "0f1007",
    0x141b9ed: "0f11040a", 0x141b9f1: "4883c114", 0x141ba06: "ba14000000",
    0x14199dc: "48890c02", 0x14199e0: "4883c008",
}


def main():
    data = Path("artifacts/node/115/hl-node").read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET
    state_slots = bind(data)["slots"]
    for slot, field in SLOTS:
        row = state_slots[slot]
        assert (int(row["box_field"], 16), int(row["vtable"], 16),
                row["type_size"], int(row["method_0"], 16)) == (field, TABLE, SIZE, METHOD)
    sections, header = unwind_index(data)
    _, fdes = eh_frame_records(data, sections)
    indexed = {(row["start"], row["fde"]) for row in header}
    extents = [(row["start"], row["end"]) for row in fdes
               if (row["start"], row["fde"]) in indexed]
    spans = {}
    for line in Path(__file__).with_name("windows.txt").read_text().splitlines():
        if match := re.match(r"\s+([0-9a-f]+):\s*((?:[0-9a-f]{2} )+)", line):
            address, raw = int(match[1], 16), bytes.fromhex(match[2])
            assert address not in spans
            assert any(start <= address < address + len(raw) <= end for start, end in extents), hex(address)
            assert read_va(data, address, len(raw)) == raw
            spans[address] = raw

    def destination(address, prefixes):
        raw = spans[address]
        assert raw[:-4] in prefixes
        return address + len(raw) + int.from_bytes(raw[-4:], "little", signed=True)

    relocs = relative_relocations(data)
    for address, target in RELOCATIONS.items():
        assert relocs[address] == target
    for address, target in CALLS.items():
        assert destination(address, (b"\xe8", b"\xff\x15", b"\xff\x25")) == target
    for address, key in KEYS:
        target = destination(address, (b"\x48\x8d\x05", b"\x48\x8d\x15"))
        assert read_va(data, target, len(key)) == key
    for address, discriminant in CONSTANTS:
        target = destination(address, (b"\x48\x8d\x3d",))
        assert read_va(data, target, 8) == discriminant.to_bytes(8, "little")
    for address, raw in PINS.items():
        assert spans[address] == bytes.fromhex(raw)

    print(f"PASS: node #115 SHA-256 {TARGET}")
    print(f"PASS: {len(spans)} authenticated spans; compact root slots {[slot for slot, _ in SLOTS]}")
    print(f"PASS: {len(KEYS)} named fields, {len(CALLS)} encoded edges and {len(RELOCATIONS)} relocations")
    print("PASS: qword discriminants 0 and 1; selected child placement, widths and guards")


if __name__ == "__main__":
    main()
