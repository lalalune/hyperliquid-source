"""Check shared raw-root capture ordinals in both native node #115 layouts."""

import csv
import hashlib
from pathlib import Path
import sys

sys.path.insert(0, str(Path.cwd() / "tools"))
import abci_block_root115 as expanded
import abci_hash_slots_115 as compact
from freeze_snapshot_115 import read_va, relative_relocations, rip_target

DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET = Path("artifacts/node/115/hl-node")
TABLE = Path(__file__).with_name("capture-layouts.tsv")
SHARED_WIDTH = 0xB70
UNCHANGED = {0: 0x0, 2: 0x80, 8: 0x670}


def capture_layouts(data):
    image = expanded.Image(data)
    right = expanded.captures(image)
    other_slots, count, allocation, group_size = expanded.parse_descriptor_stream(image, right)
    left = compact.builder_pointers(data)
    left_rows = compact.bind(data)["slots"]
    assert len(left) == len(right) == 74
    assert len(left_rows) == len(other_slots) == count == 59
    assert allocation == count * 24 and group_size == 16

    rows = []
    for index, (before, row) in enumerate(zip(left, right)):
        assert row["index"] == index
        after = int(row["state_offset"], 16)
        if index in UNCHANGED:
            assert before == after == UNCHANGED[index]
        else:
            assert before >= 0x7C0 and after == before + SHARED_WIDTH
        slot = max(0, index - 15)
        rows.append((index, slot, hex(before), hex(after), hex(after - before), left_rows[slot]["vtable"]))

    for index, (a, b) in enumerate(zip(left_rows, other_slots)):
        assert a["slot"] == b["index"] == index
        assert a["vtable"] == b["descriptor_va"]
        assert a["method_0"] == b["visit_target_va"]
        assert a["method_1"] == b["create_target_va"]
        assert (a["type_size"], a["type_align"]) == (b["size"], b["alignment"])
        if index:
            assert a["pointer_index"] == int(b["capture_index"]) == index + 15
    return rows


def verify_boundaries(data):
    relocs = relative_relocations(data)
    for call, prefix, slot, target in (
        (0x4e35359, b"\xff\x15", 0x64df500, 0x141a250),
        (0x4e34999, b"\xff\x15", 0x64df500, 0x141a250),
        (0x548db1a, b"\xff\x15", 0x64e7820, 0x41c5140),
        (0x548d90a, b"\xff\x15", 0x64e7820, 0x41c5140),
    ):
        assert rip_target(data, call, prefix, 6) == slot
        assert relocs[slot] == target
    for call, target in (
        (0x4e35324, 0x54423c0), (0x4e34964, 0x54423c0),
        (0x548db0f, 0x4e46090), (0x548d8ff, 0x4e47350),
        (0x4e46129, 0x4e34ce0), (0x4e473e9, 0x4e34320),
    ):
        assert rip_target(data, call, b"\xe8", 5) == target
    for site in (0x4e35329, 0x4e34969):
        assert read_va(data, site, 2) == b"\x3c\x04"


def main():
    data = TARGET.read_bytes()
    assert hashlib.sha256(data).hexdigest() == DIGEST
    verify_boundaries(data)
    rows = capture_layouts(data)
    with TABLE.open(newline="") as handle:
        reader = csv.reader(handle, delimiter="\t")
        assert next(reader) == [
            "pointer", "slot", "compact_offset", "expanded_offset", "delta", "descriptor",
        ]
        assert list(reader) == [list(map(str, row)) for row in rows]
    print(f"PASS: node #115 SHA-256 {DIGEST}")
    print("PASS: 74 captures, 59 paired descriptor ordinals, 16 grouped captures")
    print("PASS: 71 offsets shift by +0xb70; capture offsets 0, 0x80 and 0x670 are unchanged")
    print("PASS: both successful root paths use one dispatcher, reducer and final digest target")


if __name__ == "__main__":
    main()
