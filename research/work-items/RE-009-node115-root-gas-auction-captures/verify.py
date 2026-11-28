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

SLOTS = [(28, 0x3a00), (29, 0x3a40), (30, 0x3a80)]
TABLE, SIZE, METHOD = 0x64a84f8, 64, 0x4d3e9b0
CALLS = {
    0x4d3e9fe: 0x64df560, 0x4d3ea50: 0x64e4d78, 0x4d3ea6d: 0x64e4d80,
    0x4d3ea8c: 0x64df560, 0x4d3eaad: 0x64df538, 0x3d1ecd2: 0x41ade90,
}
RELOCATIONS = {
    0x64df560: 0x14196d0, 0x64df538: 0x14199b0,
    0x64e4d78: 0x3d1eb60, 0x64e4d80: 0x3d1ebc0,
    0x6478790: 0x46f4560, 0x6476f70: 0x43c6a50, 0x64787b8: 0x45147f0,
    0x6474038: 0x4302e70, 0x64741e0: 0x141b3c0,
}
KEYS = [
    (0x54811fa, b"register_token_gas_auction"),
    (0x5481225, b"perp_deploy_gas_auction"),
    (0x5481250, b"spot_pair_deploy_gas_auction"),
]
CONSTANTS = [(0x4d3ea15, 0), (0x4d3eaa3, 1)]
PINS = {
    0x4d3e9c3: "833f02", 0x4d3e9d9: "48837e1002", 0x4d3e9e8: "488d5818",
    0x4d3ea73: "3c04", 0x3d1eb64: "bf90000000", 0x3d1eb95: "48c70306000000",
    0x3d1eba0: "48c7431006000000", 0x3d1ebca: "488d4f10", 0x3d1ebdf: "488d4f28",
    0x3d1ebf4: "48897c2428", 0x3d1ec05: "488d5730", 0x3d1ec1a: "488d5720",
    0x3d1ec2f: "4883c738", 0x41adeb9: "48837f1006", 0x14199dc: "48890c02",
    0x14199e0: "4883c008",
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
