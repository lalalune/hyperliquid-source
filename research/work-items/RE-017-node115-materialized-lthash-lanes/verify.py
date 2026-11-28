"""Authenticate the three LtHash cache lane offsets in the node #115 materializer."""

import csv
import hashlib
from pathlib import Path
import struct
import sys

from compare_lanes import COMPACT_SIZE, OFFSETS, RECORD_SIZE

sys.path.insert(0, str(Path.cwd() / "tools"))
from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame

PACKET = Path(__file__).parent


def main():
    assert __debug__, "run without -O"
    image = Path(TARGET).read_bytes()
    assert hashlib.sha256(image).hexdigest() == TARGET_SHA256
    sections = {section["name"]: section for section in parse_sections(image)}

    def read(name, address, size):
        section = sections[name]
        delta = address - section["va"]
        assert 0 <= delta <= delta + size <= section["size"]
        offset = section["offset"] + delta
        return image[offset:offset + size]

    frame = sections[".eh_frame"]
    _, fdes = walk_eh_frame(read(".eh_frame", frame["va"], frame["size"]), frame["va"])
    bounds = {fde["entry"]: fde["end"] for fde in fdes}
    windows = {}
    owners = set()
    with (PACKET / "instructions.tsv").open() as handle:
        for row in csv.DictReader(handle, delimiter="\t"):
            owner, address = (int(row[field], 16) for field in ("fde", "va"))
            raw = bytes.fromhex(row["bytes"])
            assert owner <= address < address + len(raw) <= bounds[owner]
            assert address not in windows and read(".text", address, len(raw)) == raw
            windows[address] = raw
            owners.add(owner)

    def operand(site, prefix):
        raw = windows[site]
        assert raw[:-4] == bytes.fromhex(prefix)
        return int.from_bytes(raw[-4:], "little")

    def edge(site, opcode):
        raw = windows[site]
        assert raw[:-4] == bytes.fromhex(opcode)
        return site + len(raw) + int.from_bytes(raw[-4:], "little", signed=True)

    assert edge(0x38C2867, "e8") == 0x3C27F30
    assert edge(0x38C2899, "e8") == 0x3C284F0
    assert edge(0x38C28C8, "e8") == 0x3C28210
    assert edge(0x3C2EC16, "e8") == 0x434B9F0
    assert edge(0x38C2749, "e8") == 0x422E730
    rela = sections[".rela.dyn"]
    relative = {address: target for address, info, target in struct.iter_unpack(
        "<QQq", read(".rela.dyn", rela["va"], rela["size"]),
    ) if info == 8}
    assert relative[edge(0x434BB73, "ff15")] == 0x38C2690

    constructor_shift = [operand(site, "488dbb") for site in
                         (0x3C27F85, 0x3C28545, 0x3C28265)]
    assert all(operand(site, "ba") == RECORD_SIZE for site in
               (0x3C27F8C, 0x3C2854C, 0x3C2826C, 0x38C27E4, 0x38C2800, 0x38C281F))
    base = operand(0x38C28CD, "4c8dac24")
    starts = [base, operand(0x38C28EF, "488dbc24"), operand(0x38C2907, "488dbc24")]
    assert operand(0x38C2932, "488db424") == base
    record_aggregate_size = operand(0x38C28E4, "ba")
    assert [start - base for start in starts] == [0, record_aggregate_size, 2 * record_aggregate_size]
    assert [sizes + RECORD_SIZE for sizes in constructor_shift] == [record_aggregate_size] * 3
    assert operand(0x38C293A, "ba") == operand(0x434BBB5, "ba") == 0x1B20
    assert operand(0x434BC9D, "ba") == 0x1B40
    insertion = operand(0x3C2F1AC, "488dbb")
    assert [insertion + start - base + shift for start, shift in zip(starts, constructor_shift)
            ] == list(OFFSETS.values())
    assert operand(0x3C1366B, "bf") == COMPACT_SIZE

    print(f"PASS: #115 {TARGET_SHA256}, {len(windows)} exact spans in {len(owners)} FDEs")
    print("PASS: ordered selected cache constructors and compact offsets " +
          ", ".join(f"{name}={offset:#x}" for name, offset in OFFSETS.items()))


if __name__ == "__main__":
    main()
