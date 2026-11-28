"""Verify the selected #115 JSON context identifier counters against the pinned ELF."""
import hashlib
from pathlib import Path
import struct
import sys

PACKET = Path(__file__).resolve().parent
sys.path.insert(0, str(PACKET.parents[2] / "tools"))

from abci_state_read115 import HEIGHT_OPERANDS
from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame


def main():
    assert __debug__, "run without -O"
    data = Path(TARGET).read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET_SHA256
    sections = {item["name"]: item for item in parse_sections(data)}

    def at(name, address, length):
        section = sections[name]
        delta = address - section["va"]
        assert 0 <= delta <= delta + length <= section["size"]
        offset = section["offset"] + delta
        return data[offset:offset + length]

    frame = sections[".eh_frame"]
    _, fdes = walk_eh_frame(at(".eh_frame", frame["va"], frame["size"]), frame["va"])
    indexed = {row["entry"]: row["end"] for row in fdes}
    entries = (0x41FC4A0, 0x409C990, 0x4112920)
    bounds = [(entry, indexed[entry]) for entry in entries]
    windows = {}
    for line in (PACKET / "windows.txt").read_text().splitlines():
        address, encoding, _ = line.split("\t", maxsplit=2)
        address = int(address, 16)
        raw = bytes.fromhex(encoding)
        assert any(start <= address < address + len(raw) <= end for start, end in bounds)
        assert address not in windows and at(".text", address, len(raw)) == raw
        windows[address] = raw

    def edge(address, opcode):
        raw = windows[address]
        assert raw[:-4] == bytes.fromhex(opcode)
        return address + len(raw) + int.from_bytes(raw[-4:], "little", signed=True)

    def entry(table, index):
        return table + struct.unpack("<i", at(".rodata", table + index * 4, 4))[0]

    length_table = edge(0x41FC4B1, "488d0d")
    field_table = edge(0x409CDEF, "488d0d")
    assert entry(length_table, 8 - 3) == 0x41FC5D1
    assert entry(length_table, 12 - 3) == 0x41FC53A
    for address, name in ((0x41FC5F7, b"next_oid"), (0x41FC60A, b"next_lid"),
                          (0x41FC53A, b"next_twa")):
        assert windows[address] == bytes.fromhex("48b9") + name
    assert windows[0x41FC54A] == bytes.fromhex("4881f2") + b"p_id"
    assert edge(0x41FC604, "0f84") == 0x41FC6B9
    assert edge(0x41FC554, "0f84") == 0x41FC69E
    assert [windows[va][-1] for va in (0x41FC6B9, 0x41FC619, 0x41FC69E)] == [7, 8, 9]
    for index, arm, duplicate, colon_edge, colon, call, name in (
        (7, 0x409D109, 0x409D112, 0x409D142, 0x409D65D, 0x409D677, b"next_oid"),
        (8, 0x409D355, 0x409D35E, 0x409D38E, 0x409D723, 0x409D73D, b"next_lid"),
        (9, 0x409CFC2, 0x409CFCB, 0x409CFFB, 0x409D5E3, 0x409D5FD, b"next_twap_id"),
    ):
        assert entry(field_table, index) == arm
        handler = edge(duplicate, "0f84")
        assert at(".rodata", edge(handler, "488d05"), len(name)) == name
        assert edge(colon_edge, "0f83") == colon
        assert edge(call, "e8") == 0x3EF2DC0

    for guard, name in ((0x409D856, b"next_oid"), (0x409D864, b"next_lid")):
        assert at(".rodata", edge(edge(guard, "0f84"), "488d05"), len(name)) == name
    assert windows[0x409D67C] == bytes.fromhex("4889942480000000")
    assert windows[0x409D742] == bytes.fromhex("4889542478")
    assert windows[0x409D602] == bytes.fromhex("4889542408")
    assert windows[0x409D88F] == bytes.fromhex("31c0")
    assert windows[0x409D891] == bytes.fromhex("f68424b000000001")
    assert windows[0x409D89E] == bytes.fromhex("4c0f44f8")
    assert windows[0x409CCE1] == bytes.fromhex("488b842480000000")
    assert windows[0x409CCED] == bytes.fromhex("488b442478")
    assert windows[0x409D899] == bytes.fromhex("4c8b7c2408")
    assert [windows[va] for va in (0x409CCE9, 0x409CCF2, 0x409CCF6)] == [
        bytes.fromhex("48894338"), bytes.fromhex("48894340"), bytes.fromhex("4c897b48"),
    ]

    assert edge(0x411364C, "e8") == 0x409C990

    def operand(address, opcode, width):
        prefix = bytes.fromhex(opcode)
        raw = at(".text", address, len(prefix) + width)
        assert raw.startswith(prefix)
        return int.from_bytes(raw[len(prefix):], "little")

    bulk = {name: operand(address, opcode, width)
            for name, address, opcode, width, _ in HEIGHT_OPERANDS}
    child = bulk["locus_child_buffer"]
    base = bulk["locus_child_load_base"]
    assert operand(0x41136AB, "0f1050", 1) + base + 8 == child + 0x38
    assert operand(0x41136AF, "0f1058", 1) + base == child + 0x40
    assert operand(0x41136BB, "0f299424", 4) == operand(0x4115DD8, "0f109424", 4)
    assert operand(0x41136B3, "0f299c24", 4) == operand(0x4115DE0, "0f109c24", 4)
    result0 = operand(0x4115DF0, "0f119424", 4) + 8
    result1 = operand(0x4115DE8, "0f119c24", 4)

    def carry(position, prefix, length):
        source = bulk[prefix + "_source"]
        destination = bulk.get(prefix + "_dest", 0)
        assert source <= position <= position + length <= source + bulk[prefix + "_size"]
        return destination + position - source

    for position, length, expected in ((result0, 8, 0x38), (result1, 16, 0x40)):
        for number in range(1, 5):
            position = carry(position, f"locus_copy{number}", length)
        assert position == expected
        position += bulk["exchange_child_buffer"]
        for number in range(1, 6):
            position = carry(position, f"exchange_copy{number}", length)
        assert position == expected
        position += bulk["nested_child_buffer"]
        for number in range(1, 3):
            position = carry(position, f"nested_copy{number}", length)
        assert position == expected and position + length <= bulk["outer_copy_size"]

    print("PASS: selected Locus, Exchange, and outer copies preserve all three counter words")
    print(f"PASS: #115 SHA-256 {TARGET_SHA256}; {len(windows)} spans in {len(bounds)} FDEs")
    print("PASS: JSON indices 7/8/9 share an unsigned reader and preserve +0x38/+0x40/+0x48")
    print("PASS: absent TWAP uses zero; both other counters take their named missing paths")



if __name__ == "__main__":
    main()
