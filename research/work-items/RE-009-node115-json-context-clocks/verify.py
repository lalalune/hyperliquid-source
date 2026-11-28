"""Verify the selected #115 JSON context clock fields against the pinned ELF."""
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
    entries = (0x41FC4A0, 0x409C990, 0x3FD2100, 0x4112920)
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
    assert entry(length_table, 4 - 3) == 0x41FC525
    assert entry(length_table, 9 - 3) == 0x41FC4FE
    assert windows[0x41FC525] == b"\x81\x3e" + b"time"
    assert windows[0x41FC4FE] == b"\x48\xb9" + b"prev_tim"
    assert windows[0x41FC50F] == bytes.fromhex("4883f265")
    assert windows[0x41FC531] == bytes.fromhex("b105")
    assert windows[0x41FC51C] == bytes.fromhex("b106")
    assert entry(field_table, 5) == 0x409D1E0
    assert entry(field_table, 6) == 0x409D285

    for name, call, duplicate_guard, missing_guard in (
        (b"time", 0x409D4EB, 0x409D1E5, 0x409D83D),
        (b"prev_time", 0x409D534, 0x409D28A, 0x409D848),
    ):
        assert edge(call, "e8") == 0x3FD2100
        duplicate = edge(duplicate_guard, "0f85")
        missing = edge(missing_guard, "0f84")
        for handler in (duplicate, missing):
            assert at(".rodata", edge(handler, "488d05"), len(name)) == name

    for stage, save, reload, store, target, width in (
        (0x4C, 0x409D4FF, 0x409CD0C, 0x409CD10, 0x60, 4),
        (0xF0, 0x409D508, 0x409CD13, 0x409CD1B, 0x64, 8),
        (0x48, 0x409D548, 0x409CD1F, 0x409CD23, 0x6C, 4),
        (0xE8, 0x409D551, 0x409CD26, 0x409CD2E, 0x70, 8),
    ):
        if width == 4:
            assert windows[save] == bytes.fromhex("894424") + bytes([stage])
            assert windows[reload] == bytes.fromhex("8b4424") + bytes([stage])
            assert windows[store] == bytes.fromhex("8943") + bytes([target])
        else:
            delta = stage.to_bytes(4, "little")
            assert windows[save] == bytes.fromhex("48898424") + delta
            assert windows[reload] == bytes.fromhex("488b8424") + delta
            assert windows[store] == bytes.fromhex("488943") + bytes([target])

    assert windows[0x3FD2188] == bytes.fromhex("4180f822")
    assert edge(0x3FD21AB, "ff15") == 0x64E08F8
    assert edge(0x3FD21D3, "e8") == 0x472E8C0
    assert windows[0x3FD21E3] == bytes.fromhex("89430c")
    assert windows[0x3FD21EB] == bytes.fromhex("48894304")
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
    assert operand(0x411368C, "0f1040", 1) + base == child + 0x60
    assert operand(0x4113680, "0f1040", 1) + base == child + 0x70
    lane0 = operand(0x4113690, "0f298424", 4)
    lane1 = operand(0x4113684, "0f298424", 4)
    assert operand(0x4115DA8, "0f108424", 4) == lane0
    assert operand(0x4115D98, "0f108424", 4) == lane1
    result0 = operand(0x4115DB0, "0f118424", 4)
    result1 = operand(0x4115DA0, "0f118424", 4)

    def carry(position, prefix, length):
        source = bulk[prefix + "_source"]
        destination = bulk.get(prefix + "_dest", 0)
        assert source <= position <= position + length <= source + bulk[prefix + "_size"]
        return destination + position - source

    for position, length, expected in ((result0, 16, 0x60), (result1, 8, 0x70)):
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

    print("PASS: selected Locus, Exchange, and outer copies preserve all 24 clock bytes")
    print(f"PASS: #115 SHA-256 {TARGET_SHA256}; {len(windows)} spans in {len(bounds)} FDEs")
    print("PASS: JSON indices 5/6 call the same quoted time reader and project to +0x60/+0x6c")
    print("PASS: duplicate and missing paths preserve the distinct key names")



if __name__ == "__main__":
    main()
