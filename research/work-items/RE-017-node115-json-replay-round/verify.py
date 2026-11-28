"""Verify the selected #115 JSON context replay round against the pinned ELF."""
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
    assert entry(length_table, 5 - 3) == 0x41FC4E3
    assert entry(length_table, 15 - 3) == 0x41FC643
    assert windows[0x41FC4E3] == b"\xb9roun"
    assert windows[0x41FC4EE] == bytes.fromhex("83f264")
    assert windows[0x41FC663] == b"\x48\xb9consensu"
    assert windows[0x41FC670] == b"\x48\xbaus_round"
    assert edge(0x41FC4F9, "e9") == 0x41FC695
    assert windows[0x41FC681] == bytes.fromhex("7412")
    assert 0x41FC681 + 2 + windows[0x41FC681][1] == 0x41FC695
    assert windows[0x41FC695] == bytes.fromhex("b104")
    assert entry(field_table, 4) == 0x409CECF
    assert edge(0x409CED8, "0f84") == 0x409DE18
    assert at(".rodata", edge(0x409DE18, "488d05"), 5) == b"round"
    assert windows[0x409CBB4] == bytes.fromhex("48c78424e000000000000000")
    assert edge(0x409D578, "e8") == 0x3EF2DC0
    assert windows[0x409D57D] == bytes.fromhex("4889942488000000")
    assert windows[0x409D588] == bytes.fromhex("a801")
    assert edge(0x409D58A, "0f85") == 0x409DA61
    assert windows[0x409D595] == bytes.fromhex("48898424e0000000")
    assert windows[0x409D808] == bytes.fromhex("31c0")
    assert windows[0x409D824] == bytes.fromhex("f68424e000000001")
    assert windows[0x409D82C] == bytes.fromhex("4c8ba42488000000")
    assert windows[0x409D834] == bytes.fromhex("4c0f44e0")
    assert windows[0x409CCDD] == bytes.fromhex("4c896330")

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
    assert operand(0x41136AB, "0f1050", 1) + base == child + 0x30
    lane = operand(0x41136BB, "0f299424", 4)
    assert operand(0x4115DD8, "0f109424", 4) == lane
    result = operand(0x4115DF0, "0f119424", 4)

    def carry(position, prefix, length):
        source = bulk[prefix + "_source"]
        destination = bulk.get(prefix + "_dest", 0)
        assert source <= position <= position + length <= source + bulk[prefix + "_size"]
        return destination + position - source

    position = result
    for number in range(1, 5):
        position = carry(position, f"locus_copy{number}", 8)
    assert position == 0x30
    position += bulk["exchange_child_buffer"]
    for number in range(1, 6):
        position = carry(position, f"exchange_copy{number}", 8)
    assert position == 0x30
    position += bulk["nested_child_buffer"]
    for number in range(1, 3):
        position = carry(position, f"nested_copy{number}", 8)
    assert position == 0x30 and position + 8 <= bulk["outer_copy_size"]

    print(f"PASS: #115 SHA-256 {TARGET_SHA256}; {len(windows)} spans in {len(bounds)} FDEs")
    print("PASS: round and consensus_round select the same field and present flag")
    print("PASS: omitted round selects zero; the copy chain preserves +0x30")



if __name__ == "__main__":
    main()
