"""Verify local MessagePack Context height and round against node #115."""
import hashlib
from pathlib import Path
import struct
import sys

PACKET = Path(__file__).resolve().parent
sys.path.insert(0, str(PACKET.parents[2] / "tools"))

from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame
from abci_binary_context115 import selector
from elf_index import sections as selector_sections


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
    entries = (0x1B3E730, 0x1AC8460)
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

    def expect(address, raw):
        assert windows[address] == bytes.fromhex(raw), hex(address)

    assert edge(0x1AC8D3F, "e8") == 0x1B3E730
    assert edge(0x1B3F292, "e8") == 0x27401E0
    table = edge(0x1B3EC5A, "488d0d")
    string_sections = selector_sections(data)
    for key, index, target in (
        (b"height", 2, 0x1B3EE76),
        (b"round", 4, 0x1B3ED7E),
        (b"consensus_round", 4, 0x1B3ED7E),
    ):
        assert selector(data, string_sections, 0x27401E0, 0x2740770,
                        0x5F4788, 3, 14, 13, key) == index
        entry = struct.unpack("<i", at(".rodata", table + 4 * index, 4))[0]
        assert table + entry == target
    assert selector(data, string_sections, 0x27401E0, 0x2740770,
                    0x5F4788, 3, 14, 13, b"consensus_roune") == 13

    expect(0x1B3ED7E, "4883bc243801000001")
    assert edge(0x1B3ED87, "0f84") == 0x1B405A6
    assert edge(0x1B3ED95, "e8") == 0x2D15BC0
    expect(0x1B3ED9F, "3c09")
    assert edge(0x1B3EDA1, "0f85") == 0x1B40262
    expect(0x1B3EDA7, "488b442458")
    expect(0x1B3EDAC, "48898424d8000000")
    expect(0x1B3EDB9, "4889842438010000")

    expect(0x1B3EE76, "4883bc240001000001")
    assert edge(0x1B3EE7F, "0f84") == 0x1B40574
    assert edge(0x1B3F6B9, "ff15") == 0x64E2580
    expect(0x1B3F6C4, "488b4c2458")
    expect(0x1B3F6C9, "3c09")
    assert edge(0x1B3F6CB, "0f85") == 0x1B3FCF6
    expect(0x1B3F6D1, "48898c2498010000")
    expect(0x1B3F6DE, "4889842400010000")

    expect(0x1B3F9BE, "31c0")
    expect(0x1B3F9C0, "f684243801000001")
    expect(0x1B3F9C8, "488bbc24d8000000")
    expect(0x1B3F9D0, "480f44f8")
    expect(0x1B3FA5C, "f684240001000001")
    assert edge(0x1B3FA64, "0f85") == 0x1B3FC04
    assert edge(0x1B3FA6A, "e9") == 0x1B3FF2D
    expect(0x1B3FC82, "488b842498010000")
    expect(0x1B3FC8A, "48894328")
    expect(0x1B3FC8E, "48897b30")
    expect(0x1AC8DB3, "488d8c24980c0000")
    expect(0x1AC8DD3, "0f1001")
    expect(0x1AC8DFA, "0f29842480040000")
    assert 0xC98 - 0xC70 == 0x28

    print(f"PASS: pinned #115 {TARGET_SHA256}; {len(windows)} spans in {len(bounds)} FDEs")
    print("PASS: local MessagePack height and round use distinct fields; round alias shares the guard")
    print("PASS: missing round selects zero; height must be present for the selected return")
    print("PASS: Context +0x28/+0x30 copied together into Locus stack+0x480")


if __name__ == "__main__":
    main()
