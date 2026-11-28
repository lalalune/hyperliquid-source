"""Verify the selected normal positional context clock projection."""
import hashlib
from pathlib import Path
import sys

PACKET = Path(__file__).resolve().parent
sys.path.insert(0, str(PACKET.parents[2] / "tools"))

from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame


def main():
    assert __debug__, "run without -O"
    data = Path(TARGET).read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET_SHA256
    sections = {section["name"]: section for section in parse_sections(data)}

    def section_bytes(section):
        return data[section["offset"]:section["offset"] + section["size"]]

    frame = sections[".eh_frame"]
    _, fdes = walk_eh_frame(section_bytes(frame), frame["va"])
    by_entry = {row["entry"]: row["end"] for row in fdes}
    bounds = [(entry, by_entry[entry]) for entry in (0x30D1C60, 0x30410D0)]
    text_section = sections[".text"]
    text = section_bytes(text_section)
    spans = {}
    for line in (PACKET / "windows.txt").read_text().splitlines():
        address, encoding, _ = line.split("\t", maxsplit=2)
        address = int(address, 16)
        raw = bytes.fromhex(encoding)
        offset = address - text_section["va"]
        assert any(start <= address < address + len(raw) <= end for start, end in bounds)
        assert address not in spans and text[offset:offset + len(raw)] == raw
        spans[address] = raw

    def edge(address, opcode):
        raw = spans[address]
        assert raw[:-4] == bytes.fromhex(opcode)
        return address + len(raw) + int.from_bytes(raw[-4:], "little", signed=True)

    assert edge(0x30D38AA, "e8") == 0x3D4F3C0
    assert edge(0x30D38E6, "e8") == 0x30410D0
    assert edge(0x30410F8, "e8") == 0x2F6FA30
    assert spans[0x30D389A] == bytes.fromhex("418d47fa")
    assert spans[0x30410DF] == bytes.fromhex("ffc8")
    assert spans[0x3041128] == bytes.fromhex("c7430400000000")
    for guard, opcode, handler, formatter, index in (
        (0x30D388F, "0f84", 0x30D39E8, 0x30D39FB, 5),
        (0x30D390D, "0f84", 0x30D3DB9, 0x30D3DCC, 6),
        (0x30D3941, "0f85", 0x30D3DD6, 0x30D3DE9, 7),
        (0x30D3975, "0f85", 0x30D3E02, 0x30D3E15, 8),
    ):
        assert edge(guard, opcode) == handler
        assert spans[formatter] == bytes([0xBE, index, 0, 0, 0])
        assert edge(formatter + 5, "e9") == 0x30D338E
    assert edge(0x30D338E, "e8") == 0x2F7FE90

    for source_write, source_read, stage_write, source, stage in (
        (0x30D38C0, 0x30D3CEA, 0x30D3CF1, 0x100, 0xB0),
        (0x30D38D4, 0x30D3CF8, 0x30D3D00, 0x120, 0xB4),
        (0x30D3904, 0x30D3D08, 0x30D3D0F, 0xE4, 0xBC),
        (0x30D3918, 0x30D3D16, 0x30D3D1E, 0x138, 0xC0),
    ):
        assert int.from_bytes(spans[source_write][-4:], "little") == source
        assert int.from_bytes(spans[source_read][-4:], "little") == source
        assert int.from_bytes(spans[stage_write][-4:], "little") == stage
    assert spans[0x30D3D50] == bytes.fromhex("0f288424b0000000")
    assert spans[0x30D3D58] == bytes.fromhex("0f114360")
    assert spans[0x30D3D44] == bytes.fromhex("0f288424c0000000")
    assert spans[0x30D3D4C] == bytes.fromhex("0f114370")
    print(f"PASS: {TARGET_SHA256}; {len(spans)} instruction spans in two #115 FDEs")
    print("PASS: positional clock projection output +0x60/+0x6c; formatter operands 5/6/7/8")


if __name__ == "__main__":
    main()
