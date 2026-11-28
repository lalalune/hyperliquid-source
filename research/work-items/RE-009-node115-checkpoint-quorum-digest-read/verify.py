"""Check the selected quorum digest writer paths without executing the ELF."""

import hashlib
from pathlib import Path
import struct
import sys

PACKET = Path(__file__).resolve().parent
sys.path.insert(0, str(Path.cwd() / "tools"))

from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame


def main():
    assert __debug__, "run without -O"
    data = Path(TARGET).read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET_SHA256
    sections = {section["name"]: section for section in parse_sections(data)}

    def at(name, address, length):
        section = sections[name]
        delta = address - section["va"]
        assert 0 <= delta <= delta + length <= section["size"]
        offset = section["offset"] + delta
        return data[offset:offset + length]

    frame = sections[".eh_frame"]
    _, fdes = walk_eh_frame(at(".eh_frame", frame["va"], frame["size"]), frame["va"])
    indexed = {row["entry"]: row["end"] for row in fdes}
    entries = (0x4214250, 0x41903C0, 0x41C7230, 0x42136D0, 0x4213B10, 0x41C6110, 0x41C6610)
    bounds = [(entry, indexed[entry]) for entry in entries]
    def matches_window(address, raw):
        return (any(start <= address < address + len(raw) <= end for start, end in bounds)
                and at(".text", address, len(raw)) == raw)

    windows = {}
    for line in (PACKET / "windows.txt").read_text().splitlines():
        address, encoding, _ = line.split("\t", maxsplit=2)
        address = int(address, 16)
        raw = bytes.fromhex(encoding)
        assert address not in windows
        assert matches_window(address, raw)
        windows[address] = raw

    def operand(address, opcode):
        prefix = bytes.fromhex(opcode)
        raw = windows[address]
        assert raw.startswith(prefix) and len(raw) > len(prefix)
        return int.from_bytes(raw[len(prefix):], "little")

    def edge(address, opcode):
        prefix = bytes.fromhex(opcode)
        raw = windows[address]
        assert raw.startswith(prefix) and len(raw) > len(prefix)
        return address + len(raw) + int.from_bytes(raw[len(prefix):], "little", signed=True)

    def name_at(address, length, expected):
        assert at(".rodata", address, length) == expected

    assert edge(0x4214306, "75") == 0x4214326
    name_at(edge(0x4214308, "488d35"), operand(0x421430F, "ba"), b"qrs")
    assert edge(0x4214317, "e8") == 0x41C6110
    assert operand(0x4214326, "498d56") == 0x48
    assert edge(0x4214330, "e8") == 0x41903C0
    assert edge(0x4190426, "e8") == 0x3D50270
    assert edge(0x4190479, "e8") == edge(0x41905A9, "e8") == 0x41C7230
    stride = operand(0x41905BC, "4983c7")
    assert stride == 104

    assert operand(0x41C728B, "ba") == 2
    assert edge(0x41C7290, "e8") == 0x3D50270
    assert windows[0x41C7409] == bytes.fromhex("c6 04 01 92")
    assert windows[0x41C72DA] == windows[0x41C743C] == bytes.fromhex("49 8b 17")
    assert edge(0x41C7449, "e8") == 0x41D3710
    assert edge(0x41C73D1, "e8") == 0x4213B10
    assert edge(0x41C7527, "e8") == 0x42136D0

    assert edge(0x4213B34, "74") == 0x4213B68
    assert operand(0x4213B3E, "ba") == operand(0x4213B70, "ba") == 3
    assert edge(0x4213B43, "e8") == 0x3D4F6D0
    assert edge(0x4213B75, "e8") == 0x3D50270
    assert edge(0x4213B8A, "75") == 0x4213BAA
    name_at(edge(0x4213B8C, "488d35"), operand(0x4213B93, "ba"), b"h")
    assert edge(0x4213B9B, "e8") == 0x41C6110
    assert windows[0x42136EF] == bytes.fromhex("40 80 f5 01")
    assert windows[0x42136F3] == bytes.fromhex("40 c0 e5 04")
    assert windows[0x42136F7] == bytes.fromhex("40 80 cd 83")
    assert windows[0x4213708] == bytes.fromhex("40 88 2c 30")
    assert (0x83 | ((1 ^ 1) << 4), 0x83 | ((0 ^ 1) << 4)) == (0x83, 0x93)
    assert edge(0x421371C, "75") == 0x421374D
    assert operand(0x421372E, "c60431") == 0xA1
    assert operand(0x4213742, "c60431") == ord("h")

    for row, body, cap, length, trim, encoder, writer, target in (
        (0x41C73C2, 0x4213BAA, 0x4213BD1, 0x4213BD6, 0x4213BDB, 0x4213BDE, 0x4213BEA, 0x41C6110),
        (0x41C7518, 0x4213713, 0x4213777, 0x421377C, 0x4213781, 0x4213784, 0x4213790, 0x41C6610),
    ):
        assert operand(row, "4983c7") == 8
        assert operand(body, "498d57") == 0x40
        assert 8 + 0x40 + 32 <= stride
        assert operand(cap, "be") == 66
        assert operand(length, "b9") == 32
        assert windows[trim] == bytes.fromhex("45 31 c0")
        assert edge(encoder, "ff15") == 0x64E4D08
        assert edge(writer, "e8") == target

    reloc = sections[".rela.dyn"]
    assert [
        (kind, target)
        for address, kind, target in struct.iter_unpack("<QQq", at(".rela.dyn", reloc["va"], reloc["size"]))
        if address == 0x64E4D08
    ] == [(8, 0x2EABB50)]
    assert at(".rodata", 0x455D40, 16) == b"0123456789abcdef"
    assert operand(0x41C6160, "c60430") == operand(0x41C66A9, "42c60427") == 0xD9
    assert not matches_window(0x4213742, bytes.fromhex("c6 04 31 69"))
    assert not matches_window(0x421377C, bytes.fromhex("b9 1f 00 00 00"))
    print(f"verified {len(windows)} instruction windows in {len(bounds)} FDEs and two negative byte controls")
    print("named qrs: [u64 height, body], 104-byte native stride, body digest at row +0x48")
    print("both MessagePack writer routes: named h or first positional slot, 32 bytes -> str8 lowercase hex")


if __name__ == "__main__":
    main()
