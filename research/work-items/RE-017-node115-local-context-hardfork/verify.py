"""Verify the local startup MessagePack Context hardfork projection."""
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
    entries = (0x1B44F30, 0x199CE60, 0x1850600, 0x1AC8460, 0x1B3E730, 0x1A32FA0)
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

    for address, target in (
        (0x1B45512, 0x199CE60),
        (0x199CFCC, 0x1850600),
        (0x1850C6C, 0x1AC8460),
        (0x1AC8D3F, 0x1B3E730),
        (0x1B3F292, 0x27401E0),
        (0x1B3EF87, 0x1A32FA0),
    ):
        assert edge(address, "e8") == target

    def field_arm(table, field):
        return table + struct.unpack("<i", at(".rodata", table + 4 * field, 4))[0]

    assert edge(0x1AC8D13, "488d0d") == 0x5573A8
    assert field_arm(0x5573A8, 0) == 0x1AC8D23
    table = edge(0x1B3EC5A, "488d0d")
    key = selector(data, selector_sections(data), 0x27401E0, 0x2740770,
                   0x5F4788, 3, 14, 13, b"hardfork")
    assert key == 1 and field_arm(table, key) == 0x1B3EF6E

    def encoding(address, expected):
        assert windows[address] == bytes.fromhex(expected), hex(address)

    encoding(0x1A334EA, "ba76657273")
    encoding(0x1A334F4, "ba73696f6e")
    encoding(0x1A337B7, "ba726f756e")
    encoding(0x1A337C2, "83f064")
    encoding(0x1A33503, "31c0")
    assert edge(0x1A33505, "e9") == edge(0x1A338FA, "e9") == 0x1A337D2
    assert edge(0x1A337CA, "0f84") == 0x1A338F8
    encoding(0x1A338F8, "b001")
    assert edge(0x1A337E8, "0f85") == 0x1A331CD
    assert edge(0x1A33876, "ff15") == edge(0x1A338C7, "ff15") == 0x64E2580
    encoding(0x1A3388D, "4889b42490000000")
    encoding(0x1A338DE, "4889b424a0000000")
    encoding(0x1A33D6F, "4c8bbc24a0000000")
    assert edge(0x1A33D77, "0f85") == 0x1A33E4D
    encoding(0x1A33E4D, "488b842490000000")
    encoding(0x1A33E55, "4c89bc24b0000000")
    encoding(0x1A33E5D, "48898424b8000000")
    encoding(0x1A33E65, "c68424a800000009")
    encoding(0x1A33E84, "0f108424a8000000")
    encoding(0x1A33E8C, "0f108c24b8000000")
    assert edge(0x1A33E94, "e9") == 0x1A34076
    encoding(0x1A34076, "0f114b10")
    encoding(0x1A3407A, "0f1103")

    encoding(0x1B3EF91, "3c09")
    encoding(0x1B3EF99, "488b442458")
    encoding(0x1B3EF9E, "48898424f0000000")
    encoding(0x1B3EFA6, "488b442460")
    encoding(0x1B3EFAB, "48898424e8000000")
    encoding(0x1B3EFB8, "4889842450010000")
    encoding(0x1B3FA3A, "31c0")
    encoding(0x1B3FA3C, "f684245001000001")
    encoding(0x1B3FA44, "488b8c24f0000000")
    encoding(0x1B3FA4C, "480f44c8")
    encoding(0x1B3FA50, "488b9424e8000000")
    encoding(0x1B3FA58, "480f44d0")
    assert edge(0x1B3FA64, "0f85") == 0x1B3FC04
    encoding(0x1B3FC7A, "48894b18")
    encoding(0x1B3FC7E, "48895320")

    encoding(0x1AC8D32, "488dbc24700c0000")
    encoding(0x1AC8D6A, "488d9424980c0000")
    encoding(0x1AC8D95, "0f1042f0")
    encoding(0x1AC8D99, "0f29842410060000")
    assert edge(0x1AC8DAD, "0f84") == 0x1ACAAD1
    encoding(0x1AC8E20, "0f28842410060000")
    encoding(0x1AC8E28, "0f29842410180000")
    assert (0xC98 - 0x10) - 0xC70 == 0x18

    print(f"PASS: pinned #115 {TARGET_SHA256}, {len(windows)} spans in {len(bounds)} FDEs")
    print("PASS: selected local outer decoder reaches Context reader 0x1b3e730")
    print("PASS: hardfork maps to field 1 and child 0x1a32fa0, with version and round in order")
    print("PASS: selected map return keeps version/round at +0x18/+0x20, zero on omission")
    print("PASS: caller stages both returned words at stack+0x1810 through stack+0x610")


if __name__ == "__main__":
    main()
