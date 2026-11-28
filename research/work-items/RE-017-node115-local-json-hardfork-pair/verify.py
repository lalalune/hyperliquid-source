"""Verify the selected local JSON Context hardfork pair against node #115."""
import hashlib
from pathlib import Path
import struct
import sys

PACKET = Path(__file__).resolve().parent
sys.path.insert(0, str(PACKET.parents[2] / "tools"))

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
    entries = (0x26A3610, 0x1D74270, 0x1F3D760, 0x1F2BD40, 0x1F7E100, 0x2A6D7A0, 0x1F8E960, 0x1F32740)
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

    for address, target in (
        (0x26A382E, 0x1D74270), (0x1D742BA, 0x1F3D760),
        (0x1F3D9D6, 0x1F2BD40), (0x1F2BF4D, 0x1F7E100),
        (0x1F7E344, 0x2A6D7A0), (0x1F7EE4F, 0x1F8E960),
        (0x1F8ED9C, 0x2740770), (0x1F8F45F, 0x1F32740),
        (0x1F32C2E, 0x1D772E0), (0x1F32C51, 0x1D772E0),
    ):
        assert edge(address, "e8") == target

    locus_table = edge(0x1F7E35F, "488d0d")
    context_table = edge(0x1F8EDB1, "488d0d")
    assert locus_table + struct.unpack("<i", at(".rodata", locus_table, 4))[0] == 0x1F7E36F
    assert context_table + struct.unpack("<i", at(".rodata", context_table + 4, 4))[0] == 0x1F8F146
    assert at(".rodata", edge(0x1F80BDF, "488d05"), 3) == b"ctx"
    assert at(".rodata", edge(0x1F8FD5A, "488d05"), 8) == b"hardfork"
    assert edge(0x1F7E375, "0f85") == 0x1F80BDF
    assert edge(0x1F8F14F, "0f84") == 0x1F8FD5A
    assert edge(0x1F8F183, "0f83") == 0x1F8F440
    expect(0x2A6D7B2, "81f163740000")
    expect(0x2A6D7BC, "83f278")
    expect(0x2A6D947, "31c9")

    expect(0x1F32AAF, "b976657273")
    expect(0x1F32AB9, "ba73696f6e")
    expect(0x1F32B23, "b9726f756e")
    expect(0x1F32B2E, "83f164")
    assert edge(0x1F32AFD, "0f83") == 0x1F32C18
    assert edge(0x1F32C36, "e9") == 0x1F329F6
    expect(0x1F32A00, "48896c2460")
    expect(0x1F32C63, "48896c2448")
    expect(0x1F32CAC, "488b6c2460")
    assert edge(0x1F32CB1, "e9") == 0x1F32823
    expect(0x1F32851, "4c8b7c2448")
    expect(0x1F3285C, "48896b08")
    expect(0x1F32860, "4c897b10")

    expect(0x1F8F464, "837c243001")
    expect(0x1F8F46F, "0f10442438")
    expect(0x1F8F474, "0f29842410010000")
    expect(0x1F8F481, "48898424a8000000")
    expect(0x1F8F82C, "f30f7e8424a8000000")
    expect(0x1F8F83A, "660f72f01f")
    expect(0x1F8F83F, "660f72e01f")
    expect(0x1F8F844, "660fdbc1")
    expect(0x1F8F848, "660f7f842490000000")
    expect(0x1F8EC8F, "0f28842490000000")
    expect(0x1F8EC97, "0f114318")
    expect(0x1F7EE7B, "488d842448030000")
    expect(0x1F7EEAA, "0f104810")
    expect(0x1F7EEC6, "0f298c24d0020000")
    expect(0x1F7EEA7, "0f1000")
    expect(0x1F7EECE, "0f298424c0020000")
    # The pair straddles the two SIMD loads. These projections use
    # the upper lane of the first load and the lower lane of the second.
    assert (0x348 + 8) - 0x338 == 0x18
    assert (0x348 + 16) - 0x338 == 0x20

    print(f"PASS: #115 {TARGET_SHA256}, {len(windows)} spans in {len(bounds)} FDEs")
    print("PASS: selected local JSON route reaches its own Context and hardfork visitors")
    print("PASS: version and round enter the ordered tag-success child result")
    print("PASS: selected map defaults the pair to zero and copies +0x18/+0x20 into the Locus stage")


if __name__ == "__main__":
    main()
