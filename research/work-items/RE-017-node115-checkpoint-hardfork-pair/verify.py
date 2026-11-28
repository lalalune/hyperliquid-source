"""Verify the MessagePack checkpoint Context hardfork field projection."""
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
    entries = (0x30D1C60, 0x32B03E0)
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

    def encoding(address, expected):
        assert windows[address] == bytes.fromhex(expected), hex(address)

    encoding(0x32B0911, "4883f905")
    encoding(0x32B091B, "4883f907")
    encoding(0x32B0928, "8b08")
    encoding(0x32B0931, "8b4003")
    first = windows[0x32B092A][1:]
    second = windows[0x32B0934][1:]
    assert first[-1:] == second[:1] and first + second[1:] == b"version"
    assert edge(0x32B0915, "0f84") == 0x32B0BF5
    encoding(0x32B0BFE, "0fb64004")
    assert windows[0x32B0BF7][1:] + windows[0x32B0C02][-1:] == b"round"

    encoding(0x32B0943, "31c0")
    assert edge(0x32B0945, "e9") == edge(0x32B0D3A, "e9") == 0x32B0C12
    assert edge(0x32B0C0A, "0f84") == 0x32B0D38
    encoding(0x32B0D38, "b001")
    encoding(0x32B0C26, "84c0")
    assert edge(0x32B0C28, "0f85") == 0x32B060D
    reader_slot = edge(0x32B0D07, "ff15")
    assert edge(0x32B0CB6, "ff15") == reader_slot == 0x64E2580
    rela = sections[".rela.dyn"]
    assert any(
        (address, info, value) == (reader_slot, 8, 0x348E980)
        for address, info, value in struct.iter_unpack(
            "<QQq", at(".rela.dyn", rela["va"], rela["size"])
        )
    )
    encoding(0x32B0D1E, "4889b424a0000000")
    encoding(0x32B0CCD, "4889b42490000000")
    encoding(0x32B11AF, "4c8bbc24a0000000")
    assert edge(0x32B11B7, "0f85") == 0x32B128D
    encoding(0x32B128D, "488b842490000000")
    encoding(0x32B1295, "4c89bc24b0000000")
    encoding(0x32B129D, "48898424b8000000")
    encoding(0x32B12A5, "c68424a800000009")
    encoding(0x32B12C4, "0f108424a8000000")
    encoding(0x32B12CC, "0f108c24b8000000")
    assert edge(0x32B12D4, "e9") == 0x32B14B6
    encoding(0x32B14B6, "0f114b10")
    encoding(0x32B14BA, "0f1103")

    table = 0x68AC4C
    assert table + struct.unpack("<i", at(".rodata", table + 4, 4))[0] == 0x30D249E
    assert edge(0x30D24B7, "e8") == edge(0x30D32E1, "e8") == 0x32B03E0
    encoding(0x30D24B0, "488d7c2450")
    encoding(0x30D24BC, "0fb6442450")
    encoding(0x30D24C1, "3c09")
    encoding(0x30D24C9, "488b442458")
    encoding(0x30D24CE, "48898424f0000000")
    encoding(0x30D24D6, "488b442460")
    encoding(0x30D24DB, "48898424e8000000")
    encoding(0x30D24E3, "b801000000")
    encoding(0x30D24E8, "4889842450010000")

    encoding(0x30D2F6A, "31c0")
    encoding(0x30D2F6C, "f684245001000001")
    encoding(0x30D2F74, "488b8c24f0000000")
    encoding(0x30D2F7C, "480f44c8")
    encoding(0x30D2F80, "488b9424e8000000")
    encoding(0x30D2F88, "480f44d0")
    assert edge(0x30D2F94, "0f85") == 0x30D3134
    encoding(0x30D31AA, "48894b18")
    encoding(0x30D31AE, "48895320")
    encoding(0x30D31BA, "48894328")
    encoding(0x30D31BE, "48897b30")

    encoding(0x30D32EB, "3c09")
    encoding(0x30D32F9, "f30f6f442410")
    encoding(0x30D3808, "660f7f842450010000")
    encoding(0x30D3C7E, "660f6f842450010000")
    encoding(0x30D3C87, "f30f7f442468")
    encoding(0x30D3D7A, "660f6f4c2460")
    encoding(0x30D3D80, "0f28542470")
    assert edge(0x30D3D8D, "e9") == 0x30D2ED1
    encoding(0x30D2ED5, "0f115320")
    encoding(0x30D2ED9, "f30f7f4b10")
    print(f"PASS: pinned #115 {TARGET_SHA256}, {len(windows)} instruction spans in {len(bounds)} FDEs")
    print("PASS: hardfork map keys version and round feed the u64 reader and tag-9 payload in order")
    print("PASS: Context map projects the pair at +0x18/+0x20, or zeros both when omitted")
    print("PASS: selected positional Context return projects the same pair at +0x18/+0x20")


if __name__ == "__main__":
    main()
