"""Verify the selected #115 positional replay key against the pinned ELF."""
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
    entries = (0x30D1C60,)
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

    rela = sections[".rela.dyn"]
    relative = {offset: target for offset, info, target in struct.iter_unpack(
        "<QQq", at(".rela.dyn", rela["va"], rela["size"])
    ) if info == 8}
    assert relative[edge(0x30D381C, "ff15")] == 0x348E980
    assert edge(0x30D3846, "e8") == 0x451C540
    assert edge(0x30D3879, "e8") == 0x4524AE0
    for compare, guard, length in (
        (0x30D3834, 0x30D3838, 3),
        (0x30D3858, 0x30D385C, 4),
        (0x30D388B, 0x30D388F, 5),
    ):
        assert windows[compare] == bytes.fromhex("4183ff") + bytes([length])
        assert edge(guard, "0f84") == 0x30D39E8

    assert windows[0x30D3827] == bytes.fromhex("4c8b6c2410")
    assert windows[0x30D3895] == bytes.fromhex("488b6c2410")
    assert windows[0x30D38F8] == bytes.fromhex("4889ac2418010000")
    assert windows[0x30D3C8D] == bytes.fromhex("4c896c2478")
    assert windows[0x30D3C92] == bytes.fromhex("488b8c2418010000")
    assert windows[0x30D3C9A] == bytes.fromhex("48898c2480000000")
    assert windows[0x30D3D80] == bytes.fromhex("0f28542470")
    assert windows[0x30D3D85] == bytes.fromhex("0f289c2480000000")
    assert edge(0x30D3D8D, "e9") == 0x30D2ED1
    assert windows[0x30D2ED5] == bytes.fromhex("0f115320")
    assert windows[0x30D2ED1] == bytes.fromhex("0f115b30")
    print(f"PASS: #115 SHA-256 {TARGET_SHA256}; {len(windows)} spans in the context reader FDE")
    print("PASS: positional height and round use distinct decoders and reach output +0x28/+0x30")
    print("PASS: successful decoding still requires the following required clock slots")



if __name__ == "__main__":
    main()
