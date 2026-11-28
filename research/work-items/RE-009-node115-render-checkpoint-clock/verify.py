"""Verify the selected #115 checkpoint clock rendering inputs against the pinned ELF."""
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
    entries = (0x1627430, 0x5307510)
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

    years = at(".rodata", edge(0x162771E, "488d35"), 400)
    month_day = edge(0x1627738, "488d15")
    assert windows[0x162775A] == bytes.fromhex("c1e20d")
    assert windows[0x162776B] == bytes.fromhex("c1ee04")
    assert windows[0x162776E] == bytes.fromhex("81e6ff010000")

    for year, month, day, expected in (
        (2026, 1, 2, 0x00FD402A),
        (2000, 2, 29, 0x00FA03C4),
        (2016, 12, 31, 0x00FC16E3),
        (-1, 1, 1, 0xFFFFE01B),
    ):
        base = (month << 9) | (day << 4) | years[year % 400]
        delta = int.from_bytes(at(".rodata", month_day + (base >> 3), 1), "little", signed=True)
        assert delta != 0
        word = ((year << 13) | (base - 8 * delta)) & 0xFFFFFFFF
        assert word == expected
        print(f"PASS: calendar table input {year:05d}-{month:02d}-{day:02d} yields {word:#010x}")

    assert windows[0x5307581] == bytes.fromhex("be54000000")
    assert windows[0x5307586] == bytes.fromhex("ff5020")
    assert windows[0x530758D] == bytes.fromhex("4983c704")
    rela = sections[".rela.dyn"]
    relative = {offset: target for offset, info, target in struct.iter_unpack(
        "<QQq", at(".rela.dyn", rela["va"], rela["size"])
    ) if info == 8}
    assert relative[edge(0x5307569, "ff15")] == 0x1628BC0
    assert relative[edge(0x5307599, "ff15")] == 0x162A760
    print(f"PASS: #115 SHA-256 {TARGET_SHA256}; {len(windows)} checked instruction spans")
    print("PASS: checkpoint date and time formatters are separated by literal 0x54")



if __name__ == "__main__":
    main()
