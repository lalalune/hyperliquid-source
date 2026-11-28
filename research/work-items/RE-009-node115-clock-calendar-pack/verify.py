"""Verify the selected #115 checkpoint calendar packing against the pinned ELF."""
from datetime import date, timedelta
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
    entries = (0x1627430, 0x1627E60)
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

    assert windows[0x1627706] == bytes.fromhex("69d290010000")
    year_table = at(".rodata", edge(0x162771E, "488d35"), 400)
    month_day_table = edge(0x1627738, "488d15")
    assert windows[0x1627729] == bytes.fromhex("c1e109")
    assert windows[0x162772C] == bytes.fromhex("c1e004")
    assert windows[0x1627735] == bytes.fromhex("c1e903")
    assert windows[0x162773F] == bytes.fromhex("0fbe0c11")
    assert edge(0x1627745, "0f84") == 0x16277FA
    assert windows[0x1627755] == bytes.fromhex("c1e103")
    assert windows[0x1627758] == bytes.fromhex("29c8")
    assert windows[0x162775A] == bytes.fromhex("c1e20d")
    assert windows[0x162775D] == bytes.fromhex("09c2")
    assert windows[0x16279FF] == bytes.fromhex("49c1e420")
    assert windows[0x1628397] == bytes.fromhex("48c1e820")
    assert windows[0x1628466] == bytes.fromhex("8903")
    rela = sections[".rela.dyn"]
    relative = {offset: target for offset, info, target in struct.iter_unpack(
        "<QQq", at(".rela.dyn", rela["va"], rela["size"])
    ) if info == 8}
    assert relative[edge(0x1627E7C, "ff15")] == 0x1627430

    def packed(year, month, day):
        encoded = (month << 9) | (day << 4) | year_table[year % 400]
        shift = int.from_bytes(at(".rodata", month_day_table + (encoded >> 3), 1),
                               "little", signed=True)
        if shift == 0:
            return None
        return (year << 13) | (encoded - (shift << 3))

    count = 0
    day = date(2000, 1, 1)
    while day.year < 2400:
        value = packed(day.year, day.month, day.day)
        assert value >> 13 == day.year
        assert (value >> 4) & 0x1FF == day.timetuple().tm_yday
        day += timedelta(days=1)
        count += 1
    assert count == 146097
    assert packed(2000, 2, 29) is not None
    assert packed(2100, 2, 29) is None
    assert packed(2026, 4, 31) is None
    print(f"PASS: #115 SHA-256 {TARGET_SHA256}; {len(windows)} spans in two FDEs")
    print(f"PASS: selected table model agrees with Gregorian ordinal for {count} dates (2000–2399)")
    print("PASS: 2000-02-29 accepted; 2100-02-29 and 2026-04-31 have zero lookup entries")



if __name__ == "__main__":
    main()
