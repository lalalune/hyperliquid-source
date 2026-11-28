"""Verify the selected local JSON Context height and round projection."""
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
    entries = (0x1F8E960, 0x2740770, 0x1F7E100, 0x2CC1120)
    bounds = [(entry, indexed[entry]) for entry in entries]
    windows = {}
    for line in (PACKET / "windows.txt").read_text().splitlines():
        address, encoding, _ = line.split("\t", maxsplit=2)
        address = int(address, 16)
        raw = bytes.fromhex(encoding)
        assert any(start <= address < address + len(raw) <= end for start, end in bounds)
        assert address not in windows and at(".text", address, len(raw)) == raw
        windows[address] = raw

    def edge(address, opcode, width=4):
        raw = windows[address]
        assert raw[:-width] == bytes.fromhex(opcode)
        return address + len(raw) + int.from_bytes(raw[-width:], "little", signed=True)

    def expect(address, raw):
        assert windows[address] == bytes.fromhex(raw), hex(address)

    def table_entry(table, index):
        return table + struct.unpack("<i", at(".rodata", table + 4 * index, 4))[0]

    key_table = edge(0x2740781, "488d0d")
    assert table_entry(key_table, 5 - 3) == 0x27407B3
    assert table_entry(key_table, 6 - 3) == 0x274087F
    assert windows[0x274087F][1:] + windows[0x274088A][2:4] == b"height"
    assert windows[0x27407B3][1:] + windows[0x27407BE][-1:] == b"round"
    first = windows[0x2740933][2:]
    second = windows[0x2740940][2:]
    assert first[-1:] == second[:1] and first + second[1:] == b"consensus_round"
    expect(0x274094A, "48335607")
    assert edge(0x27407C9, "e9") == 0x2740965
    assert edge(0x2740951, "74", width=1) == 0x2740965
    expect(0x2740965, "b104")
    expect(0x2740898, "b102")

    assert edge(0x1F8ED9C, "e8") == 0x2740770
    table = edge(0x1F8EDB1, "488d0d")
    assert table_entry(table, 2) == 0x1F8EFFC
    assert table_entry(table, 4) == 0x1F8EE91
    assert edge(0x1F8F002, "0f84") == 0x1F8FD40
    assert edge(0x1F8EE9A, "0f84") == 0x1F8FDA0
    assert at(".rodata", edge(0x1F8FD40, "488d05"), 6) == b"height"
    assert at(".rodata", edge(0x1F8FDA0, "488d05"), 5) == b"round"

    assert edge(0x1F8F032, "0f83") == 0x1F8F5E6
    assert edge(0x1F8EECA, "0f83") == 0x1F8F520
    assert edge(0x1F8F600, "e8") == edge(0x1F8F53A, "e8") == 0x1D772E0
    expect(0x1F8F605, "4889d5")
    expect(0x1F8ED45, "4989ed")
    expect(0x1F8F615, "4889442468")
    expect(0x1F8F53F, "4889942488000000")
    expect(0x1F8F557, "48898424e0000000")
    expect(0x1F8F7BF, "f644246801")
    assert edge(0x1F8F7C4, "0f84") == 0x1F8FA66
    assert at(".rodata", edge(0x1F8FA66, "488d05"), 6) == b"height"
    expect(0x1F8F7CA, "31c0")
    expect(0x1F8F7E6, "f68424e000000001")
    expect(0x1F8F7EE, "4c8ba42488000000")
    expect(0x1F8F7F6, "4c0f44e0")
    expect(0x1F8EC9B, "48896b28")
    expect(0x1F8EC9F, "4c896330")
    expect(0x1F7EEAE, "0f105020")
    expect(0x1F7EEBE, "0f299424e0020000")
    assert 0x348 + 0x20 - 0x338 == 0x30
    expect(0x2CC1AB3, "488b4828")
    expect(0x2CC1C71, "498b7630")
    expect(0x2CC1C87, "49897620")

    print(f"PASS: #115 {TARGET_SHA256}; {len(windows)} spans in {len(bounds)} FDEs")
    print("PASS: height uses field 2; round and consensus_round share field 4")
    print("PASS: selected JSON map requires height and defaults absent round to zero")
    print("PASS: separate Context result offsets are +0x28 and +0x30")


if __name__ == "__main__":
    main()
