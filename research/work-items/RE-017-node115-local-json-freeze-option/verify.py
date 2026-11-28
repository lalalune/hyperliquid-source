"""Verify the local JSON scheduled-freeze option through its materializer input."""
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
    entries = (0x1F2BD40, 0x1D7F620, 0x22A76D0, 0x3C2E860, 0x2CC1120)
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

    assert edge(0x1F2BE3B, "e8") == 0x1D7F620
    table = edge(0x1D7F7FE, "4c8d3d")
    entry = struct.unpack("<i", at(".rodata", table + 13 * 4, 4))[0]
    assert table + entry == 0x1D80844
    assert edge(0x1D8084D, "0f85") == 0x1D8ABFF
    assert at(".rodata", edge(0x1D8ABFF, "488d05"), 23) == b"scheduled_freeze_height"
    expect(0x1D8AC0E, "48c784245809000017000000")
    assert edge(0x1D8088A, "0f83") == 0x1D8219B
    assert edge(0x1D821BD, "e8") == 0x22A76D0

    # Null terminates with tag zero; a scalar's success tag advances to one.
    for address, prefix, letter in (
        (0x22A773C, "4183f9", b"n"),
        (0x22A7762, "4080ff", b"u"),
        (0x22A777A, "4180f8", b"l"),
        (0x22A7792, "80f9", b"l"),
    ):
        expect(address, prefix + letter.hex())
    expect(0x22A7797, "31c0")
    expect(0x22A7799, "eb0f")
    assert edge(0x22A779E, "e8") == 0x1D772E0
    expect(0x22A77A3, "48ffc0")
    expect(0x22A77A6, "48895308")
    expect(0x22A77AA, "488903")

    # Missing, null and present all have distinct states before map completion.
    expect(0x1D7F8D7, "b802000000")
    expect(0x1D7F8DC, "48898424a8000000")
    expect(0x1D80844, "4883bc24a800000002")
    expect(0x1D821CA, "4883f802")
    assert edge(0x1D821CE, "0f84") == 0x1D860A1
    expect(0x1D821D4, "48898424a8000000")
    expect(0x1D821DC, "488b842458090000")
    expect(0x1D821E4, "4889842458040000")
    expect(0x1D87B7F, "4531ed")
    expect(0x1D87B82, "488b8424a8000000")
    expect(0x1D87B8A, "4883f802")
    expect(0x1D87B8E, "4c0f45e8")
    expect(0x1D909D6, "4d89ac24e8100000")
    expect(0x1D909DE, "488b842458040000")
    expect(0x1D909E6, "49898424f0100000")

    expect(0x1F2BE62, "488db42488340000")
    expect(0x1F2BE6A, "baa8270000")
    assert edge(0x1F2BE6F, "ff15") == 0x64DF508
    expect(0x1F2C1A8, "ba98270000")
    assert edge(0x1F2C1CE, "ff15") == 0x64DF508
    expect(0x3C2EB57, "410f1086e8100000")
    expect(0x3C2F05F, "0f1183e8100000")
    expect(0x2CC1AA6, "83b8e810000001")
    expect(0x2CC1AB7, "483988f0100000")
    assert 0x10E8 >= 0x10 and 0x10F0 + 8 <= 0x27A8

    print(f"PASS: pinned #115 {TARGET_SHA256}; {len(windows)} spans in {len(bounds)} FDEs")
    print("PASS: local JSON map field 13 binds scheduled_freeze_height to the option reader")
    print("PASS: absent/null return tag 0 and the successful scalar path returns tag 1")
    print("PASS: selected output offsets match the materializer and startup guard")


if __name__ == "__main__":
    main()
