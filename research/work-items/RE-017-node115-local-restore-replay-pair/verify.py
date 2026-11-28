"""Verify the selected #115 expected replay pair on the local-state restore lane against the pinned ELF."""
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
    entries = (0x2CC1120, 0x5A81ED0, 0x5A82670)
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

    def operand(address, opcode):
        raw = windows[address]
        prefix = bytes.fromhex(opcode)
        assert raw.startswith(prefix), hex(address)
        return int.from_bytes(raw[len(prefix):], "little", signed=True)

    def expect(address, raw):
        assert windows[address] == bytes.fromhex(raw), hex(address)

    rela = sections[".rela.dyn"]
    relative = {offset: target for offset, info, target in struct.iter_unpack(
        "<QQq", at(".rela.dyn", rela["va"], rela["size"])
    ) if info == 8}
    assert edge(0x2CC1249, "e8") == 0x26A3610
    assert edge(0x2CC1253, "0f84") == 0x2CC15BA
    assert relative[edge(0x2CC19EA, "ff15")] == 0x3C13610
    assert operand(0x2CC19F4, "498986") == operand(0x2CC2BBD, "498b9f") == 0xE0
    expect(0x2CC2BCE, "488d6801")
    assert edge(0x2CC2BDC, "e9") == 0x2CC1295
    assert operand(0x2CC12A0, "49895f") == operand(0x2CC1651, "4c8b78") == 0x20
    assert operand(0x2CC129C, "49896f") == operand(0x2CC145B, "488b42") == 0x18
    expect(0x2CC146C, "4831f1")
    expect(0x2CC1477, "480f48c1")
    assert edge(0x2CC1483, "0f83") == 0x2CC151A
    assert edge(0x2CC151D, "0f85") == 0x2CC1649
    assert edge(0x2CC16B9, "0f84") == 0x2CC180E
    assert edge(0x2CC1910, "74", 1) == edge(0x2CC191C, "74", 1) == 0x2CC1955
    assert edge(0x2CC1958, "e9") == 0x2CC22CC

    assert operand(0x2CC24B2, "410f1047") == 0x18
    assert operand(0x2CC24B7, "0f294424") == operand(0x2CC2756, "0f284424") == 0x10
    spawn_pair = operand(0x2CC275B, "0f298424") - operand(0x2CC280A, "488dbc24")
    assert spawn_pair == 0x100
    assert relative[edge(0x2CC281F, "ff15")] == 0x5A81ED0
    assert spawn_pair + 16 <= operand(0x5A81FB8, "ba") == 0x118
    assert operand(0x5A82007, "ba") == 0x2D80
    assert edge(0x5A81FC0, "ff15") == edge(0x5A8200F, "ff15") == 0x64DF508
    assert relative[edge(0x5A82015, "488d0d") + 0x18] == 0x5A82670
    assert operand(0x5A874B9, "483bbb") == spawn_pair
    assert operand(0x5A874C6, "483bb3") == spawn_pair + 8

    # The intermediate inline offset on another entry is not the source above.
    assert operand(0x2CC21A1, "4981c7") == 0x120
    table = edge(0x2CC21A8, "488d0d")
    assert table + int.from_bytes(at(".rodata", table, 4), "little", signed=True) == 0x2CC21B8
    assert edge(0x2CC21BF, "e9") == 0x2CC631C
    assert edge(0x2CC6356, "e8") == 0x2CB1EB0
    assert operand(0x2CC638A, "4c8bbc24") == 0x148

    print(f"PASS: #115 SHA-256 {TARGET_SHA256}; {len(windows)} spans in {len(bounds)} FDEs")
    print("PASS: local restore builder pointer survives the tagged output selection into R15")
    print("PASS: empty-vector continuation copies restored state +0x18/+0x20 to replay comparison +0x100/+0x108")
    print("PASS: the first inline-state dispatch routes through a separate call and replaces R15 on its selected result")


if __name__ == "__main__":
    main()
