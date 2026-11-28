"""Verify the selected #115 replay reader limit initialization against the pinned ELF."""
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
    entries = (0x5A806F0, 0x5AB4390)
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

    def operand(address, opcode, signed=False):
        raw = windows[address]
        prefix = bytes.fromhex(opcode)
        assert raw.startswith(prefix), hex(address)
        return int.from_bytes(raw[len(prefix):], "little", signed=signed)

    def expect(address, raw):
        assert windows[address] == bytes.fromhex(raw), hex(address)

    def first_case(table):
        return table + int.from_bytes(at(".rodata", table, 4), "little", signed=True)

    assert bounds == [(0x5A806F0, 0x5A81584), (0x5AB4390, 0x5AB5B4D)]
    assert operand(0x5A80709, "0fb687") == 0x918
    assert first_case(edge(0x5A80710, "488d0d")) == 0x5A80EF9
    assert first_case(edge(0x5A80C23, "488d0d")) == 0x5A80C33
    expect(0x5A80F2D, "4889d8")
    assert edge(0x5A80F30, "e9") == 0x5A808D8

    initial_limit = windows[0x5A80918]
    assert initial_limit[:3] == bytes.fromhex("48c783")
    limit_offset, limit = struct.unpack("<Ii", initial_limit[3:])
    assert (limit_offset, limit) == (0xE8, 10_000_000)
    assert operand(0x5A80923, "488983") == 0x330
    expect(0x5A8092A, "c6833803000000")
    expect(0x5A80931, "66c783410300000000")

    memcpy_slot = edge(0x5A80988, "ff15")
    assert edge(0x5A809DE, "ff15") == edge(0x5A80B19, "4c8b3d") == memcpy_slot
    rela = sections[".rela.dyn"]
    relocation = next(info for offset, info, _ in struct.iter_unpack(
        "<QQq", at(".rela.dyn", rela["va"], rela["size"])
    ) if offset == memcpy_slot)
    assert relocation & 0xFFFFFFFF == 6
    symbol_name_offset = struct.unpack("<I", at(
        ".dynsym", sections[".dynsym"]["va"] + 24 * (relocation >> 32), 4
    ))[0]
    assert at(".dynstr", sections[".dynstr"]["va"] + symbol_name_offset, 7) == b"memcpy\0"

    initial = operand(0x5A80972, "488db3")
    nested = operand(0x5A80979, "4c8dab")
    assert (initial, nested) == (0xC8, 0x350)
    snapshot = operand(0x5A809C9, "488dbc24")
    stack_copy = operand(0x5A80B09, "488dbc24")
    extent = operand(0x5A80980, "ba")
    assert operand(0x5A809D1, "ba") == operand(0x5A80B20, "ba") == extent == 0x280
    assert operand(0x5A80B11, "488db424") == snapshot
    expect(0x5A80985, "4c89ef")
    expect(0x5A809DB, "4c89ee")
    expect(0x5A80B25, "41ffd7")

    aggregate = operand(0x5A80BA0, "488db424")
    future_copy = operand(0x5A80BB3, "488dbb")
    assert operand(0x5A80BA8, "ba") == operand(0x5A80BBA, "ba") == 0x2F0
    assert stack_copy + extent == aggregate + 0x2F0
    expect(0x5A80BAD, "4c89f7")
    expect(0x5A80BBF, "4c89f6")
    expect(0x5A80BB0, "41ffd7")
    expect(0x5A80BC2, "41ffd7")

    def copied_offset(initial_offset):
        relative = initial_offset - initial
        assert 0 <= relative < extent
        return future_copy + (stack_copy - aggregate) + relative

    assert copied_offset(limit_offset) == operand(0x5A80C41, "488b93") == 0x680
    assert copied_offset(0x330) == operand(0x5A80C33, "488b83") == 0x8C8
    assert copied_offset(0x338) == operand(0x5A80C3A, "0fb68b") == 0x8D0
    assert copied_offset(0x341) == operand(0x5A80C1C, "0fb683") == 0x8D9

    assert operand(0x5A80C48, "488993") == operand(0x5A80DB8, "488b8b") == 0x688
    reader = operand(0x5A80CA2, "4c8dab")
    assert operand(0x5A80C79, "488983") == reader == 0x690
    assert operand(0x5A80C80, "888b") - reader == 8
    expect(0x5AB43D8, "488b0b")
    expect(0x5AB43ED, "48894b40")
    assert operand(0x5A80C94, "488993") - reader == operand(0x5AB43DB, "488b43") == 0x20
    assert operand(0x5AB43DF, "488943") == operand(0x5AB57C1, "488b4b") == 0x28
    assert edge(0x5A80CB9, "e8") == 0x5AB4390

    assert edge(0x5A80DE7, "e8") == 0x5860BB0

    print(f"PASS: #115 SHA-256 {TARGET_SHA256}; {len(windows)} spans in {len(bounds)} FDEs")
    print("PASS: both initial table cases and the memcpy relocation match the captured ELF")
    print(f"PASS: {limit:,} comes from producer +0xe8 through the copied reader image")
    print("PASS: the value feeds reader +0x28 for LZ4 and RCX at the replay decoder call")


if __name__ == "__main__":
    main()
