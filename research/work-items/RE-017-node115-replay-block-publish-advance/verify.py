"""Verify the native replay Block publisher and its local baseline update."""
import hashlib
from pathlib import Path
import struct
import sys

PACKET = Path(__file__).resolve().parent
sys.path.insert(0, str(Path.cwd() / "tools"))

from elf_index import unwind_index
from fde_extents import eh_frame_records

TARGET = Path("artifacts/node/115/hl-node")
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def main():
    assert __debug__, "run without -O"
    data = TARGET.read_bytes()
    assert hashlib.sha256(data).hexdigest() == DIGEST
    sections, header = unwind_index(data)
    _, fdes = eh_frame_records(data, sections)
    entries = {0x5A81650, 0x5A897E0, 0x4FACD10, 0x581B0C0}
    indexed = {(row["start"], row["fde"]) for row in header}
    bounds = {
        row["start"]: row["end"] for row in fdes
        if row["start"] in entries and (row["start"], row["fde"]) in indexed
    }
    assert set(bounds) == entries
    sections_by_name = {section["name"]: section for section in sections}

    def at(name, address, size):
        section = sections_by_name[name]
        delta = address - section["address"]
        assert 0 <= delta <= delta + size <= section["size"]
        offset = section["offset"] + delta
        return data[offset:offset + size]

    def matches(address, raw):
        return at(".text", address, len(raw)) == raw

    rows = {}
    for line in (PACKET / "windows.txt").read_text().splitlines():
        address, encoding, _ = line.split("\t", 2)
        address, raw = int(address, 16), bytes.fromhex(encoding)
        assert address not in rows and matches(address, raw)
        assert any(start <= address < address + len(raw) <= end for start, end in bounds.items())
        rows[address] = raw

    def operand(address, opcode, width=4):
        raw = rows[address]
        assert raw[:-width] == bytes.fromhex(opcode), hex(address)
        return int.from_bytes(raw[-width:], "little", signed=True)

    def edge(address, opcode, width=4):
        return address + len(rows[address]) + operand(address, opcode, width)

    def expect(address, raw):
        assert rows[address] == bytes.fromhex(raw), hex(address)

    rela = sections_by_name[".rela.dyn"]
    relative = {
        slot: addend for slot, kind, addend in struct.iter_unpack(
            "<QQq", at(".rela.dyn", rela["address"], rela["size"])
        ) if kind == 8
    }

    assert operand(0x5A89AE3, "488bb3") == 0xA8
    assert operand(0x5A89AF1, "0f1083") == 0xC8
    assert operand(0x5A89AF8, "0f108b") == 0xD8
    assert operand(0x5A89B07, "0f294424", 1) == operand(0x5A89B11, "488d5424", 1) == 0x70
    assert operand(0x5A89AFF, "0f298c24") == 0x80
    assert relative[edge(0x5A89B16, "ff15")] == 0x5A81650
    expect(0x5A81775, "4989f6")
    baseline_field = operand(0x5A81839, "498dbe")
    assert baseline_field == operand(0x5A8167A, "483b86") == 0x110
    assert edge(0x5A81681, "0f86") == 0x5A81775
    text = b"failed to verify client block batch: bad commit proof"
    assert at(".rodata", edge(0x5A816B0, "488d05"), len(text)) == text

    expect(0x5A81661, "4989d7")
    assert operand(0x5A818A0, "498b47", 1) == 0x10
    expect(0x5A818A9, "f3410f6f07")
    assert operand(0x5A818AE, "660f7f4424", 1) == operand(0x5A818BF, "4c8d7c24", 1) == 0x10
    expect(0x5A818C4, "4c89fe")
    expect(0x5A818B4, "488b17")
    result = operand(0x5A818B7, "488dbc24")
    assert edge(0x5A818CA, "e8") == 0x4FACD10
    assert operand(0x5A818DF, "0fb69424") == result == 0xF0
    assert operand(0x5A818FF, "80fa", 1) == 0x2E
    assert edge(0x5A81902, "0f85") == 0x5A81AC5
    assert operand(0x5A818EF, "488bac24") == result + 0x10
    assert operand(0x5A818F7, "488b8424") == result + 0x18

    expect(0x5A81912, "4989c4")
    shift = operand(0x5A81915, "49c1e4", 1)
    assert shift == 4
    expect(0x5A81919, "4901ec")
    assert edge(0x5A8193F, "0f84") == 0x5A81A6F
    expect(0x5A81955, "4889e8")
    assert operand(0x5A81958, "4883c5", 1) == 1 << shift
    expect(0x5A81964, "488b08")
    assert operand(0x5A81967, "4c8b48", 1) == 8
    mark = operand(0x5A81908, "49bf", 8) + operand(0x5A81945, "4d8d47", 1)
    assert mark == -(1 << 63) + 1
    assert operand(0x5A81976, "4c3941", 1) == 0x28
    expect(0x5A8197A, "480f44d0")
    load = operand(0x5A8197E, "4c8b6a", 1)
    assert operand(0x5A8196B, "488d41", 1) + load == 0x60
    assert operand(0x5A8196F, "488d91") + load == 0xB0
    expect(0x5A81982, "49ffc5")
    assert operand(0x5A81949, "48c7c7") == -1
    expect(0x5A81985, "4c0f44ef")

    assert operand(0x5A81995, "4d8bbe") == 0xC8
    assert operand(0x5A8199C, "498b87") == operand(0x5A819C7, "490fb197") == 0x1C0
    assert rows[0x5A819C6] == b"\xf0"
    assert edge(0x5A819CF, "75", 1) == 0x5A819B0
    send_pair = operand(0x5A81950, "488d7424", 1)
    assert operand(0x5A819D6, "48894c24", 1) == send_pair == 0x70
    assert operand(0x5A819DB, "4c894c24", 1) == send_pair + 8
    assert operand(0x5A819E0, "498dbf") == 0x80
    assert edge(0x5A819E7, "e8") == 0x581B0C0
    assert operand(0x5A819EC, "498b87") == operand(0x5A81A08, "490fb18f") == 0x110
    assert rows[0x5A81A07] == b"\xf0"
    assert edge(0x5A81A15, "75", 1) == edge(0x5A81A3C, "74", 1) == 0x5A81A41
    assert operand(0x5A81A41, "498d86") == baseline_field
    expect(0x5A81A48, "4c8928")
    assert operand(0x5A81A64, "488d7424", 1) == send_pair
    expect(0x5A81A4B, "4c39e5")
    assert edge(0x5A81A69, "0f85") == 0x5A81955

    assert operand(0x5A81A4E, "49bf", 8) == operand(0x5A897FA, "48bd", 8) == mark - 1
    assert operand(0x5A81A7C, "4c897b", 1) == 8
    assert operand(0x5A81A80, "c603", 1) == operand(0x5A89B23, "807c2410", 1) == 0x44
    assert operand(0x5A89B36, "0f104424", 1) - operand(0x5A89B0C, "488d7c24", 1) == 8
    assert operand(0x5A89B47, "0f1183") == operand(0x5A89B98, "0f1083") == 0x118
    assert operand(0x5A89BA6, "0f1183") == operand(0x5A89BC2, "4839ab") == 0xE8
    assert edge(0x5A89BC9, "0f84") == 0x5A89F2B

    for address in (0x5A81958, 0x5A819DB, 0x5A81A41):
        raw = rows[address]
        assert not matches(address, raw[:-1] + bytes([raw[-1] ^ 1]))
    check_publication_projection(shift)

    print(f"PASS: SHA-256 {DIGEST}; {len(rows)} ranges in authenticated FDEs")
    print("PASS: normal retained-result tag 0x2e exposes pair rows and an exclusive endpoint")
    print("PASS: publish ordered Block/attachment words, then advance F+0x110 using the same Block owner")
    print("PASS: distinct notification owner, repeat/exhaustion edges, synthetic ordered pairs and altered witness controls")


def check_publication_projection(shift):
    rows = struct.pack("<4Q", 10, 20, 30, 40)
    data = {10: (True, 100, 11), 30: (False, 12, 101)}
    cursor, end = 0, 2 << shift
    events = []
    while cursor != end:
        block, attachments = struct.unpack_from("<QQ", rows, cursor)
        cursor += 1 << shift
        marker, first_word, other_word = data[block]
        events.append(("published", block, attachments))
        events.append(("baseline", (first_word if marker else other_word) + 1))
    assert events == [
        ("published", 10, 20), ("baseline", 101),
        ("published", 30, 40), ("baseline", 102),
    ]


if __name__ == "__main__":
    main()
