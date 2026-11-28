"""Trace the selected retained replay batch's adjacent Block link."""
import hashlib
from pathlib import Path
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
    entries = {0x5A81650, 0x4FACD10, 0x5B2B500, 0x4FADCC0, 0x57E8D40}
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

    def expect(address, encoding):
        assert rows[address] == bytes.fromhex(encoding), hex(address)

    assert operand(0x5A81839, "498dbe") == 0x110
    expect(0x5A818B4, "488b17")
    assert edge(0x5A818CA, "e8") == 0x4FACD10
    expect(0x4FACD3C, "4989d5")
    first = operand(0x4FACDD0, "488d8c24")
    assert first == operand(0x4FACDA3, "4c89ac24")
    expect(0x4FACDAB, "c68424e800000000")
    assert first + 0x10 == 0xE8
    assert edge(0x4FACDD8, "e8") == 0x5B2B500
    expect(0x4FACDE2, "3c2e")
    expect(0x5B2B526, "4889ca")
    assert edge(0x5B2B529, "e8") == 0x4FADCC0
    expect(0x5B2B52E, "807c24182e")
    assert operand(0x5B2B535, "4c897b", 1) == 8
    assert operand(0x5B2B539, "4c8973", 1) == 16
    expect(0x5B2B53D, "c6032e")
    assert operand(0x4FACE04, "4c8b7424", 1) == 0x58
    assert operand(0x4FACE09, "4c8b7c24", 1) == 0x60

    expect(0x4FACDFA, "48ba0100000000000080")
    assert operand(0x4FACE29, "493956", 1) == 0x28
    assert operand(0x4FACE1E, "498d86") == 0xB0
    assert operand(0x4FACE25, "498d4e", 1) == 0x60
    expect(0x4FACE2D, "480f45c8")
    expect(0x4FACE38, "48ffc1")
    expect(0x4FACE3B, "48c7c2ffffffff")
    expect(0x4FACE42, "480f45d1")
    successor = operand(0x4FACE46, "48899424")
    assert operand(0x4FACE31, "498d46", 1) == 0x10
    assert operand(0x4FACE4E, "48898424") == first + 8
    assert operand(0x4FACE67, "488db424") == first
    digest_output = operand(0x4FACE62, "488d7c24", 1)
    assert edge(0x4FACE6F, "e8") == 0x57E8D40
    expect(0x57E8D51, "4989fe")
    expect(0x57E8F93, "410f1106")
    assert operand(0x57E8F8E, "410f114e", 1) == 16
    assert operand(0x4FACE7C, "0f104424", 1) == digest_output
    assert operand(0x4FACE81, "0f104c24", 1) == digest_output + 16
    digest_saved = operand(0x4FACE86, "0f298424")
    assert operand(0x4FACE8E, "0f298c24") == digest_saved + 16

    assert operand(0x4FACEFA, "4c8d63", 1) == 16
    expect(0x4FACEFE, "488b13")
    assert operand(0x4FACF01, "488b4b", 1) == 8
    assert operand(0x4FACFB0, "488b8424") == successor
    assert operand(0x4FACFB8, "48898424") == first
    expect(0x4FACFC0, "c68424e800000001")
    assert operand(0x4FACFC8, "0f288424") == digest_saved
    assert operand(0x4FACFD0, "0f288c24") == digest_saved + 16
    assert operand(0x4FACFD8, "488d8424") == first + 0x11
    assert operand(0x4FACFE0, "0f1148", 1) == 16
    expect(0x4FACFE4, "0f1100")
    assert operand(0x4FAD004, "488d8c24") == first
    assert edge(0x4FAD00C, "e8") == 0x5B2B500

    expect(0x4FADCDE, "4c8b3e")
    expect(0x4FADD0A, "4d3987b8000000")
    expect(0x4FADD1C, "4d394728")
    assert operand(0x4FADCFF, "4d8d67", 1) == 0x28
    assert operand(0x4FADD03, "498dbf") == 0xB8
    expect(0x4FADD11, "490f44fc")
    assert operand(0x4FADD18, "498d47", 1) == 0x30
    expect(0x4FADD20, "480f45c7")
    expect(0x4FADD15, "488b0a")
    assert operand(0x4FADD24, "488b78", 1) == 0x30
    expect(0x4FADD28, "4839cf")
    expect(0x4FADD31, "f6421001")
    assert operand(0x4FADD37, "4883c2", 1) == 0x11
    assert operand(0x4FADD3B, "f30f6f40", 1) == 0x48
    assert operand(0x4FADD40, "f30f6f48", 1) == 0x58
    expect(0x4FADD45, "f30f6f12")
    expect(0x4FADD49, "660f74d0")
    assert operand(0x4FADD4D, "f30f6f42", 1) == 16
    expect(0x4FADD52, "660f74c1")
    expect(0x4FADD56, "660fdbc2")
    expect(0x4FADD5A, "660fd7c8")
    assert operand(0x4FADD5E, "81f9") == 0xFFFF
    assert edge(0x4FADD64, "74", 1) == 0x4FADDB3
    assert edge(0x4FADDCF, "e8") == 0x57E8970

    assert {base + 0x30 for base in (0x30, 0x28, 0xB8)} == {0x60, 0x58, 0xE8}
    assert {base + 0x48 for base in (0x30, 0x28, 0xB8)} == {0x78, 0x70, 0x100}

    print(f"PASS: authenticated {DIGEST}, {len(rows)} spans in {len(bounds)} indexed FDEs")
    print("PASS: first-row continuity word comes from F+0x110 through adapter; no preceding row in this batch")
    print("PASS: accepted predecessor supplies selected saturated successor and 32-byte helper output")
    print("PASS: next row identity is projected through three layouts and all 32 linked bytes compare before onward helper")


if __name__ == "__main__":
    main()
