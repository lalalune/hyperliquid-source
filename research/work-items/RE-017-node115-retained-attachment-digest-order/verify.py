"""Trace selected retained replay attachment inputs and their ordered Block digests."""
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
    entries = {0x5B2B500, 0x4FADCC0}
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

    rela = sections_by_name[".rela.dyn"]
    slots = {}
    for slot, kind, addend in struct.iter_unpack("<QQq", at(".rela.dyn", rela["address"], rela["size"])):
        if slot in (0x64E0148, 0x64E0150):
            assert slot not in slots
            slots[slot] = (kind, addend)
    assert slots == {0x64E0148: (8, 0x5CDA910), 0x64E0150: (8, 0x5CDAD40)}

    # Original incoming pair stays in order across the retained-row adapter.
    expect(0x5B2B512, "4889742408")
    expect(0x5B2B517, "4889542410")
    assert operand(0x5B2B521, "488d7424", 1) == 8
    assert edge(0x5B2B529, "e8") == 0x4FADCC0
    expect(0x4FADCDE, "4c8b3e")
    expect(0x4FADDB8, "4889f3")
    assert edge(0x4FADDCF, "e8") == 0x57E8970
    expect(0x4FADDD4, "80bc24600100002e")
    assert operand(0x4FADE02, "488b43", 1) == 8

    attachment_rows = operand(0x4FADE06, "4c8b60", 1)
    attachment_saved = operand(0x4FADE0A, "48894424", 1)
    attachment_length = operand(0x4FADE0F, "488b40", 1)
    assert attachment_rows == 0x18 and attachment_length == 0x20
    assert operand(0x4FADE13, "48c1e0", 1) == 3
    expect(0x4FADE17, "488d1c80")
    assert edge(0x4FADE33, "0f84") == 0x4FADFBD
    expect(0x4FADE39, "4b8d0434")
    expect(0x4FADE3D, "0f1000")
    assert operand(0x4FADE40, "0f1048", 1) == 16
    expected_high = operand(0x4FADE44, "0f294c24", 1)
    expected_low = operand(0x4FADE49, "0f294424", 1)
    assert expected_high == expected_low + 16
    assert operand(0x4FADE4E, "4b8b4434", 1) == 32
    assert operand(0x4FADE53, "488b70", 1) == 0x18
    assert operand(0x4FADE57, "488b50", 1) == 0x20
    sponge = operand(0x4FADE1E, "4c8dac24")
    assert sponge + 0xD0 == 0x150 and sponge + 0xD8 == 0x158
    expect(0x4FADED0, "48c784245001000088000000")
    expect(0x4FADEDC, "66c78424580100000100")
    expect(0x4FADEE6, "4c89ef")
    assert edge(0x4FADEE9, "ff15") == 0x64E0148
    assert operand(0x4FADF00, "ba") == 32
    output = operand(0x4FADF08, "488d7424", 1)
    assert edge(0x4FADF0D, "ff15") == 0x64E0150
    assert operand(0x4FADF13, "660f6f4424", 1) == output
    assert operand(0x4FADF19, "660f6f4c24", 1) == output + 16
    assert operand(0x4FADF28, "660f744c24", 1) == expected_high
    assert operand(0x4FADF2E, "660f744424", 1) == expected_low
    expect(0x4FADF34, "660fdbc1")
    expect(0x4FADF38, "660fd7c0")
    attachment_stride = operand(0x4FADF3C, "4983c6", 1)
    assert operand(0x4FADF40, "3d") == 0xFFFF
    assert edge(0x4FADF45, "0f84") == 0x4FADE30

    # The separate counted comparison keeps 40-byte and 32-byte strides.
    assert operand(0x4FADFBD, "488b5424", 1) == attachment_saved
    assert operand(0x4FADFC2, "488b4a", 1) == attachment_length
    assert operand(0x4FADFC6, "498b47", 1) == 0x20
    expect(0x4FADFCA, "4839c1")
    assert operand(0x4FADFDE, "488b72", 1) == attachment_rows
    assert operand(0x4FADFE2, "498b57", 1) == 0x18
    assert 1 << operand(0x4FADFE6, "48c1e0", 1) == 32
    expect(0x4FAE00A, "f30f6f06")
    assert operand(0x4FAE00E, "f30f6f4e", 1) == 16
    assert operand(0x4FAE013, "4883c6", 1) == attachment_stride == 40
    expect(0x4FAE017, "f30f6f12")
    assert operand(0x4FAE01F, "f30f6f42", 1) == 16
    assert operand(0x4FAE024, "4883c2", 1) == 32
    expect(0x4FAE01B, "660f74d0")
    expect(0x4FAE028, "660f74c1")
    expect(0x4FAE02C, "660fdbc2")
    expect(0x4FAE030, "660fd7f8")
    assert operand(0x4FAE03C, "81ff") == 0xFFFF
    assert edge(0x4FAE042, "74", 1) == 0x4FAE000
    assert edge(0x4FAE003, "74", 1) == 0x4FAE046
    assert edge(0x4FAE049, "74", 1) == 0x4FAE064
    assert edge(0x4FAE069, "74", 1) == 0x4FAE07C
    expect(0x4FAE07C, "41c6062e")
    expect(0x5B2B52E, "807c24182e")
    expect(0x5B2B535, "4c897b08")
    expect(0x5B2B539, "4c897310")

    # Two distinct harmless rows provide an independent stride control.
    digests = [bytes(range(32)), bytes(range(32, 64))]
    attachments = b"".join(digest + b"ownerptr" for digest in digests)
    block = b"".join(digests)
    assert [attachments[pos:pos + 32] for pos in range(0, len(attachments), attachment_stride)] == digests
    assert [block[pos:pos + 32] for pos in range(0, len(block), 32)] == digests

    print(f"PASS: authenticated {DIGEST}, {len(rows)} spans in {len(bounds)} indexed FDEs")
    print("PASS: two relocated sponge slots receive exact attachment byte view and write a 32-byte digest")
    print("PASS: row digest precedes equal-count ordered 40-/32-byte digest comparison")
    print("PASS: ordinarily accepted path preserves both original owner words; two-row stride control")


if __name__ == "__main__":
    main()
