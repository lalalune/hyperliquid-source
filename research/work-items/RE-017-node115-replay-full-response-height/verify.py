"""Trace the Full output and height to the selected replica JSON encoder."""
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
    entries = {0x4F122C0, 0x4FCB590, 0x5A6E1E0, 0x595A6B0, 0x50E2F80, 0x4D6D740, 0x506E230, 0x4D6D170, 0x502D0D0}
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

    assert operand(0x4FCB874, "4c8b79", 1) == 0x28
    assert edge(0x4FCB87F, "74", 1) == 0x4FCB8E8
    assert operand(0x4FCB92A, "4c897c24", 1) == 0x68
    assert operand(0x4FCBB99, "0f284c24", 1) == 0x60
    assert operand(0x4FCBBB3, "0f1148", 1) == 0x10
    assert edge(0x4F1234C, "e8") == 0x4FCB590
    expect(0x4F12346, "4889df")
    expect(0x4F12351, "4889d8")

    block_result = operand(0x5A6E96E, "488d6c24", 1)
    assert block_result == 0x60
    expect(0x5A6E9F6, "4889ef")
    assert edge(0x5A6EA10, "e8") == 0x4F122C0
    assert operand(0x5A6EA2A, "0f104424", 1) == block_result
    assert operand(0x5A6EA1D, "488b4424", 1) == block_result + 0x10
    saved = operand(0x5A6EA2F, "0f298424")
    assert operand(0x5A6EA22, "48898424") == saved + 0x10
    assert operand(0x5A6EA43, "488b4424", 1) == block_result + 0x18
    height = operand(0x5A6EA48, "48898424")
    assert operand(0x5A6EC5C, "4c8bb424") == height == operand(0x5A6F981, "488bb424")
    record_height = operand(0x5A6EF02, "4c89b424")

    assert operand(0x5A6F8C3, "450fb6b7") == 0x6B8
    assert operand(0x5A6F8CB, "4180fe", 1) == 1
    assert edge(0x5A6F8D2, "75", 1) == 0x5A6F916
    assert operand(0x5A6F8D4, "488b8424") == saved + 0x10
    assert operand(0x5A6F8E8, "0f288424") == saved
    restore_base = operand(0x5A6F8DC, "488d8c24")
    restore = restore_base + operand(0x5A6F8F0, "0f1141", 1)
    assert restore == 0x67
    assert restore_base + operand(0x5A6F8E4, "488941", 1) == restore + 16
    first = operand(0x5A6F8F4, "0f104424", 1)
    second = operand(0x5A6F8F9, "660f104c24", 1)
    assert restore == first + 7 and second == first + 15
    temporary = operand(0x5A6F8FF, "0f298424")
    assert operand(0x5A6F907, "660f118c24") == temporary + 15
    expect(0x5A6F910, "31ed")
    expect(0x5A6F912, "31c9")
    assert edge(0x5A6F914, "eb", 1) == 0x5A6F949
    assert operand(0x5A6F950, "0f108424") == temporary + 15
    assert operand(0x5A6F960, "0f1141", 1) == 15
    assert operand(0x5A6F964, "660f288424") == temporary
    expect(0x5A6F96D, "660f1101")

    record = operand(0x5A6F989, "488d9424")
    tag = operand(0x5A6F949, "888c24")
    payload = operand(0x5A6F958, "488d8c24")
    extra = operand(0x5A6F971, "48898424")
    assert tag == record + 0x58 and payload == tag + 1
    triple = payload + (restore - first)
    assert triple == record + 0x60 and extra == triple + 24
    assert record_height == record + 0x80
    assert edge(0x5A6F991, "e8") == 0x595A6B0

    sink_save = operand(0x595A6CD, "48899424")
    assert operand(0x595AB3B, "488b9424") == sink_save
    assert edge(0x595A700, "0f86") == 0x595AB27
    assert edge(0x595AB43, "e8") == 0x50E2F80
    expect(0x50E2F8B, "4889d3")
    expect(0x50E2FCB, "4889df")
    assert edge(0x50E2FCE, "e8") == 0x4D6D740
    expect(0x4D6D749, "4889fb")
    assert operand(0x4D6D7A0, "488d4b", 1) == tag - record
    assert edge(0x4D6D7B5, "e8") == 0x506E230
    expect(0x506E2D6, "803b02")
    assert edge(0x506E2D9, "75", 1) == 0x506E307
    expect(0x506E307, "4889df")
    assert edge(0x506E30D, "e8") == 0x4D6D170
    expect(0x4D6D17F, "803f01")
    assert edge(0x4D6D182, "0f85") == 0x4D6D25B
    assert at(".rodata", edge(0x4D6D299, "488d35"), 4) == b"Full"
    assert tag + operand(0x4D6D2C9, "4983c6", 1) == triple
    expect(0x4D6D2EF, "4c89f6")
    assert edge(0x4D6D2F2, "e8") == 0x502D0D0
    assert operand(0x502D0E1, "4c8b76", 1) == 8
    assert operand(0x502D0E5, "4c8b66", 1) == 16
    assert record + operand(0x4D6D7C6, "4883eb", 1) * -1 == record_height
    assert at(".rodata", edge(0x4D6D7CA, "488d35"), 6) == b"height"
    expect(0x4D6D7DB, "4889d9")
    assert edge(0x4D6D7DE, "e8") == 0x5077210

    # Check the two overlapping copies with distinct bytes and an unrelated prefix.
    sample = bytes(range(1, 25))
    scratch = bytes(7) + sample
    staged = bytearray(31)
    staged[:16] = scratch[:16]
    staged[15:31] = scratch[15:31]
    outgoing = bytearray(0x88)
    outgoing[0x68:0x78] = staged[15:31]
    outgoing[0x59:0x69] = staged[:16]
    outgoing[0x78:0x80] = sample[16:24]
    outgoing[0x80:0x88] = b"H" * 8
    assert outgoing[0x58] == 0 and outgoing[0x60:0x78] == sample
    assert outgoing[0x78:0x80] == sample[16:24] != outgoing[0x80:0x88]

    print(f"PASS: authenticated {DIGEST}, {len(rows)} spans in {len(bounds)} indexed FDEs")
    print("PASS: Block result height is staged for both replica sink argument and JSON field")
    print("PASS: selected tag-0 lane restores all three original response words into Full writer")
    print("PASS: synthetic distinct-byte overlap control retains count and distinct height")


if __name__ == "__main__":
    main()
