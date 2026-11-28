"""Validate startup-to-replay baseline initialization against #115."""
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
    entry_points = {0x2AF45F0, 0x2CC1120, 0x5A81ED0, 0x5A82670}
    indexed = {(row["start"], row["fde"]) for row in header}
    bounds = {
        row["start"]: row["end"] for row in fdes
        if row["start"] in entry_points and (row["start"], row["fde"]) in indexed
    }
    assert set(bounds) == entry_points
    sections_by_name = {section["name"]: section for section in sections}

    def at(name, address, length):
        section = sections_by_name[name]
        delta = address - section["address"]
        assert 0 <= delta <= delta + length <= section["size"]
        start = section["offset"] + delta
        return data[start:start + length]

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

    def immediate(address, prefix, stack_width, expected_stack):
        raw = rows[address]
        assert len(raw) == len(bytes.fromhex(prefix)) + stack_width + 4
        assert raw.startswith(bytes.fromhex(prefix))
        assert int.from_bytes(raw[-4-stack_width:-4], "little") == expected_stack
        return int.from_bytes(raw[-4:], "little")

    rela = sections_by_name[".rela.dyn"]
    targets = {
        slot: addend for slot, kind, addend in struct.iter_unpack(
            "<QQq", at(".rela.dyn", rela["address"], rela["size"])
        ) if kind == 8
    }

    compare_tag = rows[0x2AF4D43]
    assert compare_tag == bytes.fromhex("83bc244006000002")
    assert edge(0x2AF4D4B, "0f85") == 0x2AF5ECE
    assert operand(0x2AF4D51, "4c8bbc24") - 0x640 == 0x30
    assert operand(0x2AF523A, "4c897c24", 1) == operand(0x2AF5797, "488b4424", 1) == 0x10
    joined_field = operand(0x2AF57A5, "4c8b70", 1)
    joined_input = operand(0x2AF5AEE, "488dbc24")
    joined_baseline = operand(0x2AF5A45, "4c89b424") - joined_input
    joined_buffer = tuple(
        immediate(address, "48c74424", 1, offset)
        for address, offset in ((0x2AF57DA, 0x48), (0x2AF57E3, 0x50), (0x2AF57EC, 0x58))
    )
    assert operand(0x2AF5A7C, "f30f6f4424", 1) == 0x48
    assert operand(0x2AF5A82, "660f7f8424") == joined_input
    assert operand(0x2AF5A8B, "488b4424", 1) == 0x58
    assert operand(0x2AF5A90, "48898424") - joined_input == 0x10

    assert targets[edge(0x2CC19EA, "ff15")] == 0x3C13610
    assert operand(0x2CC19F4, "498986") == operand(0x2CC2BBD, "498b9f") == 0xE0
    assert operand(0x2CC12A0, "49895f", 1) == operand(0x2CC1651, "4c8b78", 1) == 0x20
    local_field = operand(0x2CC24BC, "4d8b67", 1)
    local_input = operand(0x2CC280A, "488dbc24")
    local_baseline = operand(0x2CC2763, "4c89a424") - local_input
    local_buffer = tuple(
        immediate(address, "48c78424", 4, offset)
        for address, offset in ((0x2CC24F0, 0x1C20), (0x2CC24FC, 0x1C28), (0x2CC2508, 0x1C30))
    )
    assert operand(0x2CC279B, "0f108424") == 0x1C20
    assert operand(0x2CC27A3, "0f298424") == local_input
    assert operand(0x2CC27AB, "488b8424") == 0x1C30
    assert operand(0x2CC27B3, "48898424") - local_input == 0x10

    assert joined_field == local_field == 0x30
    assert joined_buffer == local_buffer == (0, 8, 0)
    assert edge(0x2AF5B03, "ff15") == edge(0x2CC281F, "ff15") == 0x64E74D8
    assert targets[0x64E74D8] == 0x5A81ED0

    assert rows[0x5A81F1F] == bytes.fromhex("4889fb")
    assert rows[0x5A81FBD] == bytes.fromhex("4889de")
    assert rows[0x5A8200C] == bytes.fromhex("4889df")
    assert rows[0x5A82024] == bytes.fromhex("4889da")
    assert operand(0x5A81FB3, "488d7c24", 1) == operand(0x5A82002, "488d7424", 1) == 0x10
    prefix_size = operand(0x5A81FB8, "ba")
    assert prefix_size == 0x118
    assert operand(0x5A82007, "ba") == 0x2D80
    assert edge(0x5A81FC0, "ff15") == edge(0x5A8200F, "ff15") == 0x64DF508
    assert targets[edge(0x5A82036, "ff25")] == 0x15D6EF0
    assert targets[edge(0x5A82015, "488d0d") + 0x18] == 0x5A82670

    count = operand(0x5A87613, "4c8b50", 1)
    baseline = operand(0x5A87617, "4c8b88")
    assert count == 0x10
    assert joined_baseline == local_baseline == baseline == 0x110
    assert baseline + 8 == prefix_size
    assert rows[0x5A8761E] == bytes.fromhex("4d85d2")
    assert edge(0x5A87621, "74", 1) == 0x5A8765F
    assert rows[0x5A8765F] == bytes.fromhex("4d894d00")

    for address in (0x2AF57A5, 0x2CC2763, 0x5A87621):
        stored = rows[address]
        assert not matches(address, stored[:-1] + bytes([stored[-1] ^ 1]))
    for field, buffer in ((joined_field, joined_buffer), (local_field, local_buffer)):
        state = bytearray(0x38)
        struct.pack_into("<QQQQ", state, 0x18, 1, 2, 1000, 4200)
        frame = bytearray(prefix_size)
        struct.pack_into("<QQQ", frame, 0, *buffer)
        frame[baseline:baseline + 8] = state[field:field + 8]
        assert struct.unpack_from("<Q", frame, count)[0] == 0
        assert struct.unpack_from("<Q", frame, baseline)[0] == 4200
        assert frame[baseline:baseline + 8] != state[0x28:0x30]

    print(f"PASS: SHA-256 {DIGEST}; {len(rows)} spans in {len(bounds)} indexed FDEs")
    print("PASS: both routes initialize receive-buffer prefix (0, 8, 0) and copy state+0x30 to input+0x110")
    print("PASS: installed poll preloads the preserved baseline and skips the tail on zero count")
    print("PASS: distinct checkpoint words and three changed-witness controls")


if __name__ == "__main__":
    main()
