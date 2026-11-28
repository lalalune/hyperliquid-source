"""Check selected replay Block round projections using the pinned #115 ELF."""
import hashlib
from pathlib import Path
import struct
import sys

PACKET = Path(__file__).resolve().parent
sys.path.insert(0, str(Path.cwd() / "tools"))

from elf_index import unwind_index
from fde_extents import eh_frame_records

TARGET = Path("artifacts/node/115/hl-node")
SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
MAX = (1 << 64) - 1
MARKER = (1 << 63) + 1


def main():
    assert __debug__, "run without -O"
    target = TARGET.read_bytes()
    assert hashlib.sha256(target).hexdigest() == SHA256
    sections, header = unwind_index(target)
    sections_by_name = {row["name"]: row for row in sections}
    _, fdes = eh_frame_records(target, sections)
    indexed = {(row["start"], row["fde"]) for row in header}
    begin, end = 0x5A82670, 0x5A89535
    assert any(
        row["start"] == begin and row["end"] == end
        and (begin, row["fde"]) in indexed for row in fdes
    )

    def at(section_name, address, size):
        section = sections_by_name[section_name]
        displacement = address - section["address"]
        assert 0 <= displacement <= displacement + size <= section["size"]
        offset = section["offset"] + displacement
        return target[offset:offset + size]

    def exact_text(address, raw):
        return at(".text", address, len(raw)) == raw

    rows = {}
    for line in (PACKET / "windows.txt").read_text().splitlines():
        address, encoding, _ = line.split("\t", 2)
        address, raw = int(address, 16), bytes.fromhex(encoding)
        assert address not in rows and begin <= address < address + len(raw) <= end
        assert exact_text(address, raw)
        rows[address] = raw

    section = sections_by_name[".rela.dyn"]
    relocations = {
        slot: (kind, addend) for slot, kind, addend in struct.iter_unpack(
            "<QQq", at(".rela.dyn", section["address"], section["size"])
        )
    }

    def operand(address, opcode, size=1):
        raw = rows[address]
        prefix = bytes.fromhex(opcode)
        assert raw[:-size] == prefix, hex(address)
        return int.from_bytes(raw[-size:], "little", signed=True)

    def edge(address, opcode, size=4):
        return address + len(rows[address]) + operand(address, opcode, size)

    assert operand(0x5A87523, "48899b", 4) == operand(0x5A87557, "488b83", 4) == 0x208
    assert operand(0x5A8756C, "488bb3", 4) == 0x1D8
    assert rows[0x5A875AD] == bytes.fromhex("48ffc7")
    assert operand(0x5A875A3, "48bf", 8) % (1 << 64) + 1 == MARKER
    assert operand(0x5A875B0, "48397e") == 0x28
    assert operand(0x5A875DF, "48397e") == 0x28
    assert operand(0x5A875F6, "4839be", 4) == 0xB8

    round_offsets = (
        operand(0x5A8759F, "4c8d46") + operand(0x5A875BF, "4d8b41"),
        operand(0x5A875B4, "4c8d8e", 4) + operand(0x5A875BF, "4d8b41"),
    )
    assert round_offsets == (0x60, 0xB0)
    assert rows[0x5A875BB] == bytes.fromhex("4d0f44c8")
    assert rows[0x5A875CD] == bytes.fromhex("4d0f45c8")
    assert rows[0x5A875C3] == bytes.fromhex("49ffc0")
    assert operand(0x5A875C6, "49c7c1", 4) == -1

    parent_offsets = tuple(
        operand(address, opcode, size) + operand(0x5A87601, "4d8b40")
        for address, opcode, size in (
            (0x5A875E5, "4c8d46", 1),
            (0x5A875EB, "4c8d4e", 1),
            (0x5A875EF, "4c8d86", 4),
        )
    )
    assert parent_offsets == (0x60, 0x58, 0xE8)
    assert edge(0x5A875E3, "75", 1) == 0x5A875EB
    assert edge(0x5A875E9, "eb", 1) == 0x5A87601
    assert rows[0x5A875FD] == bytes.fromhex("4d0f44c1")

    assert operand(0x5A87613, "4c8b50") == 0x10
    assert operand(0x5A87617, "4c8b88", 4) == 0x110
    assert operand(0x5A87623, "488b40") == 8
    assert operand(0x5A87627, "49c1e2") == 4
    assert rows[0x5A8762B] == bytes.fromhex("4c01d0")
    assert operand(0x5A8762E, "4883c0") == -16
    assert rows[0x5A87637] == bytes.fromhex("488b00")
    assert edge(0x5A87621, "74", 1) == edge(0x5A87635, "74", 1) == 0x5A8765F
    assert operand(0x5A8763A, "4c8d48") + operand(0x5A8764D, "488b40") == round_offsets[0]
    assert operand(0x5A87642, "488d80", 4) + operand(0x5A8764D, "488b40") == round_offsets[1]
    assert operand(0x5A8763E, "483978") == 0x28
    assert rows[0x5A87649] == bytes.fromhex("490f44c1")
    assert rows[0x5A87651] == bytes.fromhex("48ffc0")
    assert operand(0x5A87654, "49c7c1", 4) == -1
    assert rows[0x5A8765B] == bytes.fromhex("4c0f45c8")

    assert operand(0x5A87598, "4c8dbb", 4) == operand(0x5A875D1, "4c898b", 4) == 0x1F0
    assert operand(0x5A875D8, "4c8db3", 4) == operand(0x5A87605, "4c8983", 4) == 0x1F8
    assert operand(0x5A8760C, "4c8dab", 4) == 0x200
    assert rows[0x5A8765F] == bytes.fromhex("4d894d00")
    assert rows[0x5A87663] == bytes.fromhex("4d39c8")
    assert edge(0x5A87666, "0f83") == 0x5A87A52
    assert relocations[edge(0x5A87A64, "ff15")] == (8, 0x4FAD710)
    assert relocations[edge(0x5A87746, "ff15")] == (8, 0x150B310)

    for address, opcode, value in (
        (0x5A876A8, "4c897c24", 0x40),
        (0x5A876AD, "4c89b424", 0x260),
        (0x5A876B5, "4c89ac24", 0x3190),
        (0x5A876DC, "488d4424", 0x40),
        (0x5A876F8, "488d8c24", 0x260),
        (0x5A87710, "488d8c24", 0x3190),
        (0x5A876E1, "48898424", 0x1430),
        (0x5A87700, "48898c24", 0x1440),
        (0x5A87718, "48898c24", 0x1450),
    ):
        size = 1 if len(rows[address]) == len(bytes.fromhex(opcode)) + 1 else 4
        assert operand(address, opcode, size) == value
    labels = b"\xc0\x0c @@ [round: \xc0\x13] @ [parent_round: \xc0\x16] @ [last_recv_round: \xc0\x01]"
    assert at(".rodata", edge(0x5A87728, "488d35"), len(labels)) == labels
    message = b"received old client block, is peer behind?"
    assert at(".rodata", edge(0x5A8768D, "488d05"), len(message)) == message

    branch = 0x5A87666
    changed = bytearray(rows[branch])
    changed[1] ^= 1
    assert not exact_text(branch, changed)
    check_projection(round_offsets, parent_offsets)

    print(f"PASS: SHA-256 {SHA256}; {len(rows)} ranges in indexed FDE {begin:#x}..{end:#x}")
    print(f"PASS: round offsets {round_offsets}; parent offsets {parent_offsets}")
    print("PASS: F+0x110 fallback, 16-byte tail projection, unsigned parent comparison and diagnostic labels")
    print("PASS: synthetic marker arms, empty/tail/equality/lower/unsigned/saturation and corrupted witness controls")


def check_projection(round_offsets, parent_offsets):
    """Test projected addresses and preserve the distinct unsigned decision."""
    values = {0x60: 17, 0xB0: 55, 0x58: 33, 0xE8: 72}
    for marker_at_28, marker_at_b8, expected in (
        (True, False, (18, 17)),
        (True, True, (18, 17)),
        (False, True, (56, 33)),
        (False, False, (56, 72)),
    ):
        round_offset = round_offsets[0 if marker_at_28 else 1]
        parent_index = 0 if marker_at_28 else 1 if marker_at_b8 else 2
        assert (
            min(values[round_offset] + 1, MAX),
            values[parent_offsets[parent_index]],
        ) == expected

    # First owners carry deliberately different round words.
    for fallback, tail_words, parent, expected_baseline, expected_branch in (
        (73, (), 72, 73, False),
        (73, (), 73, 73, True),
        (73, (999, 16), 17, 17, True),
        (73, (2, 16), 16, 17, False),
        (73, (1 << 63,), (1 << 63) - 1, (1 << 63) + 1, False),
        (73, (MAX,), MAX, MAX, True),
    ):
        baseline = min(tail_words[-1] + 1, MAX) if tail_words else fallback
        assert baseline == expected_baseline
        assert (parent >= baseline) == expected_branch


if __name__ == "__main__":
    main()
