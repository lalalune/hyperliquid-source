"""Check replay-parent bootstrap request field provenance on node #115."""
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
    start, end = 0x5A82670, 0x5A89535
    indexed = {(row["start"], row["fde"]) for row in header}
    assert any(
        row["start"] == start and row["end"] == end
        and (start, row["fde"]) in indexed for row in fdes
    )
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
        assert start <= address < address + len(raw) <= end
        rows[address] = raw

    def operand(address, opcode, width=4):
        raw = rows[address]
        assert raw[:-width] == bytes.fromhex(opcode), hex(address)
        return int.from_bytes(raw[-width:], "little", signed=True)

    def edge(address, opcode, width=4):
        return address + len(rows[address]) + operand(address, opcode, width)

    def expect(address, encoding):
        assert rows[address] == bytes.fromhex(encoding), hex(address)

    assert operand(0x5A875D8, "4c8db3") == operand(0x5A88188, "488b8b") == 0x1F8
    assert operand(0x5A8760C, "4c8dab") == operand(0x5A88165, "488b8b") == 0x200
    expect(0x5A87FBD, "498b06")
    expect(0x5A87FC0, "493b4500")
    assert edge(0x5A87FC4, "0f86") == 0x5A84333
    msg = b"missing client blocks before received client block, bootstrapping from peer"
    assert at(".rodata", edge(0x5A88065, "488d05"), len(msg)) == msg
    expect(0x5A8816C, "48ffc1")
    assert operand(0x5A8816F, "48c7c0") == -1
    expect(0x5A88176, "480f45c1")
    assert operand(0x5A8818F, "488983") == 0x258
    assert operand(0x5A88196, "48898b") == 0x260
    assert operand(0x5A881E0, "488983") == operand(0x5A88206, "4c8db3") == 0x278
    assert operand(0x5A881E7, "48898b") == operand(0x5A8820D, "4c8dbb") == 0x280

    expect(0x5A88391, "498b07")
    expect(0x5A88394, "498b0e")
    expect(0x5A883BB, "4839c1")
    assert edge(0x5A883BE, "0f86") == 0x5A83026
    max_inclusive_offset = -operand(0x5A8302E, "4883ea", 1)
    assert max_inclusive_offset == operand(0x5A83037, "4883c6", 1) == 99
    expect(0x5A83049, "480f42d0")

    descriptor = operand(0x5A8305D, "488db3")
    assert descriptor == operand(0x5A83073, "4c89b3") == 0x2D0
    name_size = operand(0x5A8307A, "48c783d8020000")
    assert name_size == 20
    assert at(".rodata", edge(0x5A8306C, "4c8d35"), name_size) == b"node_bootstrap_query"
    first = operand(0x5A83085, "48898b")
    assert first - descriptor == 16
    assert operand(0x5A8308C, "488993") == first + 8

    # Follow the entire first 16-byte range through the staged copies.
    assert operand(0x5A830DB, "488db3") == first
    stage_one = operand(0x5A830F0, "488dbb")
    assert (stage_one, first) == (0x1100, 0x2E0)
    assert operand(0x5A83141, "488db3") == stage_one
    stage_two = operand(0x5A83148, "488dbc24")
    assert operand(0x5A8328E, "488db424") == stage_two == 0x3190
    stage_three = operand(0x5A83286, "488dbc24")
    assert stage_three == 0x1490
    copy_slot = edge(0x5A830FC, "ff15")
    assert copy_slot == edge(0x5A83155, "ff15") == edge(0x5A83296, "4c8b3d") == 0x64DF508
    size = operand(0x5A830F7, "ba")
    assert size == operand(0x5A83150, "ba") == operand(0x5A8329D, "ba") == 0xDE8
    expect(0x5A832A2, "41ffd7")

    fourth_source = operand(0x5A83321, "488db424")
    fourth_destination = operand(0x5A83319, "4c8db424")
    assert (fourth_source, fourth_destination) == (0x1420, 0x5C0)
    copy_prefix = stage_three - fourth_source
    assert copy_prefix == 0x70
    assert operand(0x5A83329, "ba") == operand(0x5A8333B, "ba") == size + copy_prefix
    expect(0x5A8332E, "4c89f7")
    expect(0x5A83331, "41ffd7")
    expect(0x5A83340, "4c89f6")
    expect(0x5A83343, "41ffd7")
    final_destination = operand(0x5A83334, "488dbb")
    final_first = final_destination + copy_prefix
    assert final_first == operand(0x5A833C2, "488b8b") == 0x1F68
    assert operand(0x5A833C9, "488b93") == final_first + 8
    assert operand(0x5A833E3, "48898b") == 0x1F80
    assert operand(0x5A833EA, "488993") == 0x1F88

    assert operand(0x5A83398, "0fb683") == 0x2D48
    table = edge(0x5A8339F, "488d0d")
    assert table == 0x939BA8
    assert table + int.from_bytes(at(".rodata", table, 4), "little", signed=True) == 0x5A833AF

    for address in (0x5A881E0, 0x5A8308C, 0x5A833C9):
        raw = rows[address]
        assert not matches(address, raw[:-1] + bytes([raw[-1] ^ 1]))
    check_round_words(copy_prefix, size, max_inclusive_offset)

    print(f"PASS: SHA-256 {DIGEST}; {len(rows)} ranges in indexed FDE {start:#x}..{end:#x}")
    print("PASS: positive parent gap binds baseline+1 and raw parent to established range builder")
    print("PASS: node_bootstrap_query descriptor carries both bounds through copied frame and selected state-0 read")
    print("PASS: synthetic short, capped and high-round bounds; reversed, truncated and altered byte controls")


def check_round_words(copy_prefix, size, max_inclusive_offset):
    max_word = (1 << 64) - 1
    for baseline, parent, expected in (
        (120, 123, (121, 123)),
        (120, 260, (121, 220)),
        (max_word - 3, max_word, (max_word - 2, max_word)),
    ):
        assert parent > baseline
        lower = min(baseline + 1, max_word)
        upper = min(parent, min(lower + max_inclusive_offset, max_word))
        words = struct.pack("<QQ", lower, upper)
        child = words + bytes(size - len(words))
        nested_frame = bytes(copy_prefix) + child
        copied_frame = bytearray(nested_frame)
        assert struct.unpack_from("<QQ", copied_frame, copy_prefix) == expected
        assert struct.unpack_from("<QQ", copied_frame, copy_prefix) != tuple(reversed(expected))
        truncated = copied_frame[:copy_prefix + 8]
        try:
            struct.unpack_from("<QQ", truncated, copy_prefix)
        except struct.error:
            pass
        else:
            raise AssertionError("one-word frame accepted")


if __name__ == "__main__":
    main()
