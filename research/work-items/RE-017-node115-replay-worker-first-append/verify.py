"""Verify worker state-zero Block admission and selected vector ownership."""
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
    indexed = {(row["start"], row["fde"]) for row in header}
    entries = {0x5A89540, 0x5A897E0}
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

    def operand(address, prefix, width=1):
        raw = rows[address]
        assert raw[:-width] == bytes.fromhex(prefix), hex(address)
        return int.from_bytes(raw[-width:], "little", signed=True)

    def edge(address, prefix, width=4):
        return address + len(rows[address]) + operand(address, prefix, width)

    def expect(address, raw):
        assert rows[address] == bytes.fromhex(raw), hex(address)

    rela = sections_by_name[".rela.dyn"]
    relative = {
        slot: addend for slot, kind, addend in struct.iter_unpack(
            "<QQq", at(".rela.dyn", rela["address"], rela["size"])
        ) if kind == 8
    }

    expect(0x5A897F4, "4889f3")
    assert operand(0x5A89804, "0fb686", 4) == 0x220
    table = edge(0x5A8980B, "488d0d")
    assert table == 0x939BC8
    assert table + int.from_bytes(at(".rodata", table, 4), "little", signed=True) == 0x5A8981B
    expect(0x5A8981B, "4c8b2b")
    assert operand(0x5A8981E, "488b53") == 8
    assert operand(0x5A89822, "488b4b") == 0x10
    assert operand(0x5A89826, "488d7c24") == 0x10
    expect(0x5A8982B, "4c89ee")
    assert relative[edge(0x5A8982E, "ff15")] == 0x5A89540
    expect(0x5A8954E, "4989d7")
    expect(0x5A89551, "4889fb")
    assert operand(0x5A89563, "48894c24") == 0x30
    assert operand(0x5A8956C, "48894c24") == 8

    # Source vector pointer, count, stride and empty-baseline input.
    assert operand(0x5A89593, "488b46") == 8
    assert operand(0x5A89597, "4c8b76") == 0x10
    expect(0x5A8959B, "4d89f5")
    shift = operand(0x5A8959E, "49c1e5")
    assert shift == 4
    assert operand(0x5A895A2, "488b8e", 4) == 0x110
    expect(0x5A895E3, "4839cd")
    assert edge(0x5A895E6, "75", 1) == 0x5A89646
    marker = operand(0x5A89554, "49bc", 8)
    expect(0x5A895E8, "49ffcc")
    assert operand(0x5A895EB, "4d39a7", 4) == 0x188
    assert edge(0x5A895F2, "0f85") == 0x5A89685
    assert operand(0x5A895F8, "4983fe") == 99
    assert edge(0x5A895FC, "0f86") == 0x5A8970A

    # With spare capacity, the kept vector is advanced only after both stores.
    assert operand(0x5A8970F, "488b4c24") == 8
    expect(0x5A89719, "4c3b36")
    assert edge(0x5A8971C, "75", 1) == 0x5A89731
    expect(0x5A89731, "4e893c28")
    assert operand(0x5A89735, "488b4c24") == 8
    assert operand(0x5A8973A, "4a894c28") == 8
    expect(0x5A8973F, "49ffc6")
    assert operand(0x5A89742, "4c8976") == 0x10
    assert operand(0x5A89746, "4c8963") == 8

    # Moved vector storage retains its full descriptor before the source reset.
    assert operand(0x5A89685, "4d8bb7", 4) == 0x340
    assert operand(0x5A8968C, "488b46") == 0x10
    assert operand(0x5A89690, "48894424") == operand(0x5A896C3, "4c8b6424") == 0x20
    expect(0x5A89695, "0f1006")
    assert operand(0x5A89698, "0f294424") == 0x10
    expect(0x5A8969D, "48c70600000000")
    expect(0x5A896A4, "48c7460808000000")
    expect(0x5A896AC, "48c7461000000000")
    assert operand(0x5A896B9, "4c8b6c24") == 8
    assert operand(0x5A896C8, "4c3b6424") == 0x10
    assert edge(0x5A896CD, "75", 1) == 0x5A896DA
    assert operand(0x5A896DA, "488b4424") == 0x18
    expect(0x5A896DF, "4c89e1")
    assert operand(0x5A896E2, "48c1e1") == shift
    expect(0x5A896E6, "4c893c08")
    assert operand(0x5A896EA, "4c896c08") == 8
    expect(0x5A896EF, "49ffc4")
    assert operand(0x5A896F7, "4c8963") == 0x18
    assert operand(0x5A896FB, "0f284424") == 0x10
    assert operand(0x5A89700, "0f1143") == 8
    assert operand(0x5A89704, "4c8973") == 0x20
    assert edge(0x5A89708, "eb", 1) == 0x5A8974A

    tag = operand(0x5A8974A, "c603")
    assert tag == operand(0x5A89834, "807c2410") == 0x44
    first_result_word = operand(0x5A8983B, "0f104424") - 0x10
    assert first_result_word == 8
    assert operand(0x5A89840, "0f104c24") == 0x28
    assert operand(0x5A89849, "0f1143") == operand(0x5A898D9, "0f1043") == 0x40
    assert operand(0x5A89845, "0f114b") == operand(0x5A898DD, "0f104b") == 0x50
    assert edge(0x5A89851, "e9") == 0x5A898D9
    assert operand(0x5A898E1, "0f1143") == operand(0x5A898EC, "48396b") == 0x18
    assert operand(0x5A897FA, "48bd", 8) == marker - 1
    assert edge(0x5A898F0, "0f84") == 0x5A89A58
    expect(0x5A89A58, "458837")
    assert operand(0x5A8990F, "0f1183", 4) == 0x80
    assert operand(0x5A89908, "0f118b", 4) == 0x90

    for address in (0x5A895EB, 0x5A896EA, 0x5A89742, 0x5A898F0):
        raw = rows[address]
        assert not matches(address, raw[:-1] + bytes([raw[-1] ^ 1]))
    check_vector_projection(shift, marker - 1)

    print(f"PASS: SHA-256 {DIGEST}; {len(rows)} ranges in {len(bounds)} indexed FDEs")
    print("PASS: worker state 0 forwards the actual Block and attachment owners through the pinned helper slot")
    print("PASS: matching Block appends in order; both source-kept and moved/reset vector cases match")
    print("PASS: 0x44 with sentinel completes immediately; moved descriptor enters prior wait setup")
    print("PASS: synthetic preserved prefix, one-row advancement and altered witness controls")


def check_vector_projection(shift, sentinel):
    row_size = 1 << shift
    for keep in (True, False):
        storage = bytearray(3 * row_size)
        struct.pack_into("<QQ", storage, 0, 10, 20)
        src = [3, 0x500, 1]
        result = [sentinel]
        vector = src
        if not keep:
            vector = src[:]
            src[:] = [0, 8, 0]
            result = vector
        offset = vector[2] << shift
        struct.pack_into("<QQ", storage, offset, 30, 40)
        vector[2] += 1
        assert tuple(struct.unpack_from("<4Q", storage)) == (10, 20, 30, 40)
        assert vector[2] == 2
        assert src[2] == (2 if keep else 0)
        assert result[0] == (sentinel if keep else 3)
        assert struct.unpack_from("<QQ", storage, 0) != (30, 40)
        assert struct.unpack_from("<QQ", storage, offset) != (40, 30)


if __name__ == "__main__":
    main()
