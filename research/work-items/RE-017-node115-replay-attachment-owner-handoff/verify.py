"""Pin the accepted replay Block attachment pair through its worker handoff."""
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
    entries = {0x4FAD710, 0x5A82670, 0x5A897E0}
    bounds = {
        row["start"]: row["end"] for row in fdes
        if row["start"] in entries and (row["start"], row["fde"]) in indexed
    }
    assert set(bounds) == entries
    sections_by_name = {section["name"]: section for section in sections}

    def at(name, address, size):
        section = sections_by_name[name]
        offset = address - section["address"]
        assert 0 <= offset <= offset + size <= section["size"]
        offset += section["offset"]
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

    def expect(address, encoding):
        assert rows[address] == bytes.fromhex(encoding), hex(address)

    rela = sections_by_name[".rela.dyn"]
    relative = {
        slot: addend for slot, kind, addend in struct.iter_unpack(
            "<QQq", at(".rela.dyn", rela["address"], rela["size"])
        ) if kind == 8
    }

    assert operand(0x5A87523, "48899b", 4) == operand(0x5A87557, "488b83", 4) == 0x208
    assert operand(0x5A8755E, "488983", 4) == 0x1E8
    assert operand(0x5A8756C, "488bb3", 4) == 0x1D8
    assert operand(0x5A87573, "488b93", 4) == 0x1E0
    assert operand(0x5A8757A, "4889b3", 4) == 0x1B8
    assert operand(0x5A87581, "488993", 4) == 0x1C0
    assert edge(0x5A87666, "0f83") == 0x5A87A52
    output = operand(0x5A87A59, "4c8da424", 4)
    expect(0x5A87A61, "4c89e7")
    assert relative[edge(0x5A87A64, "ff15")] == 0x4FAD710

    assert operand(0x4FAD721, "48897424") == operand(0x4FADA64, "4c8b7424") == 0x28
    expect(0x4FAD726, "4885d2")
    assert edge(0x4FAD729, "74", 1) == 0x4FAD74B
    assert operand(0x4FAD72B, "488977") == operand(0x4FADAD7, "4c8977") == 8
    assert operand(0x4FAD72F, "488957") == operand(0x4FADADB, "488947") == 0x10
    tag = operand(0x4FAD733, "c607")
    assert tag == rows[0x5A87A6A][-1] == 0x2E
    assert rows[0x5A87A6A][:-1] == bytes.fromhex("80bc24") + struct.pack("<I", output)

    assert operand(0x4FAD74B, "488b5e") == 0x20
    assert edge(0x4FAD75C, "76", 1) == 0x4FAD76E
    assert operand(0x4FAD771, "4889bc24", 4) == operand(0x4FADACF, "488bbc24", 4) == 0x80
    expect(0x4FAD779, "4885db")
    assert edge(0x4FAD77C, "74", 1) == 0x4FAD7AB
    dangling = operand(0x4FAD7AB, "41be", 4)
    assert dangling == 8
    expect(0x4FAD7B1, "4531ed")
    assert operand(0x4FAD7B4, "48895c24") == operand(0x4FADA7B, "488b4424") == 8
    assert operand(0x4FAD7B9, "4c897424") == operand(0x4FADA85, "488b4424") == 0x10
    expect(0x4FAD7BE, "48c744241800000000")
    assert operand(0x4FADA71, "488b4424") == 0x18
    assert edge(0x4FAD7CA, "0f84") == 0x4FADA64

    assert operand(0x4FADA80, "48894424") == operand(0x4FADAC3, "0f104c24") == 0x40
    assert operand(0x4FADA8A, "48894424") == 0x48
    assert operand(0x4FADA76, "48894424") == operand(0x4FADAB5, "488b4c24") == 0x50
    expect(0x4FADA8F, "48c744243001000000")
    expect(0x4FADA98, "48c744243801000000")
    assert operand(0x4FADABE, "0f104424") == 0x30
    assert operand(0x4FADAA1, "bf", 4) == 0x28
    assert relative[edge(0x4FADAA6, "ff15")] == 0x6355830
    expect(0x4FADAAC, "4885c0")
    assert operand(0x4FADABA, "488948") == 0x20
    assert operand(0x4FADAC8, "0f1148") == 0x10
    expect(0x4FADACC, "0f1100")
    assert edge(0x4FADADF, "e9") == 0x4FAD733

    assert operand(0x5A87A7B, "f30f6f8424", 4) - output == 8
    assert operand(0x5A87A84, "f30f7f83", 4) == 0x1C8
    assert edge(0x5A87A8C, "e9") == 0x5A87FBD
    expect(0x5A87FBD, "498b06")
    expect(0x5A87FC0, "493b4500")
    assert edge(0x5A87FC4, "0f86") == 0x5A84333
    assert operand(0x5A84333, "488b83", 4) == 0x1C8
    assert operand(0x5A8434A, "488b8b", 4) == 0x1D0
    assert operand(0x5A84351, "488b93", 4) == 0x1E8
    assert operand(0x5A84358, "488993", 4) == operand(0x5A84374, "4c8da3", 4) == 0x230
    assert operand(0x5A8435F, "488983", 4) == 0x238
    assert operand(0x5A84366, "48898b", 4) == 0x240
    expect(0x5A84383, "4c89e6")
    assert edge(0x5A8438A, "e8") == 0x5A897E0

    for address in (0x4FAD729, 0x4FADADB, 0x5A84366):
        raw = rows[address]
        assert not matches(address, raw[:-1] + bytes([raw[-1] ^ 1]))
    for owner_in, owner_out in ((0x2000, 0x2000), (0, 0x3000)):
        block, future = 0x1000, 0x4000
        result = bytearray(24)
        result[0] = tag
        owner = (owner_in, None) if owner_in else (owner_out, (1, 1, 0, dangling, 0))
        assert owner[0] == owner_out and owner[0] != block
        if owner_in == 0:
            assert struct.pack("<5Q", *owner[1]) == (struct.pack("<2Q", 1, 1) + struct.pack("<3Q", 0, 8, 0))
        struct.pack_into("<QQ", result, 8, block, owner[0])
        pair = struct.unpack_from("<QQ", result, 8)
        worker = struct.pack("<QQQ", future, *pair)
        assert struct.unpack("<QQQ", worker) == (future, block, owner_out)
        assert struct.unpack("<QQQ", worker) != (future, owner_out, block)

    print(f"PASS: SHA-256 {DIGEST}; {len(rows)} spans in indexed FDEs and worker entry")
    print("PASS: present B survives unchanged; absent B and zero count construct owner (1,1,0,8,0)")
    print("PASS: tag 0x2e pair survives the equality continuation into worker input")
    print("PASS: changed instruction and swapped owner controls")


if __name__ == "__main__":
    main()
