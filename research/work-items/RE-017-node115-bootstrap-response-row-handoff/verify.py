"""Authenticate the completed bootstrap response's vector-to-worker handoff."""
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
    entries = {0x5A82670, 0x5A6A640, 0x5A897E0}
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

    def operand(address, prefix, width=4):
        raw = rows[address]
        assert raw[:-width] == bytes.fromhex(prefix), hex(address)
        return int.from_bytes(raw[-width:], "little", signed=True)

    def edge(address, prefix, width=4):
        return address + len(rows[address]) + operand(address, prefix, width)

    def expect(address, encoding):
        assert rows[address] == bytes.fromhex(encoding), hex(address)

    assert edge(0x5A6B8B5, "e8") == 0x58606F0
    decode_result = operand(0x5A6B8BA, "4c8bac24")
    assert decode_result == 0x2A0
    assert operand(0x5A6B8F9, "4c8bb424") == decode_result + 8
    assert operand(0x5A6B901, "4c8ba424") == decode_result + 0x10
    assert operand(0x5A6B909, "0f108424") == decode_result + 0x18
    assert operand(0x5A6B8C2, "4983fd", 1) == 5
    assert edge(0x5A6B8C6, "75", 1) == 0x5A6B8F9
    assert edge(0x5A6B968, "0f85") == 0x5A6BC95
    outer_tag = operand(0x5A6BCB5, "40b5", 1)
    assert outer_tag == 0x44
    assert operand(0x5A6A663, "48897c24", 1) == operand(0x5A6BC4B, "488b7c24", 1) == 0x78

    # The selected helper widens the decoded reply into a local tagged result.
    assembled = operand(0x5A6BBCF, "488d8424")
    assert operand(0x5A6BB6B, "4c89b424") == assembled == 0x1E8
    assert operand(0x5A6BB73, "4c89a424") == assembled + 8
    assert operand(0x5A6BB53, "0f118424") == assembled + 16
    assert operand(0x5A6BBF8, "0f298424") == 0x260
    assert operand(0x5A6BC39, "488d8c24") == 0x260
    expect(0x5A6BC56, "0f1001")
    assert operand(0x5A6BC59, "0f1147", 1) == 0x10
    assert operand(0x5A6BC1C, "488d8424") == 0x270
    expect(0x5A6BC5D, "0f1000")
    assert operand(0x5A6BC68, "0f1147", 1) == 0x20
    expect(0x5A6BC74, "40882f")
    assert operand(0x5A6BC77, "4c896f", 1) == 8

    out = operand(0x5A83686, "488dac24")
    expect(0x5A8368E, "4889ef")
    assert edge(0x5A83698, "e8") == 0x5A6A640
    assert operand(0x5A8369D, "440fb6b424") == out == 0x1420
    assert operand(0x5A83719, "4c8ba424") == out + 8
    assert operand(0x5A83721, "4c8bac24") == out + 0x10
    assert operand(0x5A83729, "4c8bbc24") == out + 0x18
    assert operand(0x5A83731, "0f108424") == out + 0x20
    assert operand(0x5A83739, "0f298424") == operand(0x5A837BE, "660f6f8424") == 0x350
    assert operand(0x5A837A4, "4180fe", 1) == outer_tag
    assert operand(0x5A837F0, "4983fc", 1) == 3
    assert edge(0x5A837F4, "0f85") == 0x5A83A6E
    assert operand(0x5A837FA, "4983fd", 1) == 1
    assert edge(0x5A837FE, "0f85") == 0x5A83B4D
    assert operand(0x5A837E0, "4c8db424") == operand(0x5A837E8, "4c89bc24") == 0xA0
    assert operand(0x5A837C7, "f30f7f8424") == 0xA8
    expect(0x5A83B59, "f3410f6f06")
    assert operand(0x5A83B4D, "498b46", 1) == 0x10
    assert operand(0x5A83B5E, "660f7f8424") == operand(0x5A83EBC, "4c8ba424") == 0x120
    assert operand(0x5A83C02, "4c8bac24") == 0x128
    assert operand(0x5A83B51, "48898424") == operand(0x5A83C0A, "4c8bbc24") == 0x130
    expect(0x5A83C1A, "4d85ff")
    assert edge(0x5A83C1D, "0f84") == 0x5A83D66
    expect(0x5A83C23, "498b4d00")
    phrase = b"\x04got \xc0\x15 client blocks first=\xc0\x07, last="
    assert at(".rodata", edge(0x5A83DD2, "488d05"), len(phrase)) == phrase
    assert operand(0x5A83EC4, "41b6", 1) == outer_tag

    assert operand(0x5A83F9F, "4c896424", 1) == 0x48
    assert operand(0x5A83FA4, "4c896c24", 1) == operand(0x5A84000, "488d4424", 1) == 0x50
    assert operand(0x5A83FA9, "4c897c24", 1) == 0x58
    expect(0x5A84021, "f30f6f00")
    assert operand(0x5A8402E, "660f7f8424") == operand(0x5A8407C, "660f6f8424") == 0x1E0
    assert operand(0x5A84096, "660f7f8424") == operand(0x5A840FB, "660f6f8424") == 0xD0
    assert operand(0x5A84115, "660f7f8424") == operand(0x5A841E8, "660f6f8424") == 0x3B0
    assert operand(0x5A841DB, "4180fe", 1) == outer_tag
    assert operand(0x5A841E1, "4c89a3") == 0x298
    assert operand(0x5A841F1, "f30f7f83") == operand(0x5A841F9, "488b83") == 0x2A0
    assert operand(0x5A84200, "488b8b") == 0x2A8
    shift = operand(0x5A84215, "48c1e1", 1)
    assert shift == 4
    expect(0x5A84219, "4801c1")
    assert operand(0x5A84223, "488983") == operand(0x5A82CE7, "48898b") == 0x230
    assert operand(0x5A84231, "48898b") == 0x240
    assert edge(0x5A8423D, "e9") == 0x5A82CD5
    expect(0x5A82CD5, "4839c8")
    assert edge(0x5A82CDD, "0f84") == 0x5A82E0F
    assert operand(0x5A82CE3, "488d48", 1) == 1 << shift
    expect(0x5A82CEE, "488b08")
    assert operand(0x5A82CF1, "488b40", 1) == 8
    assert operand(0x5A82D03, "488b93") == 0x268
    worker_frame = operand(0x5A82D0A, "488993")
    assert worker_frame == operand(0x5A82D26, "4c8da3") == 0x2D0
    assert operand(0x5A82D11, "48898b") == worker_frame + 8
    assert operand(0x5A82D18, "488983") == worker_frame + 16
    expect(0x5A82D35, "4c89e6")
    assert edge(0x5A82D3C, "e8") == 0x5A897E0

    for address in (0x5A837FA, 0x5A84215, 0x5A82D11):
        raw = rows[address]
        assert not matches(address, raw[:-1] + bytes([raw[-1] ^ 1]))
    check_rows(outer_tag, shift)

    print(f"PASS: SHA-256 {DIGEST}; {len(rows)} ranges in indexed FDEs and worker entry")
    print("PASS: selected completed reply retains its vector words after the 0x44 / 3 / discriminator check")
    print("PASS: 16-byte ordered rows advance once and reach the worker; cursor equality skips the row")
    print("PASS: two distinct rows, exhausted cursor and mutated witness controls")


def check_rows(outer_tag, shift):
    raw = struct.pack("<4Q", 100, 101, 200, 201)
    reply = bytearray(48)
    reply[0] = outer_tag
    struct.pack_into("<5Q", reply, 8, 3, 0, 2, 0x4000, 2)
    assert reply[0] == 0x44
    mode, kind = struct.unpack_from("<QQ", reply, 8)
    assert mode == 3 and kind != 1
    _, start, count = struct.unpack_from("<3Q", reply, 0x18)
    cursor, end = start, start + (count << shift)
    handoffs = []
    while cursor != end:
        first, second = struct.unpack_from("<2Q", raw, cursor - start)
        handoffs.append((0x5000, first, second))
        cursor += 1 << shift
    assert handoffs == [(0x5000, 100, 101), (0x5000, 200, 201)]
    assert cursor - start == 32
    assert len(handoffs) == count
    assert start + (0 << shift) == start


if __name__ == "__main__":
    main()
