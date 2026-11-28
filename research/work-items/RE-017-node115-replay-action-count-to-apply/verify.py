"""Bind selected replay record and action descriptor counts to the ABCI engine."""
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
    entries = {0x3D9CE60, 0x4F122C0, 0x4FAD300, 0x4FCB590, 0x56186C0, 0x5A06600, 0x5A6E1E0, 0x5AB6DF0}
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
    relative = {
        slot: addend for slot, kind, addend in struct.iter_unpack(
            "<QQq", at(".rela.dyn", rela["address"], rela["size"])
        ) if kind == 8
    }

    assert edge(0x5AB6F81, "e8") == 0x581A100
    assert operand(0x5AB6F86, "488b4424", 1) == 0x48
    assert operand(0x5AB7075, "488d4424", 1) == 0x50
    assert operand(0x5AB707D, "0f294424", 1) == operand(0x5AB7184, "0f284424", 1) == 0x60
    assert operand(0x5AB7082, "41be") == 1
    assert operand(0x5AB718E, "0f1143", 1) == 8
    expect(0x5AB719C, "4c8933")
    receive = operand(0x5A6E318, "488dbc24")
    assert receive == 0x468 and edge(0x5A6E328, "e8") == 0x5AB6DF0
    expect(0x5A6E32D, "83bc246804000001")
    assert operand(0x5A6E33B, "488bac24") == receive + 8
    assert operand(0x5A6E343, "488b9424") == receive + 16
    assert edge(0x5A6E34E, "74", 1) == 0x5A6E380
    pair = operand(0x5A6E350, "4889ac24")
    assert pair == operand(0x5A6E482, "488db424") == 0x3C8
    assert operand(0x5A6E358, "48899424") == pair + 8
    assert edge(0x5A6E3EA, "0f85") == 0x5A700F8

    converted = operand(0x5A6E47A, "488dbc24")
    assert relative[edge(0x5A6E48D, "ff15")] == 0x4FAD300
    expect(0x4FAD316, "4c8b16")
    assert operand(0x4FAD388, "488b4e", 1) == 8
    assert operand(0x4FAD38C, "488b41", 1) == 0x20
    expect(0x4FAD654, "488908")
    assert operand(0x4FAD65C, "488948", 1) == 8
    assert operand(0x4FAD665, "488948", 1) == 16
    assert operand(0x5A6E49D, "48398424") == converted == 0x4F8
    assert edge(0x5A6E4A5, "0f85") == 0x5A6E5E0
    assert operand(0x5A6E600, "660f108424") == converted
    assert operand(0x5A6E609, "660f108c24") == converted + 16
    original = operand(0x5A6E63F, "660f298424")
    assert original == 0x320
    assert operand(0x5A6E636, "660f298c24") == original + 16

    assert operand(0x5A6E648, "4c8ba424") == original + 16
    expect(0x5A6E650, "4a8d04e500000000")
    expect(0x5A6E658, "488d1c80")
    assert operand(0x5A6E674, "4c8bb424") == original + 8
    assert relative[edge(0x5A6E67F, "ff15")] == 0x6355830
    expect(0x5A6E68E, "4989c7")
    assert operand(0x5A6E6A5, "498b56", 1) == operand(0x5A6E6D2, "49895407", 1) == 0x20
    assert rows[0x5A6E6A9] == b"\xf0"
    expect(0x5A6E6AA, "48ff02")
    assert operand(0x5A6E6C1, "4983c6", 1) == operand(0x5A6E6D7, "4883c0", 1) == 40
    assert operand(0x5A6E7F6, "4d89be") == 0x600
    assert operand(0x5A6E7FD, "4d89a6") == 0x608

    closure = operand(0x5A6E96E, "488d6c24", 1)
    assert operand(0x5A6E923, "660f108424") == original + 8
    assert operand(0x5A6E950, "660f114424", 1) == closure == 0x60
    assert operand(0x5A6E95E, "48894424", 1) == closure + 16
    assert operand(0x5A6E956, "488d8424") == 0x240
    collected = operand(0x5A6E963, "4c8dac24")
    assert collected == 0x1B0
    assert operand(0x5A6E92C, "48c78424b0010000") == 0
    assert operand(0x5A6E938, "48c78424b8010000") == 8
    assert operand(0x5A6E944, "48c78424c0010000") == 0
    expect(0x5A6E96B, "4c89ef")
    expect(0x5A6E973, "4889ee")
    assert edge(0x5A6E976, "e8") == 0x3D9CE60
    expect(0x3D9CE60, "4889f2")
    assert operand(0x3D9CE63, "488b76", 1) == 8
    assert edge(0x3D9CE67, "e9") == 0x4301E90
    worker = operand(0x5A6E9FC, "488d9424")
    assert worker == 0x290
    assert operand(0x5A6E97B, "660f108424") == collected
    assert operand(0x5A6E984, "660f298424") == worker
    assert operand(0x5A6E98D, "488b8424") == collected + 16
    assert operand(0x5A6E995, "48898424") == worker + 16
    assert operand(0x5A6E99D, "488d8424") == original
    assert operand(0x5A6E9A5, "48898424") == worker + 24
    assert edge(0x5A6EA10, "e8") == 0x4F122C0

    expect(0x4F122D1, "4889d5")
    expect(0x4F122DF, "807e2000")
    assert edge(0x4F122E3, "74", 1) == 0x4F12346
    expect(0x4F12349, "4889ee")
    assert edge(0x4F1234C, "e8") == 0x4FCB590
    expect(0x4FCB5A1, "4989f5")
    expect(0x4FCB764, "66410f104500")
    assert operand(0x4FCB76A, "66410f104d", 1) == 16
    frame = operand(0x4FCB790, "488d7424", 1)
    assert frame == operand(0x4FCB776, "660f294424", 1) == 0x50
    assert operand(0x4FCB770, "660f294c24", 1) == frame + 16
    assert edge(0x4FCB795, "e8") == 0x56186C0
    expect(0x56186F3, "0f1006")
    assert operand(0x56186F6, "0f104e", 1) == 16
    engine = operand(0x5618708, "488d5424", 1)
    assert engine == operand(0x56186FF, "0f294424", 1) == 0x10
    assert operand(0x56186FA, "0f294c24", 1) == engine + 16
    assert edge(0x5618710, "e8") == 0x5A06600
    expect(0x5A06611, "4889d3")
    assert operand(0x5A0663D, "488b43", 1) == 24
    assert operand(0x5A066F4, "4c8b70", 1) == 16
    assert operand(0x5A06638, "48895c24", 1) == operand(0x5A06700, "488b4424", 1) == 8
    assert operand(0x5A06705, "488b40", 1) == 16
    expect(0x5A06711, "4939c6")
    assert edge(0x5A06714, "0f85") == 0x5A07AF2

    for address in (0x5A6E923, 0x5A6E9A5, 0x5A06705):
        raw = rows[address]
        assert not matches(address, raw[:-1] + bytes([raw[-1] ^ 1]))
    check_application_input()

    print(f"PASS: SHA-256 {DIGEST}; {len(rows)} ranges in {len(bounds)} indexed FDEs")
    print("PASS: ready queue pair reaches the converter; pending cloned rows are distinct from original descriptor")
    print("PASS: collector triple plus original descriptor address reach engine unchanged through adapters")
    print("PASS: engine compares collected and converted counts; distinct storage/field/byte controls")


def check_application_input():
    original_address, clone_address, collected_address = 0x3000, 0x4000, 0x5000
    original_descriptor = struct.pack("<3Q", 7, 0x7000, 2)
    descriptors = {
        original_address: original_descriptor,
        clone_address: struct.pack("<3Q", 3, 0x8000, 1),
    }
    for collected_count, equal in ((2, True), (1, False), (0, False)):
        worker = struct.pack("<4Q", 8, collected_address, collected_count, original_address)
        adapter = bytes(worker)
        count, descriptor_address = struct.unpack_from("<QQ", adapter, 16)
        converted_count = struct.unpack_from("<Q", descriptors[descriptor_address], 16)[0]
        assert (count == converted_count) == equal
        assert descriptor_address != clone_address
        assert converted_count != struct.unpack_from("<Q", descriptors[clone_address], 16)[0]


if __name__ == "__main__":
    main()
