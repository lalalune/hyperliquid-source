"""Authenticate the selected positional tracker decoder against the pinned ELF."""

import hashlib
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path.cwd() / "tools"))
from elf_index import unwind_index
from fde_extents import eh_frame_records

TARGET = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
WITNESS = Path(__file__).with_name("windows.txt")
EXTENTS = {
    (0x1C062B0, 0x1C087F2),
    (0x198E9B0, 0x198FA65),
    (0x22A6250, 0x22A6351),
}


def main():
    data = Path("artifacts/node/115/hl-node").read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET
    sections, header = unwind_index(data)
    _, fdes = eh_frame_records(data, sections)
    indexed = {(row["start"], row["fde"]) for row in header}
    extents = {
        (row["start"], row["end"])
        for row in fdes
        if (row["start"], row["fde"]) in indexed
    }
    assert EXTENTS <= extents

    def read(section_name, address, size):
        section = next(section for section in sections if section["name"] == section_name)
        delta = address - section["address"]
        assert 0 <= delta <= section["size"] - size
        start = section["offset"] + delta
        return data[start:start + size]

    instructions = {}
    pattern = re.compile(r"\s+([0-9a-f]+):\s*((?:[0-9a-f]{2} )+)")
    for line in WITNESS.read_text().splitlines():
        if match := pattern.match(line):
            address = int(match[1], 16)
            code = bytes.fromhex(match[2])
            assert any(start <= address < address + len(code) <= end for start, end in EXTENTS)
            assert address not in instructions and read(".text", address, len(code)) == code
            instructions[address] = code

    def relative(address, prefix, destination):
        code = instructions[address]
        assert code[:len(prefix)] == prefix
        displacement = int.from_bytes(code[len(prefix):], "little", signed=True)
        assert address + len(code) + displacement == destination

    for call, destination in (
        (0x1C065A2, 0x198E9B0),
        (0x1C080B1, 0x198E9B0),
        (0x198F021, 0x22A6250),
        (0x22A6303, 0x17C73A0),
    ):
        relative(call, b"\xe8", destination)
    for branch, prefix, destination in (
        (0x1C0658F, b"\x0f\x85", 0x1C0821A),
        (0x1C07C86, b"\x0f\x85", 0x1C080A7),
        (0x1C080BB, b"\x74", 0x1C080E2),
        (0x198EA21, b"\xe9", 0x198EB30),
        (0x198F013, b"\x0f\x84", 0x198F22E),
        (0x198F02B, b"\x74", 0x198F099),
        (0x198F051, b"\xe9", 0x198F24B),
        (0x198F143, b"\x75", 0x198F1A3),
        (0x198F268, b"\xe9", 0x198F334),
    ):
        relative(branch, prefix, destination)

    relative(0x1C0825A, b"\x48\x8d\x05", 0x5C8D27)
    relative(0x1C0839D, b"\x48\x8d\x05", 0x5CBB04)
    relative(0x22A62F2, b"\x48\x8d\x15", 0x5FF785)
    for address, name in (
        (0x5C8D27, b"h"),
        (0x5CBB04, b"trackerqrshighest_quorum_heighthtmadustruct HashSignatureTracker with 6 elements"),
        (0x5FF785, b"AbciDigest"),
    ):
        assert read(".rodata", address, len(name)) == name

    for address, encoding in (
        (0x198F0DE, "44 88 7c 24 09"),
        (0x198F0E3, "88 44 24 0a"),
        (0x198F320, "48 89 4f 01"),
        (0x198F33C, "c6 07 01"),
        (0x1C080E7, "0f b6 44 24 41"),
        (0x1C080EC, "0f b6 4c 24 42"),
        (0x1C080F1, "0f 10 44 24 53"),
        (0x1C080F6, "0f 10 4c 24 43"),
        (0x22A62DE, "66 c7 03 00 00"),
        (0x22A6340, "c6 43 01 01"),
    ):
        assert instructions[address] == bytes.fromhex(encoding)
    print(f"PASS: node #115 {TARGET}")
    print(f"PASS: {len(instructions)} instruction spans across three indexed FDEs")
    print("PASS: named h correlation, positional tail and AbciDigest callee")
    print("PASS: nil/present encodings, separate boolean and option bytes, missing-slot/error path")


if __name__ == "__main__":
    main()
