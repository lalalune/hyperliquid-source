#!/usr/bin/env python3
"""Verify the two vote arms in three node #115 Action formatter copies."""
import hashlib
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))

from elf_index import unwind_index
from fde_extents import eh_frame_records

ARTIFACT = ROOT / "artifacts/node/115/hl-node"
SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
COPIES = (
    (0x2BC95F0, 0x2BCBBE1, 0x60946C, ((0x2BCB202, 0x28FEDF0), (0x2BCB902, 0x29AB7B0))),
    (0x36AEF70, 0x36B1562, 0x799DEC, ((0x36B0B82, 0x44B6060), (0x36B1283, 0x44C4FF0))),
    (0x4D81E00, 0x4D843F2, 0x9146B4, ((0x4D83A12, 0x5920730), (0x4D84113, 0x5924BD0))),
)


def require(condition, address):
    if not condition:
        raise ValueError(f"unexpected encoding at {address:#x}")


def main():
    data = ARTIFACT.read_bytes()
    require(hashlib.sha256(data).hexdigest() == SHA, 0)
    sections, index = unwind_index(data)
    _, fdes = eh_frame_records(data, sections)
    indexed = {(row["start"], row["fde"]) for row in index}
    ranges = {
        (row["start"], row["end"])
        for row in fdes if (row["start"], row["fde"]) in indexed
    }
    text = next(section for section in sections if section["name"] == ".text")
    rodata = next(section for section in sections if section["name"] == ".rodata")

    def read(section, address, size):
        relative = address - section["address"]
        require(0 <= relative <= section["size"] - size, address)
        offset = section["offset"] + relative
        return data[offset : offset + size]

    def relative(instruction, raw, opcode):
        require(raw.startswith(opcode) and len(raw) == len(opcode) + 4, instruction)
        return instruction + len(raw) + struct.unpack_from("<i", raw, len(opcode))[0]

    print("fde\ttag\tcell\tcell_bytes\tarm\tlabel\tcallee")
    for start, end, table, arms in COPIES:
        require((start, end) in ranges, start)
        prologue = read(text, start, 0x26)
        require(prologue[:0x16] == bytes.fromhex("4883ec48488b07482d86000000b914000000480f43c8"), start)
        require(relative(start + 0x16, prologue[0x16:0x1d], b"\x48\x8d\x05") == table, start)
        require(prologue[0x1d:] == bytes.fromhex("48630c884801c1ffe1"), start + 0x1d)

        for tag, (arm, callee), variant in zip((0xDC, 0xDD), arms, (b"VoteL1Hash", b"VoteAbciDigest")):
            cell = table + 4 * (tag - 0x86)
            entry = read(rodata, cell, 4)
            require(table + struct.unpack("<i", entry)[0] == arm, cell)
            require(start <= arm and arm + 0x69 <= end, arm)
            raw = read(text, arm, 0x69)
            require(raw[:4] == bytes.fromhex("4883c708"), arm)
            for offset, name in ((4, b"Action"), (0x18, variant), (0x2d, b"type"), (0x42, variant[:1].lower() + variant[1:])):
                address = relative(arm + offset, raw[offset:offset + 7], b"\x48\x8d\x05")
                require(read(rodata, address, len(name)) == name, address)
            require(raw[0x4e:0x57] == b"\x48\xc7\x44\x24\x38" + struct.pack("<I", len(variant)), arm + 0x4e)
            require(raw[0x57:0x5f] == bytes.fromhex("48897424404889e6"), arm + 0x57)
            require(relative(arm + 0x5f, raw[0x5f:0x64], b"\xe8") == callee, arm + 0x5f)
            require(raw[0x64:] == bytes.fromhex("4883c448c3"), arm + 0x64)
            print(f"{start:#x}\t{tag:#x}\t{cell:#x}\t{entry.hex()}\t{arm:#x}\t{variant.decode()}\t{callee:#x}")


if __name__ == "__main__":
    main()
