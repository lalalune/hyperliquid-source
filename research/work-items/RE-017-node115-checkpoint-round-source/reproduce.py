#!/usr/bin/env python3
"""Regenerate the selected #115 checkpoint-round disassembly evidence."""

import argparse
import csv
import hashlib
import io
from pathlib import Path
import re
import struct
import subprocess
import sys

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
sys.path.insert(0, str(ROOT / "tools"))

from abci_binary_context115 import classify_context
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

TARGET = ROOT / "artifacts/node/115/hl-node"
SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
WINDOWS = {
    # Separate round and height fields, including the absent-round default.
    0x30D1C60: """30d218a 30d2191 30d2195 30d2198 30d22ae 30d22b7 30d22c5 30d22cf 30d22d1 30d22d7 30d22dc 30d22e9
        30d23a6 30d2be9 30d2bf4 30d2c01 30d2c0e 30d2eee 30d2ef0 30d2ef8 30d2f00
        30d2f8c 30d2f94 30d31b2 30d31ba 30d31be""",
    # The nested output copies carrying both qwords.
    0x332C430: """332c7f8 332c805 332c879 332c899 332c8c0 332deab 332decb
        33309eb 3330a0b 3330b1f 3330b27 3330b2f 3330b34 332e01a 332e022 332e02a""",
    0x2FD7260: """2fd78cf 2fd78dc 2fd7912 2fd791a 2fd791f 2fd7927 2fd796b 2fd7973
        2fd7978 2fd7980 2fd77cf 2fda871 2fda879 2fda881 2fda886 2fe464f
        2fe4657 2fe465f 2fe4664 2fe4c55 2fe4c5d 2fe4c65""",
    0x32CAF70: """32cb0cc 32cb0dc 32cb221 32cb229 32cb231 32cb236 32cb260
        32cb797 32cb79f 32cb7a7 32cb7ac 32cb7c6 32cb868 32cb86d 32cb870""",
    0x3266520: """32666cc 32666d7 32666e6 32666f4 32666fa 32666ff 3266704
        3266707 326670a 3266af5 32672d5 326762a 3267632 3267650 3267664""",
    # Reader result pointer, materializer and loader acceptance.
    0x422E410: "422e5f3 422e5f6 422e6aa 422e6af 422e6b4 422e6b6 422e6c0 422e6c3",
    0x3C13520: "3c13536 3c1353b 3c1353f 3c135bc 3c135c2 3c135c8 3c135cb",
    0x3C13610: """3c1365c 3c1365f 3c13662 3c13665 3c13670 3c13679 3c1367b
        3c1367e 3c13683 3c13689 3c13699 3c1369f""",
    0x3C2E860: "3c2e8a7 3c2e8aa 3c2ec6a 3c2efff 3c2f004 3c2f007 3c2f00a 3c2f2c0",
    0x3C12800: """3c128a2 3c128a8 3c128ab 3c128af 3c128ca 3c128d4 3c128d7
        3c128e2 3c128e7 3c128ec 3c128fa 3c128ff 3c1298f""",
}
INSTRUCTION = re.compile(r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(\S.*)$")


def decode(command, start, end):
    output = subprocess.check_output(
        [*command, f"--start-address={start:#x}", f"--stop-address={end:#x}", str(TARGET)],
        text=True,
    )
    instructions = {}
    for line in output.splitlines():
        match = INSTRUCTION.match(line)
        if match:
            address, raw, assembly = match.groups()
            instructions[int(address, 16)] = (bytes.fromhex(raw), assembly.split("#")[0].strip())
    return instructions


def offset_for(elf_sections, address, size):
    offsets = [
        section["offset"] + address - section["address"]
        for section in elf_sections
        if section["type"] != 8
        and section["address"] <= address
        and address + size <= section["address"] + section["size"]
    ]
    if len(offsets) != 1:
        raise ValueError(f"ambiguous ELF mapping at {address:#x}")
    return offsets[0]


def verify_dispatch(data, elf_sections):
    table = 0x68AC4C
    for key, expected_index, expected_arm in (
        (b"height", 2, 0x30D23A6),
        (b"round", 4, 0x30D22AE),
        (b"consensus_round", 4, 0x30D22AE),
    ):
        index = classify_context(data, elf_sections, key)
        entry = offset_for(elf_sections, table + 4 * index, 4)
        (delta,) = struct.unpack_from("<i", data, entry)
        if (index, table + delta) != (expected_index, expected_arm):
            raise ValueError(f"unexpected field dispatch for {key!r}")


def verify_relocations(data, elf_sections):
    relocations = next(section for section in elf_sections if section["name"] == ".rela.dyn")
    bindings = {
        0x64E9628: 0x3C13520,
        0x64E73A0: 0x3C13610,
        0x64E9630: 0x3C2E860,
    }
    for address, slot in ((0x3C128A2, 0x64E9628), (0x3C135C2, 0x64E73A0), (0x3C13665, 0x64E9630)):
        offset = offset_for(elf_sections, address, 6)
        opcode, delta = struct.unpack_from("<2si", data, offset)
        if opcode != b"\xff\x15" or address + 6 + delta != slot:
            raise ValueError(f"unexpected materializer call at {address:#x}")
    for slot, info, addend in struct.iter_unpack(
        "<QQq", data[relocations["offset"] : relocations["offset"] + relocations["size"]]
    ):
        if slot in bindings:
            if info != 8 or addend != bindings.pop(slot):
                raise ValueError(f"unexpected relative binding at {slot:#x}")
    if bindings:
        raise ValueError("missing materializer relocation")


def evidence():
    data = TARGET.read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError("unexpected node #115 digest")
    elf_sections = sections(data)
    verify_dispatch(data, elf_sections)
    verify_relocations(data, elf_sections)
    _, index = unwind_index(data)
    indexed = {(row["start"], row["fde"]) for row in index}
    _, fdes = eh_frame_records(data, elf_sections)
    ends = {row["start"]: row["end"] for row in fdes if (row["start"], row["fde"]) in indexed}

    result = io.StringIO()
    rows = csv.writer(result, delimiter="\t", lineterminator="\n")
    rows.writerow(("fde_start", "fde_end", "linked_va", "file_offset", "bytes", "gnu_intel"))
    for start, addresses in WINDOWS.items():
        end = ends[start]
        gnu = decode(["objdump", "-d", "-M", "intel", "--insn-width=16"], start, end)
        llvm = decode(["llvm-objdump", "-d", "--x86-asm-syntax=intel"], start, end)
        for address in map(lambda word: int(word, 16), addresses.split()):
            raw, assembly = gnu[address]
            offset = offset_for(elf_sections, address, len(raw))
            if raw != llvm[address][0] or raw != data[offset : offset + len(raw)]:
                raise ValueError(f"instruction boundary or byte mismatch at {address:#x}")
            rows.writerow((hex(start), hex(end), hex(address), hex(offset), raw.hex(), assembly))
    return result.getvalue()


def coordinates(tsv):
    # The printable GNU decode may contain platform-dependent symbol labels.
    return [row[:5] for row in csv.reader(io.StringIO(tsv), delimiter="\t")]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="compare against the retained TSV")
    args = parser.parse_args()
    result = evidence()
    if args.check:
        expected = coordinates((PACKET / "instructions.tsv").read_text())
        if coordinates(result) != expected:
            raise ValueError("retained instruction coordinates or bytes differ")
        print(f"{len(expected) - 1} instruction spans match both decoders and the ELF")
    else:
        print(result, end="")


if __name__ == "__main__":
    main()
