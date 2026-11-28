#!/usr/bin/env python3
"""Regenerate the selected #115 checkpoint clock disassembly evidence."""

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
    0x30d1c60: '30d250b 30d2510 30d2515 30d2517 30d251d 30d2521 30d2528 30d252d\n    30d254b 30d2550 30d2555 30d2557 30d255d 30d2562 30d2567 30d2ee7\n    30d3156 30d3158 30d315e 30d3161 30d31fe 30d3201 30d3209 30d320d 30d3211 30d3219',
    0x332c430: '332c7f8 332c805 332c879 332c88d 332c891 332c8a4 332c8a8\n    332dec3 332dee3 332deeb 332def3 3330a03 3330a23 3330a2b 3330a33\n    3330b1f 3330b27 3330b2f 3330b34 332e01a 332e022 332e02a',
    0x2fd7260: '2fd78cf 2fd78dc 2fd7912 2fd791a 2fd791f 2fd7927 2fd796b\n    2fd7973 2fd7978 2fd7980 2fd77cf 2fda871 2fda879 2fda881 2fda886 2fe464f\n    2fe4657 2fe465f 2fe4664 2fe4c55 2fe4c5d 2fe4c65',
    0x32caf70: '32cb0cc 32cb0dc 32cb221 32cb229 32cb231 32cb236\n    32cb797 32cb79f 32cb7a7 32cb7ac',
    0x3c2e860: '3c2ec6a 3c2efff 3c2f004 3c2f007 3c2f00a',
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
        (b"time", 5, 0x30D24F5),
        (b"prev_time", 6, 0x30D253A),
    ):
        index = classify_context(data, elf_sections, key)
        entry = offset_for(elf_sections, table + 4 * index, 4)
        (delta,) = struct.unpack_from("<i", data, entry)
        if (index, table + delta) != (expected_index, expected_arm):
            raise ValueError(f"unexpected field dispatch for {key!r}")


def evidence():
    data = TARGET.read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError("unexpected node #115 digest")
    elf_sections = sections(data)
    verify_dispatch(data, elf_sections)
    _, index = unwind_index(data)
    indexed = {(row["start"], row["fde"]) for row in index}
    _, fdes = eh_frame_records(data, elf_sections)
    ends = {row["start"]: row["end"] for row in fdes if (row["start"], row["fde"]) in indexed}

    result = io.StringIO()
    rows = csv.writer(result, delimiter="\t", lineterminator="\n")
    rows.writerow(("fde_start", "fde_end", "linked_va", "file_offset", "bytes", "llvm_intel"))
    for start, addresses in WINDOWS.items():
        end = ends[start]
        llvm = decode(["llvm-objdump", "-d", "--x86-asm-syntax=intel"], start, end)
        for address in map(lambda word: int(word, 16), addresses.split()):
            raw, assembly = llvm[address]
            offset = offset_for(elf_sections, address, len(raw))
            if raw != data[offset : offset + len(raw)]:
                raise ValueError(f"instruction boundary or byte mismatch at {address:#x}")
            rows.writerow((hex(start), hex(end), hex(address), hex(offset), raw.hex(), assembly))
    return result.getvalue()


def coordinates(tsv):
    # The printable LLVM decode may contain platform-dependent symbol labels.
    return [row[:5] for row in csv.reader(io.StringIO(tsv), delimiter="\t")]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="compare against the retained TSV")
    args = parser.parse_args()
    result = evidence()
    if args.check:
        expected = coordinates((PACKET / "windows.txt").read_text())
        if coordinates(result) != expected:
            raise ValueError("retained instruction coordinates or bytes differ")
        print(f"PASS: node #115 SHA-256 {SHA}")
        print("PASS: MessagePack field dispatch time=5, prev_time=6")
        print(f"PASS: {len(expected) - 1} instruction spans match the ELF and LLVM objdump")
    else:
        print(result, end="")


if __name__ == "__main__":
    main()
