#!/usr/bin/env python3
"""Verify selected replay-key instructions against the authenticated node ELF."""

import csv
import hashlib
from pathlib import Path
import sys

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
sys.path.insert(0, str(ROOT / "tools"))

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def check_bytes(actual, expected, address):
    if not expected or actual != expected:
        raise ValueError(f"instruction bytes differ at {address:#x}")


def main():
    data = (ROOT / "artifacts/node/115/hl-node").read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError("unexpected node #115 digest")
    elf_sections = sections(data)
    _, index = unwind_index(data)
    _, fdes = eh_frame_records(data, elf_sections)
    indexed = {(row["start"], row["fde"]) for row in index}
    extents = {
        (row["start"], row["end"])
        for row in fdes
        if (row["start"], row["fde"]) in indexed
    }

    seen = set()
    with (PACKET / "instructions.tsv").open(newline="") as handle:
        for row in csv.DictReader(handle, delimiter="\t"):
            start = int(row["fde_start"], 16)
            end = int(row["fde_end"], 16)
            address = int(row["linked_va"], 16)
            expected = bytes.fromhex(row["bytes"])
            stop = address + len(expected)
            if address in seen or (start, end) not in extents or not start <= address < stop <= end:
                raise ValueError(f"invalid or duplicate instruction at {address:#x}")
            seen.add(address)
            offsets = [
                section["offset"] + address - section["address"]
                for section in elf_sections
                if section["type"] != 8 and section["flags"] & 4
                and section["address"] <= address
                and stop <= section["address"] + section["size"]
            ]
            if offsets != [int(row["file_offset"], 16)]:
                raise ValueError(f"unexpected file mapping at {address:#x}")
            offset = offsets[0]
            actual = data[offset : offset + len(expected)]
            check_bytes(actual, expected, address)
            try:
                check_bytes(actual[:-1] + bytes([actual[-1] ^ 1]), expected, address)
            except ValueError:
                continue
            raise AssertionError(f"byte corruption accepted at {address:#x}")
    if len(seen) != 41:
        raise ValueError(f"expected 41 selected instructions, got {len(seen)}")
    print(f"{len(seen)} exact instructions verified; {len(seen)} byte mutations rejected")


if __name__ == "__main__":
    main()
