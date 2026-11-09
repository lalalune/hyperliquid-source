#!/usr/bin/env python3
"""Verify the selected node #115 bridge input producer trace (static only)."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))

from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

PACKET = Path(__file__).resolve().parent
EVIDENCE = json.loads((PACKET / "evidence.json").read_text())


def anchor_matches(data: bytes | bytearray, section: dict, record: dict) -> bool:
    va = int(record["va"], 16)
    offset = section["offset"] + va - section["address"]
    return bytes(data[offset : offset + record["size"]]).hex() == record["bytes"]


def main() -> None:
    binary = ROOT / EVIDENCE["target"]
    data = binary.read_bytes()
    assert len(data) == EVIDENCE["size"]
    assert hashlib.sha256(data).hexdigest() == EVIDENCE["sha256"]
    all_sections = sections(data)
    by_name = {section["name"]: section for section in all_sections}
    text = by_name[".text"]
    rodata = by_name[".rodata"]
    _, fdes = eh_frame_records(data, all_sections)

    for record in EVIDENCE["anchors"]:
        va = int(record["va"], 16)
        end = va + record["size"]
        bounds = (int(record["fde_start"], 16), int(record["fde_end"], 16))
        assert bounds in {(fde["start"], fde["end"]) for fde in fdes}
        assert bounds[0] <= va < end <= bounds[1]
        assert anchor_matches(data, text, record), record["id"]

    for literal in EVIDENCE["literals"]:
        va = int(literal["va"], 16)
        offset = rodata["offset"] + va - rodata["address"]
        expected = bytes.fromhex(literal["bytes"])
        assert data[offset : offset + len(expected)] == expected

    rela = by_name[".rela.dyn"]
    relocs = {
        slot: (info, addend)
        for slot, info, addend in struct.iter_unpack(
            "<QQq", data[rela["offset"] : rela["offset"] + rela["size"]]
        )
    }
    for slot, expected in EVIDENCE["relative_relocations"].items():
        info, addend = relocs[int(slot, 16)]
        assert info == expected["type"] == 8
        assert addend == int(expected["addend"], 16)

    table = EVIDENCE["switch_table"]
    base = int(table["base"], 16)
    for index, target in table["entries"].items():
        offset = rodata["offset"] + base - rodata["address"] + 4 * int(index)
        assert base + struct.unpack_from("<i", data, offset)[0] == int(target, 16)

    # Negative control: a one-byte mutation of a recorded callsite must fail.
    record = next(row for row in EVIDENCE["anchors"] if row["id"] == "caller_tag5")
    mutated = bytearray(data)
    va = int(record["va"], 16)
    offset = text["offset"] + va - text["address"]
    mutated[offset] ^= 1
    assert not anchor_matches(mutated, text, record)

    print(
        f"target digest, {len(EVIDENCE['anchors'])} instruction anchors, "
        f"{len(EVIDENCE['relative_relocations'])} RELATIVE relocations, "
        "tag-4/tag-5 switch entries and one-byte negative control verified"
    )


if __name__ == "__main__":
    main()
