#!/usr/bin/env python3
"""Verify the entry-callback to node #115 dispatch-selector trace."""
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


def section_rows(data: bytes) -> list[dict]:
    shoff = struct.unpack_from("<Q", data, 40)[0]
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 58)
    rows = []
    for i in range(shnum):
        fields = struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize)
        rows.append(
            {
                "name_offset": fields[0],
                "type": fields[1],
                "address": fields[3],
                "offset": fields[4],
                "size": fields[5],
                "link": fields[6],
                "entry_size": fields[9],
            }
        )
    names = rows[shstrndx]
    table = data[names["offset"] : names["offset"] + names["size"]]
    for row in rows:
        end = table.find(b"\0", row["name_offset"])
        row["name"] = table[row["name_offset"] : end].decode()
    return rows


def anchor_matches(data: bytes | bytearray, text: dict, row: dict) -> bool:
    va = int(row["va"], 16)
    off = text["offset"] + va - text["address"]
    return bytes(data[off : off + row["size"]]).hex() == row["bytes"]


def main() -> None:
    data = (ROOT / EVIDENCE["target"]).read_bytes()
    assert len(data) == EVIDENCE["size"]
    assert hashlib.sha256(data).hexdigest() == EVIDENCE["sha256"]

    parsed_sections = sections(data)
    by_name = {row["name"]: row for row in parsed_sections}
    text = by_name[".text"]
    _, fdes = eh_frame_records(data, parsed_sections)
    bounds = {(row["start"], row["end"]) for row in fdes}
    for row in EVIDENCE["anchors"]:
        va = int(row["va"], 16)
        end = va + row["size"]
        extent = (int(row["fde_start"], 16), int(row["fde_end"], 16))
        assert extent in bounds and extent[0] <= va < end <= extent[1]
        assert anchor_matches(data, text, row), row["id"]

    raw = section_rows(data)
    raw_by_name = {row["name"]: row for row in raw}
    rodata = by_name[".rodata"]
    table = EVIDENCE["dispatch_table"]
    base = int(table["base"], 16)
    table_off = rodata["offset"] + base - rodata["address"]
    index = table["index"]
    selected = base + struct.unpack_from("<i", data, table_off + 4 * index)[0]
    other = base + struct.unpack_from("<i", data, table_off + 4 * (index + 1))[0]
    assert selected == int(table["target"], 16) == 0x2AE420B
    assert other != selected

    relsec = raw_by_name[".rela.dyn"]
    relocs = {
        offset: (info, addend)
        for offset, info, addend in struct.iter_unpack(
            "<QQq", data[relsec["offset"] : relsec["offset"] + relsec["size"]]
        )
    }
    imp = EVIDENCE["copy_import_relocation"]
    info, addend = relocs[int(imp["slot"], 16)]
    assert info & 0xFFFFFFFF == imp["type"] == 6  # R_X86_64_GLOB_DAT
    symbol_index = info >> 32
    assert symbol_index == imp["symbolIndex"]
    dynsym = raw_by_name[".dynsym"]
    dynstr = raw[dynsym["link"]]
    symbol_offset = dynsym["offset"] + symbol_index * dynsym["entry_size"]
    name_offset = struct.unpack_from("<I", data, symbol_offset)[0]
    string_bytes = data[dynstr["offset"] : dynstr["offset"] + dynstr["size"]]
    name_end = string_bytes.find(b"\0", name_offset)
    assert string_bytes[name_offset:name_end].decode() == imp["symbol"] == "memcpy"
    assert addend == int(imp["addend"], 16) == 0

    cli = EVIDENCE["case_zero_cli_builder_relocation"]
    call_va = int(cli["call_va"], 16)
    call_off = text["offset"] + call_va - text["address"]
    assert bytes(data[call_off : call_off + 2]) == b"\xff\x15"
    disp = struct.unpack_from("<i", data, call_off + 2)[0]
    slot = call_va + 6 + disp
    assert slot == int(cli["slot"], 16)
    info, addend = relocs[slot]
    assert info & 0xFFFFFFFF == cli["type"] == 8  # R_X86_64_RELATIVE
    assert info >> 32 == cli["symbolIndex"] == 0
    assert addend == int(cli["target"], 16) == 0x564D700

    # Negative control: change the initialized selector byte from 0 to 1.
    row = next(r for r in EVIDENCE["anchors"] if r["id"] == "entry_zero_and_call")
    mutated = bytearray(data)
    va = 0x2CD839C
    off = text["offset"] + va - text["address"]
    assert data[off] == 0
    mutated[off] = 1
    assert not anchor_matches(mutated, text, row)

    print(
        f"target digest, {len(EVIDENCE['anchors'])} instruction anchors, "
        "copy and CLI-builder relocations, dispatch entry 0 and one-byte control verified"
    )


if __name__ == "__main__":
    main()
