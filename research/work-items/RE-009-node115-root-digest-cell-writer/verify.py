#!/usr/bin/env python3
"""Verify the bounded node #115 root-digest cell-writer packet."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PACKET = Path(__file__).resolve().parent
TARGET = ROOT / "artifacts/node/115/hl-node"
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

sys.path.insert(0, str(ROOT / "tools"))
from elf_index import unwind_index  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def rows_from_packet() -> list[dict[str, str]]:
    with (PACKET / "instructions.tsv").open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle, delimiter="\t"))


def validate_spans(data: bytes, sections: list[dict], fdes: list[dict], rows: list[dict[str, str]]) -> dict[int, bytes]:
    text = next(section for section in sections if section["name"] == ".text")
    valid_fdes = {(fde["start"], fde["end"]) for fde in fdes}
    spans: dict[int, bytes] = {}
    role_counts: dict[str, int] = {}
    for row in rows:
        address = int(row["va"], 16)
        start, end = int(row["fde_start"], 16), int(row["fde_end"], 16)
        raw = bytes.fromhex(row["bytes"])
        role_counts[row["role"]] = role_counts.get(row["role"], 0) + 1
        require(address not in spans, f"duplicate instruction address {address:#x}")
        require((start, end) in valid_fdes, f"unindexed FDE {start:#x}..{end:#x}")
        require(start <= address < address + len(raw) <= end, f"instruction outside FDE at {address:#x}")
        displacement = address - text["address"]
        require(0 <= displacement <= displacement + len(raw) <= text["size"], f"instruction outside .text at {address:#x}")
        offset = text["offset"] + displacement
        require(data[offset:offset + len(raw)] == raw, f"instruction bytes differ at {address:#x}")
        spans[address] = raw
    require(role_counts == {"selector-fallback": 3, "provider-entry": 3, "writer": 21, "root-caller": 2},
            f"unexpected witness row counts: {role_counts}")
    expected = {
        0x160BF4B: "ff15173bed04",
        0x5CADD61: "31c0",
        0x5CADD63: "31c9",
        0x5CADD68: "0fa2",
        0x5CAE39B: "4c89e8",
        0x5CAE39E: "4809f8",
        0x5CAE3A1: "488b0db8168300",
        0x5CAE3A8: "488901",
        0x5CAE3B6: "48894108",
        0x5CAE3C4: "48894110",
        0x5CAE3C8: "4c89e8",
        0x5CAE3D9: "c3",
        0x41C52D8: "ff15aaa13102",
        0x41C5367: "888424fb000000",
    }
    for address, raw_hex in expected.items():
        require(spans.get(address) == bytes.fromhex(raw_hex), f"required instruction differs at {address:#x}")
    return spans


def rip_target(address: int, raw: bytes) -> int:
    require(len(raw) >= 5, f"short RIP-relative instruction at {address:#x}")
    return address + len(raw) + struct.unpack_from("<i", raw, len(raw) - 4)[0]


def parse_relocations(data: bytes, sections: list[dict]) -> dict[int, tuple[int, int]]:
    rela = next(section for section in sections if section["name"] == ".rela.dyn")
    require(rela["size"] % 24 == 0, ".rela.dyn has a partial entry")
    return {
        address: (info, addend)
        for address, info, addend in struct.iter_unpack("<QQq", data[rela["offset"]:rela["offset"] + rela["size"]])
    }


def validate_relocations(relocations: dict[int, tuple[int, int]]) -> None:
    expected = {
        0x64DF488: (8, 0x160BEE0),
        0x64DFA60: (8, 0x6500098),
        0x64DFA68: (8, 0x5CADD50),
    }
    for slot, target in expected.items():
        require(relocations.get(slot) == target, f"unexpected RELATIVE relocation at {slot:#x}")


def verify() -> dict:
    data = TARGET.read_bytes()
    require(hashlib.sha256(data).hexdigest() == TARGET_SHA256, "node #115 digest mismatch")
    sections, _ = unwind_index(data)
    _, fdes = eh_frame_records(data, sections)
    rows = rows_from_packet()
    spans = validate_spans(data, sections, fdes, rows)
    require(rip_target(0x160BF4B, spans[0x160BF4B]) == 0x64DFA68, "selector fallback edge changed")
    require(rip_target(0x5CAE3A1, spans[0x5CAE3A1]) == 0x64DFA60, "cell pointer slot edge changed")
    require(rip_target(0x41C52D8, spans[0x41C52D8]) == 0x64DF488, "root caller selector edge changed")
    relocations = parse_relocations(data, sections)
    validate_relocations(relocations)
    bss = next(section for section in sections if section["name"] == ".bss")
    cell = 0x6500098
    require(bss["type"] == 8 and bss["address"] <= cell and cell + 24 <= bss["address"] + bss["size"],
            "the three-qword cell is not within zero-fill .bss")
    return {
        "target_sha256": TARGET_SHA256,
        "authenticated_instruction_rows": len(spans),
        "provider_fde": ["0x5cadd50", "0x5cae3da"],
        "provider_entry_cpuid_leaf": 0,
        "cell_pointer_slot": "0x64dfa60",
        "cell_address": "0x6500098",
        "cell_section": ".bss",
        "cell_bytes_written": 24,
        "writer_store_offsets": ["0x0", "0x8", "0x10"],
        "first_stored_expression": "r13 | rdi",
        "provider_return_expression": "r13",
        "selector_call_slot": "0x64dfa68",
        "runtime_execution": False,
    }


def self_test() -> dict:
    result = verify()
    data = TARGET.read_bytes()
    sections, _ = unwind_index(data)
    _, fdes = eh_frame_records(data, sections)
    rows = rows_from_packet()
    changed_rows = [dict(row) for row in rows]
    store = next(row for row in changed_rows if int(row["va"], 16) == 0x5CAE3B6)
    store["bytes"] = "48894118"
    try:
        validate_spans(data, sections, fdes, changed_rows)
    except ValueError:
        pass
    else:
        raise ValueError("altered second-store offset was accepted")
    changed_relocations = parse_relocations(data, sections)
    changed_relocations[0x64DFA60] = (8, 0x6500099)
    try:
        validate_relocations(changed_relocations)
    except ValueError:
        pass
    else:
        raise ValueError("altered cell relocation was accepted")
    result["negative_controls"] = ["altered second-store offset rejected", "altered cell relocation rejected"]
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    print(json.dumps(self_test() if args.self_test else verify(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
