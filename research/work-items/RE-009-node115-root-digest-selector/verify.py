#!/usr/bin/env python3
"""Verify the bounded node #115 root-digest selector evidence packet."""

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
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET = ROOT / "artifacts/node/115/hl-node"

sys.path.insert(0, str(ROOT / "tools"))
from elf_index import unwind_index  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def read_rows() -> list[dict[str, str]]:
    with (PACKET / "instructions.tsv").open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle, delimiter="\t"))


def parse_rows(data: bytes, sections: list[dict], fdes: list[dict], rows: list[dict[str, str]]) -> dict[int, bytes]:
    text = next(section for section in sections if section["name"] == ".text")
    indexed_fdes = {(row["start"], row["end"]) for row in fdes}
    spans: dict[int, bytes] = {}
    for row in rows:
        va = int(row["va"], 16)
        start, end = int(row["fde_start"], 16), int(row["fde_end"], 16)
        raw = bytes.fromhex(row["bytes"])
        require(va not in spans, f"duplicate instruction address {va:#x}")
        require((start, end) in indexed_fdes, f"unindexed FDE {start:#x}..{end:#x}")
        require(start <= va < va + len(raw) <= end, f"instruction outside FDE at {va:#x}")
        delta = va - text["address"]
        require(0 <= delta <= delta + len(raw) <= text["size"], f"instruction outside .text at {va:#x}")
        offset = text["offset"] + delta
        require(data[offset:offset + len(raw)] == raw, f"instruction bytes differ at {va:#x}")
        spans[va] = raw
    return spans


def relocations_for(data: bytes, sections: list[dict]) -> dict[int, tuple[int, int]]:
    section = next(row for row in sections if row["name"] == ".rela.dyn")
    require(section["size"] % 24 == 0, ".rela.dyn has a partial entry")
    return {
        address: (info, addend)
        for address, info, addend in struct.iter_unpack(
            "<QQq", data[section["offset"]:section["offset"] + section["size"]]
        )
    }


def rip_target(address: int, raw: bytes) -> int:
    require(len(raw) >= 5, f"short RIP-relative instruction at {address:#x}")
    displacement = struct.unpack_from("<i", raw, len(raw) - 4)[0]
    return address + len(raw) + displacement


def branch_target(address: int, raw: bytes) -> int:
    if len(raw) == 2 and (0x70 <= raw[0] <= 0x7F or raw[0] == 0xEB):
        return address + 2 + struct.unpack("b", raw[1:2])[0]
    require(len(raw) == 6 and raw[:1] == b"\x0f" and 0x80 <= raw[1] <= 0x8F,
            f"unsupported branch encoding at {address:#x}")
    return address + 6 + struct.unpack_from("<i", raw, 2)[0]


def verify_relocations(relocations: dict[int, tuple[int, int]]) -> None:
    expected = {
        0x64DF488: (8, 0x160BEE0),
        0x64DFA60: (8, 0x6500098),
        0x64DFA68: (8, 0x5CADD50),
    }
    for slot, result in expected.items():
        require(relocations.get(slot) == result, f"unexpected RELATIVE relocation at {slot:#x}")


def select_from_samples(samples: list[int]) -> int:
    """Model the observed predicate order from successive effective word reads."""
    cursor = iter(samples)
    first = next(cursor)
    if first & 0x80000:
        second = next(cursor)
        if second & 0x2000000:
            return 4
    third = next(cursor)
    if third & 0x8000:
        return 3
    fourth = next(cursor)
    return 1 + ((fourth >> 10) & 1)


def verify_spans(data: bytes, sections: list[dict], fdes: list[dict], rows: list[dict[str, str]]) -> dict[int, bytes]:
    spans = parse_rows(data, sections, fdes, rows)
    roles = [row["role"] for row in rows]
    require(roles.count("selector") == 46, "expected all 46 selector instructions")
    require(roles.count("root-caller") == 2, "expected selector call and result store")
    require(roles.count("fallback-provider-entry") == 3, "expected CPUID provider entry witnesses")
    required = {
        0x160BEE0: bytes.fromhex("53"),
        0x160BEE1: bytes.fromhex("488b1d783bed04"),
        0x160BEF0: bytes.fromhex("a900000800"),
        0x160BF01: bytes.fromhex("f7c100000002"),
        0x160BF13: bytes.fromhex("6685c9"),
        0x160BF20: bytes.fromhex("c1e80a"),
        0x160BF23: bytes.fromhex("83e001"),
        0x160BF26: bytes.fromhex("fec0"),
        0x160BF29: bytes.fromhex("c3"),
        0x160BF2A: bytes.fromhex("ff15383bed04"),
        0x160BF39: bytes.fromhex("ff15293bed04"),
        0x160BF4B: bytes.fromhex("ff15173bed04"),
        0x160BF60: bytes.fromhex("ff15023bed04"),
        0x41C52D8: bytes.fromhex("ff15aaa13102"),
        0x41C5367: bytes.fromhex("888424fb000000"),
        0x5CADD61: bytes.fromhex("31c0"),
        0x5CADD63: bytes.fromhex("31c9"),
        0x5CADD68: bytes.fromhex("0fa2"),
    }
    for address, expected in required.items():
        require(spans.get(address) == expected, f"required instruction differs at {address:#x}")

    branches = {
        0x160BEEE: 0x160BF2A,
        0x160BEF5: 0x160BF09,
        0x160BEFD: 0x160BF4B,
        0x160BF07: 0x160BF5E,
        0x160BF0F: 0x160BF39,
        0x160BF16: 0x160BF5E,
        0x160BF1E: 0x160BF60,
        0x160BF35: 0x160BEF7,
        0x160BF37: 0x160BF09,
        0x160BF47: 0x160BF18,
        0x160BF49: 0x160BF5E,
        0x160BF5C: 0x160BF09,
        0x160BF66: 0x160BF20,
    }
    for address, expected in branches.items():
        require(branch_target(address, spans[address]) == expected, f"branch target differs at {address:#x}")

    require(rip_target(0x160BEE1, spans[0x160BEE1]) == 0x64DFA60, "selector cell slot edge changed")
    for address in (0x160BF2A, 0x160BF39, 0x160BF4B, 0x160BF60):
        require(rip_target(address, spans[address]) == 0x64DFA68, f"fallback call edge differs at {address:#x}")
    require(rip_target(0x41C52D8, spans[0x41C52D8]) == 0x64DF488, "root caller selector slot edge changed")
    return spans


def verify() -> dict:
    data = TARGET.read_bytes()
    require(hashlib.sha256(data).hexdigest() == TARGET_SHA256, "node #115 digest mismatch")
    sections, _ = unwind_index(data)
    _, fdes = eh_frame_records(data, sections)
    rows = read_rows()
    spans = verify_spans(data, sections, fdes, rows)
    relocations = relocations_for(data, sections)
    verify_relocations(relocations)
    bss = next(section for section in sections if section["name"] == ".bss")
    require(bss["type"] == 8 and bss["address"] <= 0x6500098 < bss["address"] + bss["size"],
            "selector cell is no longer in zero-fill .bss")
    require(select_from_samples([0x80000, 0x2000000]) == 4, "selector branch-4 control failed")
    require(select_from_samples([0, 0x8000]) == 3, "selector branch-3 control failed")
    require(select_from_samples([0, 0, 0x400]) == 2, "selector branch-2 control failed")
    require(select_from_samples([0, 0, 0]) == 1, "selector branch-1 control failed")
    require(select_from_samples([0x80000, 0, 0, 0x400]) == 2, "selector fallthrough priority control failed")
    return {
        "target_sha256": TARGET_SHA256,
        "selector_fde": ["0x160bee0", "0x160bf68"],
        "selector_instruction_count": sum(row["role"] == "selector" for row in rows),
        "authenticated_instruction_rows": len(spans),
        "selector_call_site": "0x41c52d8",
        "selector_result_context_offset": "0x6b",
        "cell_address": "0x6500098",
        "fallback_provider": "0x5cadd50",
        "fallback_entry_executes_cpuid": True,
        "checked_predicate_bits": {"bit_19": "0x80000", "bit_25": "0x2000000", "bit_15": "0x8000", "bit_10": "0x400"},
        "stable_sample_selector_values": [1, 2, 3, 4],
        "runtime_execution": False,
    }


def self_test() -> dict:
    result = verify()
    data = TARGET.read_bytes()
    sections, _ = unwind_index(data)
    _, fdes = eh_frame_records(data, sections)
    rows = read_rows()
    bad_rows = [dict(row) for row in rows]
    changed = next(row for row in bad_rows if int(row["va"], 16) == 0x160BEF0)
    changed["bytes"] = "a900000400"
    try:
        verify_spans(data, sections, fdes, bad_rows)
    except ValueError:
        pass
    else:
        raise ValueError("altered selector-mask control was accepted")
    bad_relocations = relocations_for(data, sections)
    bad_relocations[0x64DFA68] = (8, 0x5CADD51)
    try:
        verify_relocations(bad_relocations)
    except ValueError:
        pass
    else:
        raise ValueError("altered provider-relocation control was accepted")
    result["negative_controls"] = ["changed selector mask rejected", "changed provider relocation rejected"]
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    result = self_test() if args.self_test else verify()
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
