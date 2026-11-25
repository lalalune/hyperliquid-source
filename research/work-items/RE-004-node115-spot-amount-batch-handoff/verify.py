#!/usr/bin/env python3
"""Verify a static #115 spot-amount-to-batch-consumer handoff.

Reads the pinned ELF as data only. It never executes or emulates captured code.
"""
from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

TARGET = ROOT / "artifacts/node/115/hl-node"
SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

# Complete unwind-described extents used by the bounded call/dataflow trace.
FDES = {
    0x2C2E230: 0x2C2E7D2,
    0x22E5C90: 0x22E617A,
    0x22E81C0: 0x22E8382,
    0x2D36860: 0x2D3764C,
    0x22E5090: 0x22E537D,
    0x241A3C0: 0x241B097,
    0x162A9A0: 0x162AB02,
}

# Address, exact instruction bytes, short observation. Addresses are ELF VAs.
WITNESSES = (
    (0x2C2E5B6, "e8d5766bff", "order-value gate call"),
    (0x2C2E5BB, "66817c2410a201", "success-tag comparison"),
    (0x2C2E5C2, "0f85f1000000", "non-success branch"),
    (0x2C2E5DB, "e8e09b6bff", "conditional next-stage call"),
    (0x22E829C, "488dbc24c0000000", "output slot for next-stage call"),
    (0x22E82A4, "488d542420", "staged argument record"),
    (0x22E82A9, "e8b2e5a400", "call into amount producer"),
    (0x22E82CA, "e8f1201300", "call into batch consumer"),
    (0x2D36A84, "e807e65aff", "decimal-conversion caller call"),
    (0x2D36A89, "0fb7842410020000", "conversion result tag read"),
    (0x2D36A9C, "488b8c2418020000", "conversion result plus-eight read"),
    (0x2D36BB3, "ff15bfa37a03", "indirect helper call"),
    (0x2D36F1C, "48c784241002000004000000", "record tag written before append"),
    (0x2D36F28, "4c8b7c2410", "vector header loaded"),
    (0x2D36F43, "4869fbc8020000", "record stride multiplication"),
    (0x2D36F5B, "ff15a7857a03", "record append copy slot"),
    (0x2D36F61, "48ffc3", "vector length increment"),
    (0x241A3C0, "55415741564155415453", "batch consumer entry"),
    (0x241A3D1, "488b07", "batch header first word read"),
    (0x241A3DC, "48c70700000000", "batch header reset"),
    (0x241A3FB, "4869f9c8020000", "consumer record stride"),
    (0x241A4A7, "4983fc0b", "special record tag comparison"),
    (0x241A4D8, "41ffd6", "special record indirect call"),
    (0x162A9A0, "50448b06", "indirect helper begins with output/input reads"),
    (0x162AA93, "44890789770448894708", "helper writes output fields at plus zero, four and eight"),
)

CALLS = {
    0x2C2E5B6: 0x22E5C90,
    0x2C2E5DB: 0x22E81C0,
    0x22E82A9: 0x2D36860,
    0x22E82CA: 0x241A3C0,
    0x2D36A84: 0x22E5090,
}


def _text_map(data: bytes):
    matches = [s for s in sections(data) if s["name"] == ".text"]
    if len(matches) != 1 or matches[0]["type"] == 8:
        raise ValueError("expected one file-backed .text section")
    return matches[0]


def _read(data: bytes | bytearray, text: dict, va: int, size: int) -> bytes:
    if not text["address"] <= va or va + size > text["address"] + text["size"]:
        raise ValueError(f"VA outside .text: {va:#x}")
    off = text["offset"] + va - text["address"]
    return bytes(data[off:off + size])


def _verify_witnesses(data: bytes | bytearray, text: dict) -> int:
    for va, encoded, label in WITNESSES:
        expected = bytes.fromhex(encoded)
        actual = _read(data, text, va, len(expected))
        if actual != expected:
            raise ValueError(f"witness changed: {label} at {va:#x}")
    return len(WITNESSES)


def _relocation_target(data: bytes, secs: list[dict], slot: int) -> int:
    rela, = [s for s in secs if s["name"] == ".rela.dyn" and s["type"] == 4]
    if rela["size"] % 24:
        raise ValueError("unexpected .rela.dyn entry size")
    found = []
    for off in range(rela["offset"], rela["offset"] + rela["size"], 24):
        r_offset, r_info, addend = struct.unpack_from("<QQq", data, off)
        if r_offset == slot and (r_info & 0xFFFFFFFF) == 8:
            found.append(addend)
    if len(found) != 1:
        raise ValueError(f"expected one RELATIVE relocation at {slot:#x}")
    return found[0]


def _verify_evidence(data: bytes | bytearray, check_identity: bool = True) -> dict:
    if check_identity and hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError("target SHA-256 mismatch")
    secs = sections(data)
    text = _text_map(data)
    _, fdes = eh_frame_records(data, secs)
    for start, end in FDES.items():
        matches = [f for f in fdes if f["start"] == start]
        if len(matches) != 1 or matches[0]["end"] != end:
            raise ValueError(f"FDE extent mismatch at {start:#x}")
    witness_count = _verify_witnesses(data, text)
    call_count = 0
    for site, target in CALLS.items():
        inst = _read(data, text, site, 5)
        if inst[0] != 0xE8 or site + 5 + struct.unpack_from("<i", inst, 1)[0] != target:
            raise ValueError(f"direct call changed at {site:#x}")
        call_count += 1
    if _relocation_target(data, secs, 0x64E0F78) != 0x162A9A0:
        raise ValueError("normalization-helper relocation changed")

    rejected = 0
    for va, encoded, label in WITNESSES:
        expected = bytes.fromhex(encoded)
        off = text["offset"] + va - text["address"]
        altered = bytearray(data)
        altered[off] ^= 1
        try:
            _verify_witnesses(altered, text)
        except ValueError:
            rejected += 1
        else:
            raise ValueError(f"in-memory corruption survived: {label}")
    return {
        "target_sha256": SHA256,
        "fdes": len(FDES),
        "instruction_witnesses": witness_count,
        "direct_call_edges": call_count,
        "indirect_helper_relocation": "0x64e0f78 -> 0x162a9a0",
        "witness_mutations_rejected": rejected,
        "captured_binary_executed": False,
    }


def run(target: Path = TARGET) -> dict:
    return _verify_evidence(target.read_bytes())


if __name__ == "__main__":
    import json
    print(json.dumps(run(), indent=2, sort_keys=True))
