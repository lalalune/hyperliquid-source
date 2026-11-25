#!/usr/bin/env python3
"""Verify two #115 indirect exchange-to-fee-handler call edges."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))

from elf_index import sections  # noqa: E402
from fde_extents import fde_extents  # noqa: E402

TARGET = ROOT / "artifacts/node/115/hl-node"
SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

# The extents are unwind ranges, not asserted source-level function bounds.
CALLERS = {
    "fee_handler": {
        "call": 0x2419EE5,
        "fde": (0x2419810, 0x241A3C0),
        "slot": 0x64E5B40,
        "callee": 0x44896F0,
        "arguments": (
            (0x2419ED1, bytes.fromhex("4c89ef")),
            (0x2419ED4, bytes.fromhex("488db424f0000000")),
            (0x2419EDC, bytes.fromhex("8b542404")),
            (0x2419EE0, bytes.fromhex("488b4c2478")),
        ),
        "call_bytes": bytes.fromhex("ff1555bc0c04"),
    },
    "spot_fee_handler": {
        "call": 0x241ABCA,
        "fde": (0x241A3C0, 0x241B097),
        "slot": 0x64E5B60,
        "callee": 0x3C10000,
        "arguments": (
            (0x241ABB5, bytes.fromhex("488b7c2428")),
            (0x241ABBA, bytes.fromhex("488db42460020000")),
            (0x241ABC2, bytes.fromhex("4489fa")),
            (0x241ABC5, bytes.fromhex("488b4c2468")),
        ),
        "call_bytes": bytes.fromhex("ff1590af0c04"),
    },
}


class Reject(ValueError):
    pass


def read_va(data: bytes, address: int, size: int) -> bytes:
    matches = [s for s in sections(data)
               if s["type"] != 8 and s["address"] <= address
               and address + size <= s["address"] + s["size"]]
    if len(matches) != 1:
        raise Reject(f"no unique file-backed mapping at {address:#x}")
    sec = matches[0]
    off = sec["offset"] + address - sec["address"]
    return data[off:off + size]


def relative_relocations(data: bytes) -> dict[int, int]:
    result: dict[int, int] = {}
    for sec in sections(data):
        if sec["type"] != 4:
            continue
        if sec["size"] % 24:
            raise Reject(f"truncated relocation section {sec['name']}")
        start = sec["offset"]
        end = start + sec["size"]
        for slot, info, addend in struct.iter_unpack("<QQq", data[start:end]):
            if info & 0xFFFFFFFF == 8:
                result[slot] = addend
    return result


def fde_rows(data: bytes) -> list[dict]:
    _, rows, _ = fde_extents(data)
    return rows


def verify_facts(data: bytes, *, check_digest: bool = True) -> dict:
    digest = hashlib.sha256(data).hexdigest()
    if check_digest and digest != SHA256:
        raise Reject(f"target SHA-256 mismatch: {digest}")
    relocs = relative_relocations(data)
    rows = fde_rows(data)
    verified = {}
    for name, item in CALLERS.items():
        lo, hi = item["fde"]
        matches = [row for row in rows if row["start"] == lo and row["end"] == hi]
        if len(matches) != 1 or not lo <= item["call"] < hi:
            raise Reject(f"{name}: expected unwind range/callsite changed")
        for address, expected in item["arguments"]:
            if read_va(data, address, len(expected)) != expected:
                raise Reject(f"{name}: call argument setup changed at {address:#x}")
        insn = item["call"]
        raw = read_va(data, insn, len(item["call_bytes"]))
        if raw != item["call_bytes"]:
            raise Reject(f"{name}: indirect call instruction changed")
        displacement = struct.unpack("<i", raw[2:6])[0]
        slot = insn + len(raw) + displacement
        if slot != item["slot"]:
            raise Reject(f"{name}: indirect slot target changed")
        if relocs.get(slot) != item["callee"]:
            raise Reject(f"{name}: slot relocation no longer selects expected callee")
        verified[name] = {
            "caller_fde_unwind_range": [hex(lo), hex(hi)],
            "callsite": hex(insn),
            "indirect_slot": hex(slot),
            "relocated_callee": hex(item["callee"]),
            "argument_setup_anchors": len(item["arguments"]),
        }
    return {
        "target_sha256": digest,
        "captured_binary_executed": False,
        "claim": "two static indirect call edges and register/stack argument setup",
        "callers": verified,
        "semantic_labels_recovered": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", type=Path, default=TARGET)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        result = verify_facts(args.target.read_bytes())
    except (OSError, Reject, ValueError) as exc:
        parser.error(str(exc))
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
