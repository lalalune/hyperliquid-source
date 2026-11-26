#!/usr/bin/env python3
"""Bind the node #115 fee-schedule validator to its request-validation route."""
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

CALLER_FDE = (0x3C18A80, 0x3C193C5)
VALIDATOR_FDE = (0x36A1C20, 0x36A31FF)
DIRECT_CALL = 0x3C190FB
DIRECT_BYTES = bytes.fromhex("e8208ba8ff")
VALIDATOR = 0x36A1C20
SLOT = 0x64E6B88
SLOT_TARGET = 0x3C18A80
INDIRECT_CALLS = {
    0x28D3A49: bytes.fromhex("ff153931c103"),
    0x5392B0F: bytes.fromhex("ff1573401501"),
    0x539D92F: bytes.fromhex("ff1553921401"),
}
CALLER_FDES = {
    0x28D3A49: (0x28CD7A0, 0x28D8AC4),
    0x5392B0F: (0x538CD30, 0x5397B4D),
    0x539D92F: (0x5397B50, 0x53A296D),
}
STATUS_BYTES = {
    0x3C19100: bytes.fromhex("84c0"),
    0x3C1910A: bytes.fromhex("7429"),
    0x3C1912E: bytes.fromhex("66c703a201"),
    0x3C19135: bytes.fromhex("66c703a100"),
}
INPUT_BYTES = {
    0x3C190E5: bytes.fromhex("488d742460"),
    0x3C190EA: bytes.fromhex("bab0000000"),
    0x3C190EF: bytes.fromhex("4889df"),
    0x3C190F2: bytes.fromhex("ff1510648c02"),
    0x3C190F8: bytes.fromhex("4889df"),
}


class Reject(ValueError):
    pass


def read_va(data: bytes, address: int, size: int) -> bytes:
    matches = [s for s in sections(data)
               if s["type"] != 8 and s["address"] <= address
               and address + size <= s["address"] + s["size"]]
    if len(matches) != 1:
        raise Reject(f"no unique file-backed mapping at {address:#x}")
    section = matches[0]
    offset = section["offset"] + address - section["address"]
    return data[offset:offset + size]


def relative_relocations(data: bytes) -> dict[int, int]:
    result = {}
    for section in sections(data):
        if section["type"] != 4:
            continue
        if section["size"] % 24:
            raise Reject(f"truncated RELA section {section['name']}")
        for offset in range(section["offset"], section["offset"] + section["size"], 24):
            where, info, addend = struct.unpack_from("<QQq", data, offset)
            if info & 0xFFFFFFFF == 8:
                result[where] = addend
    return result


def indirect_slot_calls(data: bytes, slot: int) -> list[int]:
    text = next(section for section in sections(data) if section["name"] == ".text")
    code = data[text["offset"]:text["offset"] + text["size"]]
    sites = []
    cursor = 0
    while True:
        cursor = code.find(b"\xff\x15", cursor)
        if cursor < 0:
            return sites
        if cursor + 6 <= len(code):
            target = text["address"] + cursor + 6 + struct.unpack_from("<i", code, cursor + 2)[0]
            if target == slot:
                sites.append(text["address"] + cursor)
        cursor += 1


def direct_call_xrefs(data: bytes, target: int) -> list[int]:
    text = next(section for section in sections(data) if section["name"] == ".text")
    code = data[text["offset"]:text["offset"] + text["size"]]
    sites = []
    cursor = 0
    while True:
        cursor = code.find(b"\xe8", cursor)
        if cursor < 0:
            return sites
        if cursor + 5 <= len(code):
            destination = text["address"] + cursor + 5 + struct.unpack_from("<i", code, cursor + 1)[0]
            if destination == target:
                sites.append(text["address"] + cursor)
        cursor += 1


def verify_facts(data: bytes, *, check_digest: bool = True) -> dict:
    digest = hashlib.sha256(data).hexdigest()
    if check_digest and digest != SHA256:
        raise Reject(f"target SHA-256 mismatch: {digest}")
    _, fdes, _ = fde_extents(data)

    def require_fde(address: int, expected: tuple[int, int]) -> None:
        matches = [(row["start"], row["end"]) for row in fdes
                   if row["start"] <= address < row["end"]]
        if matches != [expected]:
            raise Reject(f"unexpected unwind extent at {address:#x}: {matches}")

    require_fde(DIRECT_CALL, CALLER_FDE)
    require_fde(VALIDATOR, VALIDATOR_FDE)
    for callsite, expected in CALLER_FDES.items():
        require_fde(callsite, expected)

    raw = read_va(data, DIRECT_CALL, len(DIRECT_BYTES))
    if raw != DIRECT_BYTES:
        raise Reject("direct validator call bytes changed")
    target = DIRECT_CALL + len(raw) + struct.unpack_from("<i", raw, 1)[0]
    if target != VALIDATOR:
        raise Reject("direct call no longer targets the fee-schedule validator")
    if direct_call_xrefs(data, VALIDATOR) != [DIRECT_CALL]:
        raise Reject("raw direct-call xref set changed")

    for address, expected in STATUS_BYTES.items():
        if read_va(data, address, len(expected)) != expected:
            raise Reject(f"status/result anchor changed at {address:#x}")
    for address, expected in INPUT_BYTES.items():
        if read_va(data, address, len(expected)) != expected:
            raise Reject(f"validator input setup changed at {address:#x}")

    if indirect_slot_calls(data, SLOT) != sorted(INDIRECT_CALLS):
        raise Reject("indirect slot callsite set changed")
    for address, expected in INDIRECT_CALLS.items():
        if read_va(data, address, len(expected)) != expected:
            raise Reject(f"indirect caller bytes changed at {address:#x}")
    if relative_relocations(data).get(SLOT) != SLOT_TARGET:
        raise Reject("relative relocation no longer binds the validator-caller slot")

    return {
        "target_sha256": digest,
        "direct_validator_call": {
            "callsite": hex(DIRECT_CALL), "target": hex(VALIDATOR),
            "caller_fde_unwind_range": [hex(v) for v in CALLER_FDE],
            "validator_fde_unwind_range": [hex(v) for v in VALIDATOR_FDE],
            "raw_direct_call_xrefs": 1,
        },
        "validator_caller_registration": {
            "relative_slot": hex(SLOT), "relocated_callee": hex(SLOT_TARGET),
            "indirect_calls": [
                {"callsite": hex(site), "caller_fde_unwind_range": [hex(v) for v in CALLER_FDES[site]]}
                for site in sorted(INDIRECT_CALLS)
            ],
        },
        "result_observation": {
            "source_pointer_setup": "&[rsp+0x60] in RSI at 0x3c190e5",
            "byte_count_setup": "0xb0 in EDX at 0x3c190ea",
            "preceding_indirect_helper_slot": "0x64df508 at 0x3c190f2",
            "test_al": "0x3c19100", "false_branch": "0x3c19135",
            "true_status_store": "0x1a2 at 0x3c1912e",
            "false_status_store": "0xa1 at 0x3c19135",
        },
        "captured_binary_executed": False,
        "maker_taker_labels_recovered": False,
        "trade_fee_to_ledger_composition_proven": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, default=TARGET)
    args = parser.parse_args()
    print(json.dumps(verify_facts(args.target.read_bytes()), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
