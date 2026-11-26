#!/usr/bin/env python3
"""Bind node #115 fee-credit indirect callers to their relocated slot."""
from __future__ import annotations

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
CALLEE_FDE = (0x3C10000, 0x3C1128E)
SLOT = 0x64E5B60
CALLEE = 0x3C10000
CALLS = {
    0x241ABCA: bytes.fromhex("ff1590af0c04"),
    0x593C633: bytes.fromhex("ff152795ba00"),
    0x593D2C3: bytes.fromhex("ff159788ba00"),
}
CALLER_FDES = {
    0x241ABCA: (0x241A3C0, 0x241B097),
    0x593C633: (0x593BE40, 0x593CAC6),
    0x593D2C3: (0x593CAD0, 0x593D756),
}
SETUP = {
    0x241ABCA: {
        0x241ABB5: bytes.fromhex("488b7c2428"),
        0x241ABBA: bytes.fromhex("488db42460020000"),
        0x241ABC2: bytes.fromhex("4489fa"),
        0x241ABC5: bytes.fromhex("488b4c2468"),
    },
    0x593C633: {
        0x593C61F: bytes.fromhex("488b7c2428"),
        0x593C624: bytes.fromhex("488db42460020000"),
        0x593C62C: bytes.fromhex("89da"),
        0x593C62E: bytes.fromhex("488b4c2468"),
    },
    0x593D2C3: {
        0x593D2AF: bytes.fromhex("488b7c2428"),
        0x593D2B4: bytes.fromhex("488db42460020000"),
        0x593D2BC: bytes.fromhex("89da"),
        0x593D2BE: bytes.fromhex("488b4c2468"),
    },
}


class Reject(ValueError):
    """Raised when a bound target fact no longer matches."""


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


def slot_calls(data: bytes, slot: int) -> list[int]:
    text = next(s for s in sections(data) if s["name"] == ".text")
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

    require_fde(CALLEE, CALLEE_FDE)
    for site, expected in CALLER_FDES.items():
        require_fde(site, expected)
        raw = read_va(data, site, 6)
        if raw != CALLS[site]:
            raise Reject(f"indirect-call bytes changed at {site:#x}")
        destination = site + 6 + struct.unpack_from("<i", raw, 2)[0]
        if destination != SLOT:
            raise Reject(f"indirect call no longer targets slot at {site:#x}")
        for address, expected_bytes in SETUP[site].items():
            if read_va(data, address, len(expected_bytes)) != expected_bytes:
                raise Reject(f"argument setup changed at {address:#x}")

    sites = sorted(CALLS)
    if slot_calls(data, SLOT) != sites:
        raise Reject("raw .text slot-call candidate set changed")
    if relative_relocations(data).get(SLOT) != CALLEE:
        raise Reject("relative relocation no longer binds the slot to the callee")

    return {
        "target_sha256": digest,
        "callee_fde_unwind_range": [hex(v) for v in CALLEE_FDE],
        "registration_slot": hex(SLOT),
        "relative_relocation_target": hex(CALLEE),
        "indirect_call_sites": [
            {
                "site": hex(site),
                "caller_fde_unwind_range": [hex(v) for v in CALLER_FDES[site]],
                "raw_call_bytes": CALLS[site].hex(),
                "argument_setup": {
                    hex(address): code.hex() for address, code in SETUP[site].items()
                },
            }
            for site in sites
        ],
        "raw_text_slot_call_candidates": len(slot_calls(data, SLOT)),
        "captured_binary_executed": False,
        "source_level_caller_roles_identified": False,
        "fee_tier_to_ledger_composition_proven": False,
    }


def main() -> None:
    print(json.dumps(verify_facts(TARGET.read_bytes()), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
