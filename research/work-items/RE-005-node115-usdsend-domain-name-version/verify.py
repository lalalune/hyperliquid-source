#!/usr/bin/env python3
"""Verify the static UsdSend EIP-712 domain name/version byte path."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
PACKET = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import sections
from fde_extents import eh_frame_records

TARGET = ROOT / "artifacts/node/115/hl-node"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
SIZE = 105_896_032
WRAPPER = (0x44338B0, 0x4433C1B)
NAME_BASE = 0x7D2FE5
NAME_TAIL = 0x7D2FEF
NAME = b"HyperliquidSignTransaction"
VERSION = b"1"
CALL_DOMAIN = 0x443399F
CALL_ACTION = 0x44339EE
DOMAIN_SLOT = 0x64E2178
ACTION_SLOT = 0x64EA890
DOMAIN_TARGET = 0x169E950
ACTION_TARGET = 0x43D2B20


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


class Image:
    def __init__(self, blob: bytes, *, authenticate: bool = True):
        if authenticate:
            require(len(blob) == SIZE, "node #115 size mismatch")
            require(hashlib.sha256(blob).hexdigest() == DIGEST, "node #115 SHA-256 mismatch")
        self.blob = blob
        self.sections = sections(blob)
        _, fdes = eh_frame_records(blob, self.sections)
        self.fdes = [f for f in fdes if (f["start"], f["end"]) == WRAPPER]
        require(len(self.fdes) == 1, "wrapper FDE extent is not unique")

    def read(self, address: int, size: int) -> bytes:
        rows = [s for s in self.sections if s["type"] != 8 and s["flags"] & 2 and s["address"] <= address and address + size <= s["address"] + s["size"]]
        require(len(rows) == 1, f"address range has no unique file-backed section: {address:#x}")
        s = rows[0]
        offset = s["offset"] + address - s["address"]
        return self.blob[offset : offset + size]

    def rela_relative_addend(self, slot: int) -> int:
        found = []
        for s in self.sections:
            if s["name"] != ".rela.dyn" or s["type"] == 8:
                continue
            require(s["size"] % 24 == 0, "malformed .rela.dyn")
            for p in range(s["offset"], s["offset"] + s["size"], 24):
                where, info, addend = struct.unpack_from("<QQq", self.blob, p)
                if where == slot and (info & 0xFFFFFFFF) == 8:
                    found.append(addend)
        require(len(found) == 1, f"relative relocation is not unique at {slot:#x}")
        return found[0]

    def call_slot(self, address: int) -> int:
        insn = self.read(address, 6)
        require(insn[:2] == b"\xff\x15", f"expected RIP-indirect call at {address:#x}")
        return address + 6 + struct.unpack_from("<i", insn, 2)[0]


def verify(blob: bytes, *, authenticate: bool = True) -> dict[str, object]:
    image = Image(blob, authenticate=authenticate)
    require(image.read(0x44338C6, 5) == bytes.fromhex("bf1a000000"), "name allocation size changed")
    require(image.read(0x44338DD, 7) == bytes.fromhex("0f10050bf739fc"), "name-tail load changed")
    require(image.read(0x44338E8, 7) == bytes.fromhex("0f1005f6f639fc"), "name-prefix load changed")
    require(image.read(0x44338F2, 5) == bytes.fromhex("bf01000000"), "version allocation size changed")
    require(image.read(0x443390D, 5) == bytes.fromhex("41c6042431"), "version byte store changed")
    require(image.read(0x4433942, 9) == bytes.fromhex("48c74424681a000000"), "name length field changed")
    require(image.read(0x443394B, 5) == bytes.fromhex("4c897c2470"), "name pointer field changed")
    require(image.read(0x4433950, 9) == bytes.fromhex("48c74424781a000000"), "second name length field changed")
    require(image.read(0x4433959, 12) == bytes.fromhex("48c784248000000001000000"), "name-present field changed")
    require(image.read(0x4433965, 8) == bytes.fromhex("4c89a42488000000"), "version pointer field changed")
    require(image.read(0x443396D, 12) == bytes.fromhex("48c784249000000001000000"), "version length field changed")
    require(image.read(0x4433979, 8) == bytes.fromhex("c684249800000001"), "version-present field changed")
    require(image.read(CALL_DOMAIN, 6)[:2] == b"\xff\x15", "domain callsite changed")
    require(image.read(CALL_ACTION, 6)[:2] == b"\xff\x15", "action callsite changed")
    require(image.call_slot(CALL_DOMAIN) == DOMAIN_SLOT, "domain call no longer uses the recorded slot")
    require(image.call_slot(CALL_ACTION) == ACTION_SLOT, "action call no longer uses the recorded slot")
    require(image.rela_relative_addend(DOMAIN_SLOT) == DOMAIN_TARGET, "domain slot binding changed")
    require(image.rela_relative_addend(ACTION_SLOT) == ACTION_TARGET, "action slot binding changed")

    prefix = image.read(NAME_BASE, 16)
    tail = image.read(NAME_TAIL, 16)
    require(NAME_TAIL == NAME_BASE + 10, "name literal chunks are not adjacent as expected")
    reconstructed = prefix + tail[6:]
    require(reconstructed == NAME, "domain-name bytes do not match the recorded literal")
    require(image.read(0x44338B0, 1) == b"\x41", "wrapper extent start changed")
    return {
        "target_sha256": DIGEST,
        "wrapper_fde_elf_va": [hex(WRAPPER[0]), hex(WRAPPER[1])],
        "wrapper_fde_size_bytes": WRAPPER[1] - WRAPPER[0],
        "domain_name_bytes_hex": NAME.hex(),
        "domain_name": reconstructed.decode("ascii"),
        "domain_version_bytes_hex": VERSION.hex(),
        "domain_version": VERSION.decode("ascii"),
        "domain_call": {"site": hex(CALL_DOMAIN), "slot": hex(DOMAIN_SLOT), "relative_target": hex(DOMAIN_TARGET)},
        "action_call": {"site": hex(CALL_ACTION), "slot": hex(ACTION_SLOT), "relative_target": hex(ACTION_TARGET)},
        "runtime_chain_id_verifying_contract_salt": "not established by this packet",
        "captured_binary_executed": False,
    }


def self_test(blob: bytes) -> None:
    verify(blob)
    image = Image(blob)
    text = next(s for s in image.sections if s["name"] == ".text")
    rodata = next(s for s in image.sections if s["name"] == ".rodata")
    cases = ((text, 0x443390D, 4, "version-byte"), (rodata, NAME_BASE, 0, "name-literal"))
    for section, address, delta, label in cases:
        damaged = bytearray(blob)
        offset = section["offset"] + address - section["address"] + delta
        damaged[offset] ^= 1
        try:
            verify(bytes(damaged), authenticate=False)
        except ValueError:
            continue
        raise AssertionError(f"{label} corruption was not rejected")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    blob = TARGET.read_bytes()
    if args.self_test:
        self_test(blob)
    result = verify(blob)
    text = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    else:
        print(text, end="")


if __name__ == "__main__":
    main()
