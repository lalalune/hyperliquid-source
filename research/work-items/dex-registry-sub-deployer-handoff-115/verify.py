#!/usr/bin/env python3
"""Verify the node-115 HIP-3 sub-deployer serializer handoff anchors."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import sections  # noqa: E402
from fde_extents import fde_extents  # noqa: E402


def fail(message: str) -> None:
    raise ValueError(message)


def verify_bytes(data: bytes, records: dict) -> dict:
    digest = hashlib.sha256(data).hexdigest()
    if digest != records["target_sha256"]:
        fail(f"target digest mismatch: {digest}")

    text_sections = [s for s in sections(data) if s["name"] == ".text"]
    if len(text_sections) != 1 or text_sections[0]["type"] == 8:
        fail("expected one file-backed .text section")
    text = text_sections[0]

    _, fdes, _ = fde_extents(data)
    fdes_by_start = {f["start"]: f for f in fdes}
    functions: dict[tuple[int, str], tuple[int, int]] = {}
    for copy in records["copies"]:
        copy_id = copy["copy"]
        for family, function in copy["functions"].items():
            start, end = int(function["start"], 16), int(function["end"], 16)
            fde = fdes_by_start.get(start)
            if fde is None or fde["end"] != end or fde["section"] != ".text":
                fail(f"copy {copy_id} {family}: FDE extent mismatch")
            if start < text["address"] or end > text["address"] + text["size"]:
                fail(f"copy {copy_id} {family}: outside .text")
            offset = text["offset"] + start - text["address"]
            body = data[offset:offset + end - start]
            actual_hash = hashlib.sha256(body).hexdigest()
            if actual_hash != function["sha256"]:
                fail(f"copy {copy_id} {family}: FDE byte hash mismatch")
            functions[(copy_id, family)] = (start, end)

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    verified = 0
    for anchor in records["anchors"]:
        copy_id = anchor["copy"]
        start, end = functions[(copy_id, anchor["family"])]
        address = int(anchor["address"], 16)
        expected = bytes.fromhex(anchor["hex"])
        if not start <= address or address + len(expected) > end:
            fail(f"anchor outside copy {copy_id} {anchor['family']} FDE")
        offset = text["offset"] + address - text["address"]
        actual = data[offset:offset + len(expected)]
        if actual != expected:
            fail(f"instruction-byte mismatch at {address:#x}")
        instructions = list(md.disasm(actual, address))
        if len(instructions) != 1 or instructions[0].size != len(actual):
            fail(f"anchor is not one instruction at {address:#x}")
        insn = instructions[0]
        if insn.mnemonic != anchor["mnemonic"]:
            fail(f"mnemonic mismatch at {address:#x}: {insn.mnemonic}")
        expected_target = anchor.get("target")
        if expected_target is not None:
            if len(insn.operands) != 1 or insn.operands[0].imm != int(expected_target, 16):
                fail(f"direct target mismatch at {address:#x}")
        verified += 1

    if len(records["copies"]) != 3 or len(functions) != 18 or verified != 39:
        fail("packet coverage count mismatch")
    return {"target_sha256": digest, "fde_bodies": len(functions),
            "instruction_anchors": verified, "result": "PASS",
            "scope": "static serializer handoff only"}


def main() -> int:
    target = ROOT / "artifacts/node/115/hl-node"
    records_path = Path(__file__).with_name("records.json")
    result = verify_bytes(target.read_bytes(), json.loads(records_path.read_text()))
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"verification failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
