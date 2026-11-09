#!/usr/bin/env python3
"""Verify selected #115 EIP-712 domain-string byte and FDE observations."""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

EXPECTED_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
START, END = 0x169E950, 0x169F713
CODE = {
    0x169E988: "48b832446f6d61696e28",
    0x169E997: "48b8454950373132446f",
    0x169EA54: "48b8737472696e67206e",
    0x169EA62: "41c7441c076e616d65",
    0x169EC15: "48b82076657273696f6e",
    0x169EC24: "48b8737472696e672076",
    0x169EDF1: "48b820636861696e4964",
    0x169EE00: "48b875696e7432353620",
    0x169EEE0: "0f10051bc9ddfe",
    0x169EEED: "0f100505c9ddfe",
}


def file_offset(data, va, size, *, required_flags=None):
    matches = [s for s in sections(data)
               if s["type"] != 8 and s["address"] <= va
               and va + size <= s["address"] + s["size"]
               and (required_flags is None or s["flags"] & required_flags)]
    if len(matches) != 1:
        raise ValueError(f"VA range is not uniquely file-backed: {va:#x}+{size:#x}")
    sec = matches[0]
    return sec["offset"] + va - sec["address"]


def observed_bytes(data):
    code = dict(CODE)
    code.update({
        0x169EFC4: "48b86279746573333220",
        0x169EFD2: "43c744340873616c74",
        0x169F07C: "41c6040429",
        0x169EE8D: "41807f5800",
        0x169EF76: "41807f6d00",
    })
    rows = []
    for address, expected_hex in sorted(code.items()):
        expected = bytes.fromhex(expected_hex)
        actual = data[file_offset(data, address, len(expected), required_flags=4):][:len(expected)]
        if actual != expected:
            raise ValueError(f"code-byte mismatch at {address:#x}")
        rows.append({"address": hex(address), "bytes": actual.hex()})
    rodata = file_offset(data, 0x47B7F9, 25)
    literal = data[rodata:rodata + 25]
    if literal != b"address verifyingContract":
        raise ValueError("verifyingContract data literal mismatch at 0x47b7f9")
    return rows, literal.decode("ascii")


def collect(binary):
    data = binary.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA256:
        raise ValueError(f"unexpected target SHA-256: {digest}")
    if data[:6] != b"\x7fELF\x02\x01":
        raise ValueError("expected ELF64 little-endian target")
    _, fdes = eh_frame_records(data)
    selected = [fde for fde in fdes if fde["start"] == START]
    if len(selected) != 1 or selected[0]["end"] != END:
        raise ValueError("expected one FDE extent [0x169e950, 0x169f713)")
    byte_rows, literal = observed_bytes(data)
    return {
        "target_sha256": digest,
        "target_executed": False,
        "coordinate_system": "ELF virtual address, pre-load-bias",
        "fde_extent": {"start": hex(START), "end": hex(END), "size": END - START,
                       "validated_function_boundary": False},
        "code_anchors": byte_rows,
        "rodata_literal": {"address": "0x47b7f9", "bytes": literal},
        "limitations": ["caller and input ABI not recovered",
                        "indirect-call runtime bindings not resolved",
                        "no domain value or digest semantics inferred"],
    }


if __name__ == "__main__":
    path = Path(sys.argv[1]) if len(sys.argv) == 2 else ROOT / "artifacts/node/115/hl-node"
    print(json.dumps(collect(path), indent=2, sort_keys=True))
