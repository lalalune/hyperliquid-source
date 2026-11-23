#!/usr/bin/env python3
"""Verify the selected admitted-vote to replay-tracker join from node #115 bytes.

The target is read, never executed. Existing packets provide the complete semantics
of the record body and replay consumer; this verifier pins the new cross-path join.
"""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
import hash_signature_record_115 as base  # noqa: E402


EXPECTED_FDES = {
    0x294FDD0: (0x294FDD0, 0x294FFDE),
    0x2760BC0: (0x2760BC0, 0x27610AC),
    0x54897E0: (0x54897E0, 0x548C8E0),
}

ANCHORS = {
    0x294FDEF: "4c8d6628",             # message +0x28
    0x294FDFC: "f30f6f06",             # first 16 digest bytes
    0x294FE00: "f30f6f4e10",           # second 16 digest bytes
    0x294FEE1: "488db2503e0000",       # state +0x3e50 as tracker
    0x294FEE8: "4c89b424b8000000",     # record +0x8 = message height
    0x294FF0C: "4c89a424b0000000",     # record +0x0 = signature pointer
    0x294FF53: "e8680ce1ff",           # call 0x2760bc0
    0x2760F5D: "e8ae1f1500",           # insert helper 0x28b2f10
    0x548BF2D: "498db424503e0000",     # finalizer uses same owner +0x3e50
    0x548BF4B: "e8e0e06600",           # drain helper 0x5afa030
}

CALLS = {
    0x294FF53: 0x2760BC0,
    0x2760F5D: 0x28B2F10,
    0x548BF4B: 0x5AFA030,
}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def check_image(image):
    for start, bounds in EXPECTED_FDES.items():
        lo, hi, _ = base.body_insns(image, start)
        require((lo, hi) == bounds, f"unexpected FDE for {start:#x}: {(lo, hi)}")
    for va, expected_hex in ANCHORS.items():
        expected = bytes.fromhex(expected_hex)
        offset = image.file_offset(va)
        require(image.data[offset:offset + len(expected)] == expected,
                f"instruction bytes changed at {va:#x}")
    for va, target in CALLS.items():
        insn = image.fetch(va)
        require(insn.key == 0xE8 and insn.target == target,
                f"call target mismatch at {va:#x}")


def main():
    image = base.load_image()
    check_image(image)
    print(f"target {base.SHA256}: 10 byte anchors, 3 call edges, 3 FDEs match")


if __name__ == "__main__":
    main()
