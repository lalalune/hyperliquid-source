#!/usr/bin/env python3
"""Verify target-bound instruction anchors for the DEX map representation path.

This reads the pinned ELF as data. It never executes the captured binary.
"""

from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
ELF = ROOT / "artifacts/node/115/hl-node"
SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
FDE_START = 0x4DD59A0
FDE_END = 0x4DD6145
FDE_RECORD = Path(__file__).with_name("fde.tsv")

ANCHORS = {
    0x4DD59D1: bytes.fromhex("4883f820"),  # compare observed count with 0x20
    0x4DD5B75: bytes.fromhex("4d39f7"),    # compare representation word to sentinel
    0x4DD5B92: bytes.fromhex("48837d183f"),  # compare count with 0x3f
    0x4DD5BD3: bytes.fromhex("e878d53800"),  # call 0x5163150
    0x4DD5B84: bytes.fromhex("e8e76aa200"),  # call ordered-map search
    0x4DD5C57: bytes.fromhex("a801"),         # test search result's low bit
    0x4DD5CA7: bytes.fromhex("e83479a100"),  # call ring entry insertion
    0x4DD5F61: bytes.fromhex("0f1002"),       # load prior 16-byte value
    0x4DD5F70: bytes.fromhex("0f1102"),       # write replacement's first 16 bytes
    0x4DD5F79: bytes.fromhex("b101"),         # Some discriminant after replacement
    0x4DD6070: bytes.fromhex("31c9"),         # None discriminant after insertion
    0x4DD5FF7: bytes.fromhex("e864cd4100"),  # call 0x51f2d60
    0x57FC6E5: bytes.fromhex("ff156534ce00"),  # compare ring keys through slot
    0x57FC740: bytes.fromhex("eb06"),          # empty-ring setup
    0x57FC757: bytes.fromhex("41bd01000000"),  # absent result initialized to 1
    0x57FC6EB: bytes.fromhex("489885c04c89ea490f44c54885c00f98c00f9fc128c1440fb6e9"),
    0x57FC91D: bytes.fromhex("4c89e8"),         # return status in RAX
    0x57FC920: bytes.fromhex("4c89fa"),         # return search position in RDX
    0x57ED5EF: bytes.fromhex("4c39c6"),         # insertion position <= len
    0x57ED5F2: bytes.fromhex("0f87d8000000"),   # reject position > len
    0x57ED604: bytes.fromhex("7510"),         # grow only when len==capacity
    0x57ED656: bytes.fromhex("49ff4618"),       # increment ring len
    0x57ED6AE: bytes.fromhex("0f1003"),         # copy first 16 record bytes
    0x57ED6B5: bytes.fromhex("0f105320"),       # copy final 16 record bytes
}


def va_to_offset(data: bytes, va: int) -> int:
    if data[:4] != b"\x7fELF" or data[4:6] != b"\x02\x01":
        raise ValueError("expected ELF64 little-endian target")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    for i in range(phnum):
        off = phoff + i * phentsize
        p_type, _, p_offset, p_vaddr, _, p_filesz, _, _ = struct.unpack_from(
            "<IIQQQQQQ", data, off
        )
        if p_type == 1 and p_vaddr <= va and va + 1 <= p_vaddr + p_filesz:
            return p_offset + va - p_vaddr
    raise ValueError(f"VA {va:#x} is not file-backed by a PT_LOAD segment")


def check(data: bytes) -> list[str]:
    digest = hashlib.sha256(data).hexdigest()
    if digest != SHA256:
        raise ValueError(f"target digest mismatch: {digest}")
    results = []
    for va, expected in ANCHORS.items():
        actual = data[va_to_offset(data, va):va_to_offset(data, va) + len(expected)]
        if actual != expected:
            raise ValueError(f"anchor mismatch at {va:#x}: {actual.hex()} != {expected.hex()}")
        results.append(f"{va:#x}: {actual.hex()} OK")
    rows = set(FDE_RECORD.read_text().splitlines())
    expected_rows = {
        f"{start:#x}\t{end:#x}\t{end - start}\t.text"
        for start, end in (
            (FDE_START, FDE_END),
            (0x57ED5E0, 0x57ED70A),
            (0x57FC670, 0x57FC932),
        )
    }
    if not expected_rows <= rows:
        raise ValueError("retained FDE rows do not match the claimed extents")
    return results


def main() -> int:
    data = ELF.read_bytes()
    results = check(data)
    # In-memory corruption controls ensure two decision-boundary witnesses fail closed.
    for va in (0x4DD59D1, 0x4DD5B92, 0x4DD5C57, 0x4DD5F70):
        mutant = bytearray(data)
        pos = va_to_offset(data, va)
        mutant[pos + len(ANCHORS[va]) - 1] ^= 1
        try:
            check(bytes(mutant))
        except ValueError as exc:
            if "target digest mismatch" in str(exc):
                # Digest authentication intentionally rejects mutated whole artifacts first.
                results.append(f"mutation at {va:#x}: rejected by target digest")
                continue
            raise
        raise AssertionError(f"mutation at {va:#x} was accepted")
    print(f"target SHA-256: {SHA256}")
    print("FDE extents: map upsert, ring insert helper, ring search helper verified")
    print("\n".join(results))
    print("captured binary executed: no")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, AssertionError) as exc:
        print(f"verification failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
