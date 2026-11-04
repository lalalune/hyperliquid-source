#!/usr/bin/env python3
"""Verify the node115 storage-key suffix evidence and all frozen key vectors."""

from __future__ import annotations

import csv
import hashlib
import io
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "artifacts/node/115/hl-node"
VECTORS = ROOT / "research/work-items/RE-011-storage-read-115/key-vectors.tsv"

TARGET_SIZE = 105_896_032
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
BODY_START_VA = 0x3D47D20
BODY_FILE_OFFSET = 0x3D46D20
BODY_SIZE = 411
BODY_SHA256 = "f0e2fe83e9d6268d41a2c15c6423e09fbfcfa6ab5441e0008d0804e992409d91"
EXPECTED_VECTOR_COUNT = 258
PREFIX_HEX = "4573"

WINDOWS = (
    (
        "key_dynamic_prefix",
        0x3D46D2E,
        "488b5e104885db790b31ff4889deff15567779024989d548895c240848897c2410742b"
        "4c8b66084889dfff15227779024885c00f8405010000488904244889c74c89e64889da"
        "ff158e777902eb09b80100000048890424",
    ),
    (
        "key_buffer_size_and_limbs",
        0x3D46D85,
        "4d8b7d184d8b7510498b6d00498b5d08bf34000000ff15e07679024885c00f84b10000"
        "004989c4480fcd480fcb490fce490fcf418b45304189442410410f104520410f110424"
        "4d897c24144d8974241c49895c242449896c242c",
    ),
    (
        "key_join_descriptors",
        0x3D46DDF,
        "488b5c240848895c24184c8b3c244c897c242048895c242848c7442430340000004c"
        "8964243848c744244034000000488d742418ba020000004c8b7424104c89f7e8fb6905"
        "00",
    ),
)

HEX_FIELD = re.compile(r"^[0-9a-f]+$")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hex_bytes(name: str, value: str, expected_length: int | None = None) -> bytes:
    if not value or len(value) % 2 or not HEX_FIELD.fullmatch(value):
        raise ValueError(f"malformed {name}")
    decoded = bytes.fromhex(value)
    if expected_length is not None and len(decoded) != expected_length:
        raise ValueError(f"wrong {name} length")
    return decoded


def verify_binary(data: bytes, expected_sha256: str = TARGET_SHA256) -> dict[str, int]:
    if len(data) != TARGET_SIZE:
        raise ValueError("wrong node115 size")
    if _sha256(data) != expected_sha256:
        raise ValueError("wrong node115 digest")

    body = data[BODY_FILE_OFFSET : BODY_FILE_OFFSET + BODY_SIZE]
    if len(body) != BODY_SIZE:
        raise ValueError("truncated selected FDE body")
    if _sha256(body) != BODY_SHA256:
        raise ValueError("wrong selected FDE body digest")

    verify_windows(data)

    return {
        "body_bytes": BODY_SIZE,
        "selected_windows": len(WINDOWS),
    }


def verify_windows(data: bytes) -> None:
    for label, offset, expected_hex in WINDOWS:
        expected = bytes.fromhex(expected_hex)
        actual = data[offset : offset + len(expected)]
        if actual != expected:
            raise ValueError(f"wrong selected window: {label}")


def verify_vectors(text: str) -> int:
    reader = csv.DictReader(io.StringIO(text), delimiter="\t")
    required = {
        "case",
        "address_hex",
        "little_endian_limbs_hex",
        "suffix_hex",
        "conditional_example_key_hex",
    }
    if reader.fieldnames is None or set(reader.fieldnames) != required:
        raise ValueError("wrong key-vector columns")

    names: set[str] = set()
    rows = 0
    for row in reader:
        case = row["case"]
        if not case or case in names:
            raise ValueError("empty or duplicate key-vector case")
        names.add(case)

        address = _hex_bytes("address", row["address_hex"], 20)
        limb_fields = row["little_endian_limbs_hex"].split(",")
        if len(limb_fields) != 4:
            raise ValueError(f"wrong limb count: {case}")
        limbs = []
        for field in limb_fields:
            _hex_bytes("limb", field, 8)
            limbs.append(int(field, 16))

        suffix = address + b"".join(
            limb.to_bytes(8, "big") for limb in reversed(limbs)
        )
        expected_suffix = _hex_bytes("suffix", row["suffix_hex"], 52)
        if suffix != expected_suffix:
            raise ValueError(f"key suffix mismatch: {case}")

        prefix = bytes.fromhex(PREFIX_HEX)
        expected_key = _hex_bytes(
            "conditional full key", row["conditional_example_key_hex"]
        )
        if prefix + suffix != expected_key:
            raise ValueError(f"conditional full key mismatch: {case}")
        rows += 1

    if rows != EXPECTED_VECTOR_COUNT:
        raise ValueError(
            f"wrong key-vector count: expected {EXPECTED_VECTOR_COUNT}, got {rows}"
        )
    return rows


def verify(data: bytes | None = None, vectors: str | None = None) -> dict[str, int]:
    binary = TARGET.read_bytes() if data is None else data
    vector_text = VECTORS.read_text(encoding="utf-8") if vectors is None else vectors
    metrics = verify_binary(binary)
    metrics["key_vectors"] = verify_vectors(vector_text)
    return metrics


def main() -> int:
    try:
        metrics = verify()
    except (OSError, ValueError) as error:
        print(f"re011_storage_key_suffix115: {error}", file=sys.stderr)
        return 1
    print(f"target_sha256={TARGET_SHA256}")
    print(f"fde_body_bytes={metrics['body_bytes']}")
    print(f"selected_windows={metrics['selected_windows']}")
    print(f"key_vectors={metrics['key_vectors']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
