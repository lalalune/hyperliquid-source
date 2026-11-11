#!/usr/bin/env python3
"""Verify the node115 DB-hub byte-key lookup evidence."""

from __future__ import annotations

import csv
import hashlib
import io
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "artifacts/node/115/hl-node"
CASES = (
    ROOT
    / "research/work-items/RE-009-node115-db-hub-byte-key-lookup/target-smoke.tsv"
)

TARGET_SIZE = 105_896_032
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
BODY_FILE_OFFSET = 0x1691CA0
BODY_SIZE = 841
BODY_SHA256 = "01f207a1ef95d113cf325e6b26a93e18260f89a6d96269823b1b70f75383be75"
EXPECTED_CASES = 1284

WINDOWS = (
    (
        "root_height_and_count",
        0x1691D0F,
        "498b47184885c00f8450020000498b4f20450fb6e50fb770624889f748f7df48c7c"
        "2ffffffff66662e0f1f840000000000",
    ),
    (
        "scan_equal_and_continue",
        0x1691D40,
        "4c8d04174983f8ff7436440fb64410654d39c4410f9cc1410f9fc04528c848ffc2"
        "4180f80174d9410fb6f085f67425",
    ),
    (
        "descend_and_missing",
        0x1691D80,
        "4889f24883e9010f82df010000488b44d070eb904189ef",
    ),
)

CASE_KEYS = {
    "empty": [],
    "single_zero": [0],
    "single_255": [255],
    "edges": [0, 127, 128, 255],
    "all_bytes": list(range(256)),
    "height_zero_hit": [7, 9],
    "height_zero_miss": [7, 9],
    "high_bits_low_zero": [0, 255],
    "high_bits_low_ff": [0, 255],
}
HEX = re.compile(r"^[0-9a-f]+$")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _scan(keys: list[int], query: int) -> tuple[str, str]:
    byte = query & 0xFF
    for index, key in enumerate(keys):
        if byte > key:
            continue
        if byte == key:
            return "found", str(index)
        return "missing", ""
    return "missing", ""


def verify_binary(data: bytes, expected_sha256: str = TARGET_SHA256) -> dict[str, int]:
    if len(data) != TARGET_SIZE:
        raise ValueError("wrong node115 size")
    if _sha256(data) != expected_sha256:
        raise ValueError("wrong node115 digest")
    body = data[BODY_FILE_OFFSET : BODY_FILE_OFFSET + BODY_SIZE]
    if len(body) != BODY_SIZE or _sha256(body) != BODY_SHA256:
        raise ValueError("wrong selected FDE body")
    verify_windows(data)
    return {"body_bytes": BODY_SIZE, "selected_windows": len(WINDOWS)}


def verify_windows(data: bytes) -> None:
    for label, offset, expected_hex in WINDOWS:
        expected = bytes.fromhex(expected_hex)
        if data[offset : offset + len(expected)] != expected:
            raise ValueError(f"wrong selected window: {label}")


def verify_cases(text: str) -> int:
    reader = csv.DictReader(io.StringIO(text), delimiter="\t")
    if reader.fieldnames != ["case", "height", "query", "result", "value_index"]:
        raise ValueError("wrong case columns")
    rows = 0
    for row in reader:
        case = row["case"]
        if case not in CASE_KEYS:
            raise ValueError(f"unknown case: {case}")
        query = int(row["query"])
        if not 0 <= query <= 0xFFFFFFFF:
            raise ValueError(f"query outside u32: {query}")
        if not HEX.fullmatch(row["height"]) and not row["height"].isdigit():
            raise ValueError(f"malformed height: {row['height']}")
        result, value_index = _scan(CASE_KEYS[case], query)
        if (row["result"], row["value_index"]) != (result, value_index):
            raise ValueError(f"case mismatch: {case} / {query}")
        rows += 1
    if rows != EXPECTED_CASES:
        raise ValueError(f"wrong case count: expected {EXPECTED_CASES}, got {rows}")
    return rows


def verify(data: bytes | None = None, cases: str | None = None) -> dict[str, int]:
    binary = TARGET.read_bytes() if data is None else data
    case_text = CASES.read_text(encoding="ascii") if cases is None else cases
    metrics = verify_binary(binary)
    metrics["cases"] = verify_cases(case_text)
    return metrics


def main() -> int:
    try:
        metrics = verify()
    except (OSError, ValueError) as error:
        print(f"re009_db_hub_lookup115: {error}", file=sys.stderr)
        return 1
    print(f"target_sha256={TARGET_SHA256}")
    print(f"fde_body_bytes={metrics['body_bytes']}")
    print(f"selected_windows={metrics['selected_windows']}")
    print(f"cases={metrics['cases']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
