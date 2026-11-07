#!/usr/bin/env python3
"""Verify the node115 heartbeat ratio/age classification relation."""

from __future__ import annotations

import csv
import hashlib
import io
import math
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "artifacts/node/115/hl-node"
PACKET = ROOT / "research/work-items/RE-008-node115-heartbeat-query-static"
CASES = PACKET / "heartbeat-vectors.tsv"

TARGET_SIZE = 105_896_032
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
BODY_OFFSET = 0x5A2F130
BODY_SIZE = 1194
BODY_SHA256 = "9b2e1d41364bbe9cb2cd815e9d1b2d85cb2b5b06aefdc21bf68ef55098f74bda"
WINDOWS = (
    (
        "denominator",
        0x5A2F28E,
        "f2410f10442418660f57c9660f2ec1660f57d275027b15660f2ec10f8612030000"
        "f2410f10542410f20f5ed0",
    ),
    (
        "ratio_sanitize",
        0x5A2F2BA,
        "66480f7ed148b8ffffffffffffff7f4821c848ba000000000000f0ff4801c248c1ea35"
        "660f57c04885c90f892602000048ffc981faff0300000f832a02000048baffffffff"
        "ffff0f00660f28ca4839d10f832e0200004885c00f8532020000",
    ),
    (
        "ratio_threshold",
        0x5A2F3AF,
        "660f2e55180f8696000000",
    ),
    (
        "age_threshold",
        0x5A2F4B3,
        "f20f5e0d9588a2faf20f58c8660f57c0f20f5fc8660f2e0d418ba2fa7404660f28c1"
        "660f2e051b93a2fa0f8785000000",
    ),
)
EXPECTED_CASES = 1025


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def value(raw: int) -> float:
    return struct.unpack("<d", struct.pack("<Q", raw))[0]


def bits(number: float) -> int:
    return struct.unpack("<Q", struct.pack("<d", number))[0]


def classify(
    found: bool,
    numerator: float,
    denominator: float,
    threshold: float,
    flag: bool,
    age: float,
) -> tuple[str, str]:
    if not found:
        return "missing", "0"
    if denominator == 0.0:
        ratio = 0.0
    elif denominator <= 0.0 or math.isnan(denominator):
        return "error", "-"
    else:
        ratio = numerator / denominator
    if ratio == 0.0 or (ratio > 0.0 and math.isfinite(ratio)):
        cleaned = ratio
    else:
        cleaned = 0.0
    if cleaned > threshold and not flag:
        return "ratio", str(bits(cleaned))
    if age > 180.0:
        return "age", str(bits(age))
    return "skip", "3"


def verify_binary(data: bytes, expected_sha256: str = TARGET_SHA256) -> dict[str, int]:
    if len(data) != TARGET_SIZE:
        raise ValueError("wrong node115 size")
    if _sha256(data) != expected_sha256:
        raise ValueError("wrong node115 digest")
    body = data[BODY_OFFSET : BODY_OFFSET + BODY_SIZE]
    if len(body) != BODY_SIZE or _sha256(body) != BODY_SHA256:
        raise ValueError("wrong heartbeat FDE body")
    verify_windows(data)
    return {"body_bytes": BODY_SIZE, "selected_windows": len(WINDOWS)}


def verify_windows(data: bytes) -> None:
    for label, offset, expected_hex in WINDOWS:
        expected = bytes.fromhex(expected_hex)
        if data[offset : offset + len(expected)] != expected:
            raise ValueError(f"wrong selected window: {label}")


def verify_cases(text: str) -> int:
    reader = csv.DictReader(io.StringIO(text), delimiter="\t")
    if reader.fieldnames != [
        "found",
        "numerator_bits",
        "denominator_bits",
        "threshold_bits",
        "flag",
        "age_bits",
        "result",
        "payload",
    ]:
        raise ValueError("wrong case columns")
    rows = 0
    for row in reader:
        if row["found"] not in ("0", "1") or row["flag"] not in ("0", "1"):
            raise ValueError("non-boolean case flag")
        observed = classify(
            row["found"] == "1",
            value(int(row["numerator_bits"])),
            value(int(row["denominator_bits"])),
            value(int(row["threshold_bits"])),
            row["flag"] == "1",
            value(int(row["age_bits"])),
        )
        if observed != (row["result"], row["payload"]):
            raise ValueError(f"case mismatch: {row}")
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
        print(f"re008_heartbeat_classification115: {error}", file=sys.stderr)
        return 1
    print(f"target_sha256={TARGET_SHA256}")
    print(f"fde_body_bytes={metrics['body_bytes']}")
    print(f"selected_windows={metrics['selected_windows']}")
    print(f"cases={metrics['cases']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
