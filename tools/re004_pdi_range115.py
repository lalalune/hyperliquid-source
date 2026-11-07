#!/usr/bin/env python3
"""Verify the selected node115 PDI range evidence and Rust arithmetic cases."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "artifacts/node/115/hl-node"
PACKET = ROOT / "research/work-items/RE-004-node115-pdi-range"
CASES = PACKET / "pdi-range-vectors.tsv"

TARGET_SIZE = 105_896_032
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
MAX = (1 << 64) - 1
MAX_COUNT = (1 << 60) - 1
MULTIPLIER = 10_000
BODIES = (
    ("range", 0x22B2160, 312, "9d5a5e84ae58cbf70584e42af0321270acd95aca7af1edf7e69a8cfb8707ce19"),
    ("caller", 0x2912750, 2585, "827bd25e4149df28194078ff2dcae48637aaac538ec080d16a6acf36d70d7669"),
)
WINDOWS = (
    (
        "range_and_admission",
        0x22B2175,
        "4c89eb4c29e3480f42d84c8d3cdd000000004889d948c1e93d0f95c148baf8ffffffff"
        "ffff7f4939d70f97c208ca740c4889c74c89feff15e7c22204",
    ),
    (
        "checked_iteration",
        0x22B21F0,
        "b81027000048f76650704c498d14044801ca4839c2724f498914ce48ffc14c89c04801"
        "c875da",
    ),
    (
        "overflow_failure",
        0x22B2247,
        "488d3da2111904ff151cc62204eb0d488d3d93111904ff15bdc22204",
    ),
)
EXPECTED_CASES = 49


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def evaluate(start: int, end: int, base: int, index: int) -> tuple[str, str]:
    count = max(end - start, 0)
    if count > MAX_COUNT:
        return "range", ""
    if index >= count:
        return "out_of_range", ""
    product = base * MULTIPLIER
    if product > MAX:
        return "multiply", ""
    value = product + start + index
    if value > MAX:
        return "add", ""
    return "ok", str(value)


def verify_binary(data: bytes, expected_sha256: str = TARGET_SHA256) -> dict[str, int]:
    if len(data) != TARGET_SIZE:
        raise ValueError("wrong node115 size")
    if _sha256(data) != expected_sha256:
        raise ValueError("wrong node115 digest")
    for name, offset, size, expected in BODIES:
        body = data[offset : offset + size]
        if len(body) != size or _sha256(body) != expected:
            raise ValueError(f"wrong {name} FDE body")
    verify_windows(data)
    return {"body_bytes": sum(body[2] for body in BODIES), "selected_windows": len(WINDOWS)}


def verify_windows(data: bytes) -> None:
    for label, offset, expected_hex in WINDOWS:
        expected = bytes.fromhex(expected_hex)
        if data[offset : offset + len(expected)] != expected:
            raise ValueError(f"wrong selected window: {label}")


def verify_cases(text: str) -> int:
    reader = csv.DictReader(io.StringIO(text), delimiter="\t")
    if reader.fieldnames != ["start", "end", "base", "index", "result", "value"]:
        raise ValueError("wrong case columns")
    rows = 0
    for row in reader:
        values = [int(row[name]) for name in ("start", "end", "base", "index")]
        if any(value < 0 or value > MAX for value in values):
            raise ValueError(f"value outside u64: {row}")
        expected = evaluate(*values)
        if (row["result"], row["value"]) != expected:
            raise ValueError(f"case mismatch: {row}")
        rows += 1
    if rows != EXPECTED_CASES:
        raise ValueError(f"wrong case count: expected {EXPECTED_CASES}, got {rows}")
    return rows


def verify_records() -> None:
    records = json.loads((PACKET / "records.json").read_text())
    if records["target_sha256"] != TARGET_SHA256:
        raise ValueError("wrong records target")
    selected = {(row["start"], row["end"]): row["sha256"] for row in records["windows"]}
    for name, offset, size, expected in BODIES:
        va = offset + 0x1000
        end = va + size
        if selected.get((hex(va), hex(end))) != expected:
            raise ValueError(f"records mismatch: {name}")


def verify(data: bytes | None = None, cases: str | None = None) -> dict[str, int]:
    binary = TARGET.read_bytes() if data is None else data
    case_text = CASES.read_text(encoding="ascii") if cases is None else cases
    verify_records()
    metrics = verify_binary(binary)
    metrics["cases"] = verify_cases(case_text)
    return metrics


def main() -> int:
    try:
        metrics = verify()
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"re004_pdi_range115: {error}", file=sys.stderr)
        return 1
    print(f"target_sha256={TARGET_SHA256}")
    print(f"fde_body_bytes={metrics['body_bytes']}")
    print(f"selected_windows={metrics['selected_windows']}")
    print(f"cases={metrics['cases']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
