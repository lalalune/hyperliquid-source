#!/usr/bin/env python3
"""Verify the selected node115 display-name decision evidence."""

from __future__ import annotations

import csv
import hashlib
import io
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "artifacts/node/115/hl-node"
VECTORS = ROOT / "research/work-items/RE-010-display-name-path-115/branch-vectors.tsv"

TARGET_SIZE = 105_896_032
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
WRAPPER = (
    0x2391200,
    264,
    "483533a7ffcc753a1eca1d168a2e937f8523919de2a2d23a06e0c453a44be3a5",
)
CORE = (
    0x2C75380,
    860,
    "c62228768dba0728cc302de45383c29ed52c692c394939651959ca7e905dc677",
)
WINDOWS = (
    (
        "wrapper_guard",
        0x2391214,
        "4c8b76104983fe65720f66c74310580148897318e9b50000004d85f67436",
    ),
    (
        "core_bounds",
        0x2C7539A,
        "4c8b69104d85ed746366b8e2004983fd140f878600000066b8e3004983fd03"
        "727c",
    ),
)
EXPECTED_VECTORS = 14


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def classify(length: int, duplicate: bool, blocked: bool) -> tuple[str, str, str, str]:
    if blocked:
        return "prior_rejection", "15", "288", "none"
    if length >= 101:
        return "wrapper_limit", "15", "344", "none"
    if length == 0:
        return "empty", "14", "418", "erase"
    if length > 20:
        return "too_long", "15", "226", "none"
    if length < 3:
        return "too_short", "15", "227", "none"
    if duplicate:
        return "duplicate", "15", "228", "none"
    return "unique", "14", "418", "upsert"


def verify_binary(data: bytes, expected_sha256: str = TARGET_SHA256) -> dict[str, int]:
    if len(data) != TARGET_SIZE:
        raise ValueError("wrong node115 size")
    if _sha256(data) != expected_sha256:
        raise ValueError("wrong node115 digest")
    for name, (offset, size, expected_hash) in (
        ("wrapper", WRAPPER),
        ("core", CORE),
    ):
        body = data[offset : offset + size]
        if len(body) != size or _sha256(body) != expected_hash:
            raise ValueError(f"wrong {name} FDE body")
    verify_windows(data)
    return {
        "body_bytes": WRAPPER[1] + CORE[1],
        "selected_windows": len(WINDOWS),
    }


def verify_windows(data: bytes) -> None:
    for label, offset, expected_hex in WINDOWS:
        expected = bytes.fromhex(expected_hex)
        if data[offset : offset + len(expected)] != expected:
            raise ValueError(f"wrong selected window: {label}")


def verify_vectors(text: str) -> int:
    reader = csv.DictReader(io.StringIO(text), delimiter="\t")
    if reader.fieldnames != [
        "length",
        "duplicate",
        "prior_rejection",
        "predicted_path",
        "outer_tag",
        "result_word",
        "predicted_mutation",
    ]:
        raise ValueError("wrong branch-vector columns")
    rows = 0
    for row in reader:
        length = int(row["length"])
        if not 0 <= length < 1 << 64:
            raise ValueError(f"length outside u64: {length}")
        if row["duplicate"] not in ("0", "1") or row["prior_rejection"] not in ("0", "1"):
            raise ValueError("non-boolean predicate")
        predicted = classify(
            length, row["duplicate"] == "1", row["prior_rejection"] == "1"
        )
        observed = (
            row["predicted_path"],
            row["outer_tag"],
            row["result_word"],
            row["predicted_mutation"],
        )
        if predicted != observed:
            raise ValueError(f"branch-vector mismatch: {row}")
        rows += 1
    if rows != EXPECTED_VECTORS:
        raise ValueError(f"wrong vector count: expected {EXPECTED_VECTORS}, got {rows}")
    return rows


def verify(data: bytes | None = None, vectors: str | None = None) -> dict[str, int]:
    binary = TARGET.read_bytes() if data is None else data
    vector_text = VECTORS.read_text(encoding="ascii") if vectors is None else vectors
    metrics = verify_binary(binary)
    metrics["branch_vectors"] = verify_vectors(vector_text)
    return metrics


def main() -> int:
    try:
        metrics = verify()
    except (OSError, ValueError) as error:
        print(f"re010_display_name_decision115: {error}", file=sys.stderr)
        return 1
    print(f"target_sha256={TARGET_SHA256}")
    print(f"fde_body_bytes={metrics['body_bytes']}")
    print(f"selected_windows={metrics['selected_windows']}")
    print(f"branch_vectors={metrics['branch_vectors']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
