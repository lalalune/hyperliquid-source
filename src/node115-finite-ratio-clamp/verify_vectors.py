#!/usr/bin/env python3
"""Verify frozen Rust test vectors against the digest-bound evidence packet."""

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PACKET = ROOT / "research/work-items/RE-001-node115-finite-ratio-clamp"
RECORDS = PACKET / "records.json"
FIXTURE = Path(__file__).resolve().parent / "target-vectors.tsv"
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def main() -> None:
    records = json.loads(RECORDS.read_text(encoding="utf-8"))
    target = records.get("target", {})
    if target.get("release") != 115 or target.get("sha256") != TARGET_SHA256:
        raise SystemExit("evidence records do not identify the expected node #115 target")

    vectors = records.get("vectors")
    if not isinstance(vectors, list) or len(vectors) != 28:
        raise SystemExit("evidence packet must contain exactly 28 frozen vectors")

    expected = "".join(
        "\t".join(
            str(vector[key])
            for key in ("name", "numerator_bits", "divisor_bits", "status", "xmm0_bits")
        )
        + "\n"
        for vector in vectors
    )
    actual = FIXTURE.read_text(encoding="utf-8")
    if actual != expected:
        raise SystemExit("target-vectors.tsv differs from the evidence packet's records.json")
    print(f"Verified {len(vectors)} Rust test vectors against node #115 evidence {TARGET_SHA256}.")


if __name__ == "__main__":
    main()
