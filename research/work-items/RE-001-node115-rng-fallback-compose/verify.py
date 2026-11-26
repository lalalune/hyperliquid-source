#!/usr/bin/env python3
"""Verify the node #115 RNG policy/fallback composition without executing the target."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PIN = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=True)


def verify(target: Path) -> dict:
    records = json.loads((HERE / "records.json").read_text(encoding="utf-8"))
    if records["target_sha256"] != PIN or records["issue"] != 3906:
        raise ValueError("composition record identity changed")

    contract = run([
        sys.executable,
        str(ROOT / "research/work-items/RE-001-node115-rng-refill-contract/verify.py"),
        "--target",
        str(target),
    ])
    native = json.loads(contract.stdout)
    if (
        native["target_sha256"] != PIN
        or len(native["semantic_corruptions_rejected"]) != 13
    ):
        raise ValueError("prior target-bound refill contract did not verify")

    rustup = shutil.which("rustup")
    if rustup is None:
        raise RuntimeError("rustup is required for the pinned Rust 1.95 reference comparison")
    cargo = run([
        rustup,
        "run",
        "1.95.0",
        "cargo",
        "run",
        "--locked",
        "--offline",
        "--release",
        "--manifest-path",
        str(HERE / "reference/Cargo.toml"),
    ])
    comparison = json.loads(cargo.stdout.strip().splitlines()[-1])
    expected = records["comparison"]
    for key in (
        "cases",
        "wrong_rounds_detected",
        "wrong_counter_detected",
        "wrong_stream_detected",
        "wrong_key_detected",
        "captured_target_executed",
    ):
        if comparison[key] != expected[key]:
            raise ValueError(f"reference comparison mismatch: {key}")
    if comparison["words"] != expected["cases"] * expected["words_per_case"]:
        raise ValueError("reference word count mismatch")
    return {
        "issue": 3906,
        "target_sha256": PIN,
        "native_refill_contract": native,
        "independent_policy_comparison": comparison,
        "scope": "selected four-block fallback after branch selection; no captured target execution",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", type=Path, default=ROOT / "artifacts/node/115/hl-node")
    parser.add_argument("--write", action="store_true", help="write verification.json")
    args = parser.parse_args()
    result = verify(args.target)
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.write:
        (HERE / "verification.json").write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
