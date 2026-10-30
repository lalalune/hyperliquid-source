#!/usr/bin/env python3
"""Fail-closed replay for the committed RE-006 evidence packet."""
import hashlib
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import order_book_lifecycle_94 as lifecycle  # noqa: E402


def fail(message):
    print(f"RE-006 verify: FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def main():
    for line in (HERE / "MANIFEST.sha256").read_text().splitlines():
        expected, name = line.split("  ", 1)
        actual = hashlib.sha256((HERE / name).read_bytes()).hexdigest()
        if actual != expected:
            fail(f"{name}: {actual} != {expected}")
    try:
        recomputed = lifecycle.render(lifecycle.scan(lifecycle.TARGET.read_bytes()))
    except (lifecycle.EvidenceError, ValueError) as exc:
        fail(str(exc))
    if recomputed != (HERE / "evidence.json").read_text():
        fail("recomputed evidence.json differs from committed bytes")
    print("RE-006 verify: OK", hashlib.sha256(recomputed.encode()).hexdigest())


if __name__ == "__main__":
    main()
