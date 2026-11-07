#!/usr/bin/env python3
"""Independently recheck retained synthetic digest vectors; no target execution."""
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[3]
version = subprocess.check_output(["openssl", "version"], text=True).strip()
path = ROOT / "src/node115-noop-preimage/tests/digest-vectors.txt"
count = 0
lengths = set()
for line in path.read_text().splitlines():
    preimage, expected = line.split()
    payload = bytes.fromhex(preimage)
    actual = subprocess.check_output(["openssl", "dgst", "-KECCAK-256", "-binary"], input=payload)
    if actual.hex() != expected:
        raise ValueError(f"reference mismatch at vector {count}")
    lengths.add(len(payload))
    count += 1
if count != 64 or lengths != {20, 29, 40, 49}:
    raise ValueError("unexpected comparison denominator")
print(json.dumps({"independent_reference": version, "matching_digests": count,
                  "input_lengths": sorted(lengths), "target_execution": False}, indent=2))
