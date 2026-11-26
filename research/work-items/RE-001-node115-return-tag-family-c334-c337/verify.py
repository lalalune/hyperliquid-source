#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / "artifacts/node/115/hl-node"
SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
DATA = json.loads((Path(__file__).parent / "records.json").read_text())


def read(va, n):
    # Target virtual addresses map 0x1000 above file offsets in this artifact.
    return TARGET.read_bytes()[int(va, 16) - 0x1000 : int(va, 16) - 0x1000 + n].hex()


actual = hashlib.sha256(TARGET.read_bytes()).hexdigest()
assert actual == SHA
assert DATA["sha256"] == SHA and len(DATA["families"]) == 4
for family in DATA["families"]:
    assert int(family["start"], 16) < int(family["end"], 16)
    for key in ("call", "terminal", "ret"):
        assert read(family[key], len(family[key + "_bytes"]) // 2) == family[key + "_bytes"]

print(json.dumps({"target_sha256": actual, "families_verified": 4, "captured_code_executed_or_emulated": False}, sort_keys=True))
