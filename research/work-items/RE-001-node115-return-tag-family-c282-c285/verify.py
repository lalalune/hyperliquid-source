#!/usr/bin/env python3
import hashlib, json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / "artifacts/node/115/hl-node"
SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
DATA = json.loads((Path(__file__).parent / "records.json").read_text())

def read(va, n):
    # This artifact maps virtual address 0x1000 above the file offset.
    raw = TARGET.read_bytes()
    off = int(va, 16) - 0x1000
    return raw[off:off+n].hex()

actual = hashlib.sha256(TARGET.read_bytes()).hexdigest()
assert actual == SHA, (actual, SHA)
assert DATA["sha256"] == SHA and len(DATA["families"]) == 4
for f in DATA["families"]:
    assert int(f["start"], 16) < int(f["end"], 16)
    assert read(f["call"], len(f["call_bytes"]) // 2) == f["call_bytes"]
    assert read(f["terminal"], len(f["terminal_bytes"]) // 2) == f["terminal_bytes"]
    assert read(f["ret"], len(f["ret_bytes"]) // 2) == f["ret_bytes"]
print(json.dumps({"target_sha256": actual, "families_verified": 4, "captured_code_executed_or_emulated": False}, sort_keys=True))
