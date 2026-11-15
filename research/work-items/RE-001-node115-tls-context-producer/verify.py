#!/usr/bin/env python3
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / "artifacts/node/115/hl-node"
SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
DATA = json.loads((Path(__file__).parent / "records.json").read_text())

def elf_text_bytes(data, va, size):
    # The authenticated #115 .text PT_LOAD is file-backed at VA 0x1000.
    return data[int(va, 16) - 0x1000:int(va, 16) - 0x1000 + size]

def main():
    data = TARGET.read_bytes()
    assert hashlib.sha256(data).hexdigest() == SHA == DATA["sha256"]
    assert DATA["fde"] == {"start": "0x15d6fd0", "end": "0x15d8447"}
    assert len(DATA["windows"]) == 4
    for row in DATA["windows"]:
        raw = bytes.fromhex(row["bytes"])
        assert elf_text_bytes(data, row["va"], len(raw)) == raw
    excerpt = (Path(__file__).parent / "excerpts.objdump.txt").read_text()
    assert "15d7047" in excerpt and "15d70d6" in excerpt
    assert "15d729f" in excerpt and "15d72b9" in excerpt
    print(json.dumps({"target_sha256": SHA, "windows_verified": 4,
                      "captured_code_executed_or_emulated": False}, sort_keys=True))

if __name__ == "__main__":
    main()
