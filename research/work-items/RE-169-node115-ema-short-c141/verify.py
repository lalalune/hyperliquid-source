#!/usr/bin/env python3
"""Fail-closed static verification for the node115 EMA short c141 packet."""
from pathlib import Path
import hashlib
import re
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import unwind_index
from fde_extents import eh_frame_records

START = 0x4D463C0
END = 0x4D4643E
FDE = 0xF18940
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
PACKET = Path(__file__).parent
OBJ = PACKET / "excerpts.objdump.txt"


def objdump_bytes():
    rows = {}
    line_re = re.compile(r"^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)")
    for line in OBJ.read_text().splitlines():
        match = line_re.match(line)
        if match:
            rows[int(match.group(1), 16)] = bytes.fromhex(match.group(2))
    return rows


def main():
    binary = ROOT / "artifacts/node/115/hl-node"
    data = binary.read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET_SHA256, "target binary digest mismatch"
    sections, header = unwind_index(data)
    _, fdes = eh_frame_records(data, sections)
    assert any(row["start"] == START and row["end"] == END and row["fde"] == FDE for row in fdes)
    assert any(row["start"] == START and row["fde"] == FDE for row in header)

    rows = objdump_bytes()
    expected = {
        START: bytes.fromhex("53"),
        START + 1: bytes.fromhex("4883ec50"),
        START + 5: bytes.fromhex("4889fb"),
        START + 8: bytes.fromhex("4889742420"),
        START + 13: bytes.fromhex("4889542428"),
        START + 18: bytes.fromhex("c644241806"),
        START + 0x6E: bytes.fromhex("48c70301000000"),
    }
    for address, value in expected.items():
        assert rows.get(address) == value, f"objdump witness mismatch at {address:#x}"
    assert START - 1 not in rows and END not in rows, "packet boundary witness unexpectedly included"
    print(f"verified {START:#x}-{END - 1:#x} ({END - START} bytes), FDE {FDE:#x}")


if __name__ == "__main__":
    main()
