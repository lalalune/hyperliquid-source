#!/usr/bin/env python3
"""Fail-closed, digest-bound verification of one node115 sibling-family packet."""
from pathlib import Path
import hashlib
import json
import re
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import unwind_index
from fde_extents import eh_frame_records

TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
PACKET = Path(__file__).parent
OBJ = PACKET / "excerpts.objdump.txt"
ROWS = json.loads((PACKET / "records.json").read_text())


def objdump_bytes():
    rows = {}
    pattern = re.compile(r"^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)")
    for line in OBJ.read_text().splitlines():
        match = pattern.match(line)
        if match:
            rows[int(match.group(1), 16)] = bytes.fromhex(match.group(2))
    return rows


def main():
    data = (ROOT / "artifacts/node/115/hl-node").read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET_SHA256, "target digest mismatch"
    sections, header = unwind_index(data)
    _, fdes = eh_frame_records(data, sections)
    by_start = {(row["start"], row["end"]): row for row in fdes}
    header_by_start = {row["start"]: row["fde"] for row in header}
    rows = objdump_bytes()
    assert len(ROWS) == 8
    for record in ROWS:
        start, end, fde = (int(record[k], 16) for k in ("start", "end", "fde"))
        assert by_start.get((start, end), {}).get("fde") == fde
        assert header_by_start.get(start) == fde
        assert rows.get(start) == bytes.fromhex("53")
        assert rows.get(start + 1) == bytes.fromhex("4883ec50")
        assert rows.get(end - 1) == bytes.fromhex("c3")
        call_sites = [address for address, value in rows.items() if address >= start and address < end and value[:1] == bytes.fromhex("e8")]
        assert len(call_sites) == 1
        call = call_sites[0]
        displacement = int.from_bytes(rows[call][1:5], "little", signed=True)
        assert call + 5 + displacement == int(record["call_target"], 16)
    expected_results = {
        0x4D46440: bytes.fromhex("48c70302000000"),
        0x4D464C0: None,
        0x4D46540: bytes.fromhex("488903"),
        0x4D465D0: bytes.fromhex("48c70301000000"),
        0x4D46650: bytes.fromhex("488903"),
        0x4D466E0: bytes.fromhex("488903"),
        0x4D46770: bytes.fromhex("48c70302000000"),
        0x4D467F0: None,
    }
    result_sites = {
        0x4D46440: 0x4D464AE,
        0x4D46540: 0x4D465B8,
        0x4D465D0: 0x4D4663E,
        0x4D46650: 0x4D466C8,
        0x4D466E0: 0x4D46758,
        0x4D46770: 0x4D467DE,
    }
    for start, expected in expected_results.items():
        if expected is None:
            assert start not in result_sites
        else:
            assert rows.get(result_sites[start]) == expected
    assert rows.get(0x4D465AE) == bytes.fromhex("48b80100000000000080")
    assert rows.get(0x4D466BE) == bytes.fromhex("48b80100000000000080")
    assert rows.get(0x4D4674E) == bytes.fromhex("48b80100000000000080")
    # Negative controls: padding is outside every FDE and no shifted boundary is accepted.
    assert rows.get(0x4D464BE) == bytes.fromhex("cc")
    assert rows.get(0x4D46533) == bytes.fromhex("cc")
    assert (0x4D4643F, 0x4D464BE) not in by_start
    print("verified 8 node115 sibling FDEs, call targets, terminal stores, and boundaries")


if __name__ == "__main__":
    main()
