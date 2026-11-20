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
        call_sites = [address for address, value in rows.items() if start <= address < end and value[:1] == bytes.fromhex("e8")]
        assert len(call_sites) == 1
        call = call_sites[0]
        displacement = int.from_bytes(rows[call][1:5], "little", signed=True)
        assert call + 5 + displacement == int(record["call_target"], 16)

    expected = {
        0x4D46870: (0x4D468DE, bytes.fromhex("48b80100000000000080"), 0x4D468E8, bytes.fromhex("488903")),
        0x4D46900: (0x4D4696A, bytes.fromhex("c7432400000000"), None, None),
        0x4D46980: (0x4D469EE, bytes.fromhex("48b80000000000000080"), 0x4D469F8, bytes.fromhex("488903")),
        0x4D46A10: (0x4D46A7E, bytes.fromhex("48c70302000000"), None, None),
        0x4D46C10: (0x4D46C88, bytes.fromhex("488903"), None, None),
    }
    for start, (address, value, store_address, store_value) in expected.items():
        assert rows.get(address) == value
        if store_address is not None:
            assert rows.get(store_address) == store_value
    for start in (0x4D46A90, 0x4D46B10, 0x4D46B90):
        start_row = next(record for record in ROWS if int(record["start"], 16) == start)
        end = int(start_row["end"], 16)
        body = [value for address, value in rows.items() if start <= address < end]
        assert not any(value.startswith((bytes.fromhex("488903"), bytes.fromhex("48c703"), bytes.fromhex("c74324"))) for value in body)
    # Negative controls: the int3 padding is outside each FDE and a shifted extent is absent.
    assert rows.get(0x4D468F4) == bytes.fromhex("cc")
    assert rows.get(0x4D4697A) == bytes.fromhex("cc")
    assert (0x4D4686F, 0x4D468F4) not in by_start
    print("verified 8 node115 sibling FDEs, call targets, terminal stores, and boundaries")


if __name__ == "__main__":
    main()
