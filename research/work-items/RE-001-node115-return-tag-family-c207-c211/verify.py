#!/usr/bin/env python3
from pathlib import Path
import hashlib
import json
import re
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import unwind_index
from fde_extents import eh_frame_records

TARGET = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
PACKET = Path(__file__).parent
RECORDS = json.loads((PACKET / "records.json").read_text())

def rows():
    out = {}
    pattern = re.compile(r"^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s*)+)$")
    for line in (PACKET / "excerpts.objdump.txt").read_text().splitlines():
        match = pattern.match(line)
        if match:
            out[int(match.group(1), 16)] = bytes.fromhex(match.group(2))
    return out

def main():
    data = (ROOT / "artifacts/node/115/hl-node").read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET
    sections, header = unwind_index(data)
    _, fdes = eh_frame_records(data, sections)
    by_extent = {(r["start"], r["end"]): r for r in fdes}
    by_header = {r["start"]: r["fde"] for r in header}
    dis = rows()
    assert len(RECORDS) == 5
    for record in RECORDS:
        start, end, fde = (int(record[key], 16) for key in ("start", "end", "fde"))
        assert by_extent.get((start, end), {}).get("fde") == fde
        assert by_header.get(start) == fde
        assert dis.get(start) == bytes.fromhex("53")
        assert dis.get(start + 1) == bytes.fromhex("4883ec50")
        assert dis.get(end - 1) == bytes.fromhex("c3")
        calls = [address for address, value in dis.items() if start <= address < end and value[:1] == b"\xe8"]
        assert len(calls) == 1
        call = calls[0]
        displacement = int.from_bytes(dis[call][1:5], "little", signed=True)
        assert call + 5 + displacement == int(record["call_target"], 16)
    assert dis.get(0x4D489B4) == bytes.fromhex("c70301000000")
    assert dis.get(0x4D487FF) == bytes.fromhex("cc")
    assert dis.get(0x4D48A39) == bytes.fromhex("cc")
    assert (0x4D487FF, 0x4D48869) not in by_extent
    print("verified 5 node115 sibling FDEs, call targets, terminal forms, and boundaries")

if __name__ == "__main__":
    main()
