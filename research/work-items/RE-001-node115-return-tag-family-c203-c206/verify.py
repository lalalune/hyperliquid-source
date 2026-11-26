#!/usr/bin/env python3
"""Fail-closed, digest-bound verification of one node115 sibling-family packet."""
from pathlib import Path
import hashlib, json, re, sys
ROOT = Path(__file__).resolve().parents[3]; sys.path.insert(0, str(ROOT / "tools"))
from elf_index import unwind_index
from fde_extents import eh_frame_records
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
PACKET = Path(__file__).parent; ROWS = json.loads((PACKET / "records.json").read_text())
def objdump_bytes():
    rows = {}; pattern = re.compile(r"^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s*)+)$")
    for line in (PACKET / "excerpts.objdump.txt").read_text().splitlines():
        m = pattern.match(line)
        if m: rows[int(m.group(1), 16)] = bytes.fromhex(m.group(2))
    return rows
def main():
    data = (ROOT / "artifacts/node/115/hl-node").read_bytes(); assert hashlib.sha256(data).hexdigest() == TARGET_SHA256, "target digest mismatch"
    sections, header = unwind_index(data); _, fdes = eh_frame_records(data, sections); by_start = {(r["start"], r["end"]): r for r in fdes}; header_by_start = {r["start"]: r["fde"] for r in header}; rows = objdump_bytes(); assert len(ROWS) == 4
    for record in ROWS:
        start, end, fde = (int(record[k], 16) for k in ("start", "end", "fde")); assert by_start.get((start, end), {}).get("fde") == fde; assert header_by_start.get(start) == fde; assert rows.get(start) == bytes.fromhex("53"); assert rows.get(start + 1) == bytes.fromhex("4883ec50"); assert rows.get(end - 1) == bytes.fromhex("c3")
        calls = [a for a, v in rows.items() if start <= a < end and v[:1] == bytes.fromhex("e8")]; assert len(calls) == 1; call = calls[0]; disp = int.from_bytes(rows[call][1:5], "little", signed=True); assert call + 5 + disp == int(record["call_target"], 16)
    assert rows.get(0x4D486F4) == bytes.fromhex("48c70303000000"); assert rows.get(0x4D487EE) == bytes.fromhex("488903")
    for start in (0x4D48620, 0x4D48710):
        record = next(r for r in ROWS if int(r["start"], 16) == start); body = [v for a, v in rows.items() if start <= a < int(record["end"], 16)]; assert not any(v.startswith((bytes.fromhex("488903"), bytes.fromhex("48c703"), bytes.fromhex("c74324"), bytes.fromhex("c74308"))) for v in body)
    assert rows.get(0x4D4861F) == bytes.fromhex("cc"); assert rows.get(0x4D487FA) == bytes.fromhex("cc"); assert (0x4D4861F, 0x4D48689) not in by_start
    print("verified 4 node115 sibling FDEs, call targets, terminal forms, and boundaries")
if __name__ == "__main__": main()
