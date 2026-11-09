#!/usr/bin/env python3
"""Verify the static byte, FDE, and relocation evidence in this packet."""
import csv
import hashlib
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import sections, unwind_index  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

PACKET = Path(__file__).resolve().parent
TARGET = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def main():
    binary = ROOT / "artifacts/node/115/hl-node"
    data = binary.read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET
    section_rows = sections(data)
    text = next(row for row in section_rows if row["name"] == ".text")
    rela = next(row for row in section_rows if row["name"] == ".rela.dyn")
    indexed_sections, unwind_rows = unwind_index(data)
    _, fde_rows = eh_frame_records(data, indexed_sections)
    indexed = {(row["start"], row["fde"]) for row in unwind_rows}
    actual_fdes = {(row["start"], row["end"], row["fde"]) for row in fde_rows}
    rows = list(csv.DictReader((PACKET / "instructions.tsv").open(), delimiter="\t"))
    assert rows
    extents = {}
    for row in rows:
        va, end, fde, fde_end, _fde_record = (int(row[name], 16) for name in
            ("va", "end_va", "fde_start_va", "fde_end_va", "fde_record_va"))
        fde_record = _fde_record
        raw = bytes.fromhex(row["bytes"])
        assert raw and end == va + len(raw)
        assert (fde, fde_record) in indexed
        assert (fde, fde_end, fde_record) in actual_fdes
        assert text["address"] <= va < end <= text["address"] + text["size"]
        offset = text["offset"] + va - text["address"]
        assert data[offset:offset + len(raw)] == raw
        extents.setdefault(fde, {"end": fde_end, "spans": []})["spans"].append((va, end))
    assert len(extents) == 4
    for fde, extent in extents.items():
        spans = extent["spans"]
        assert min(start for start, _ in spans) == fde
        ordered = sorted(spans)
        assert all(left[1] == right[0] for left, right in zip(ordered, ordered[1:]))
        assert max(end for _, end in spans) == extent["end"]

    rela_rows = struct.iter_unpack("<QQq", data[rela["offset"]:rela["offset"] + rela["size"]])
    relocations = {slot: (info, addend) for slot, info, addend in rela_rows}
    assert relocations[0x64e0f80] == (8, 0x1546570)
    print(f"verified target digest, {len(rows)} contiguous instruction spans in 4 FDE extents, and slot relocation")


if __name__ == "__main__":
    main()
