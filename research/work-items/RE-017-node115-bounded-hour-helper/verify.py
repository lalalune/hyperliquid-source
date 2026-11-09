#!/usr/bin/env python3
"""Verify the static dispatch, instruction, literal and arithmetic evidence."""
import csv
import hashlib
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
PACKET = Path(__file__).resolve().parent
TARGET = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import sections, unwind_index  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402


def main():
    image = (ROOT / "artifacts/node/115/hl-node").read_bytes()
    assert hashlib.sha256(image).hexdigest() == TARGET
    sections_by_name = {row["name"]: row for row in sections(image)}
    text = sections_by_name[".text"]
    rodata = sections_by_name[".rodata"]
    rela = sections_by_name[".rela.dyn"]
    index_sections, unwind_rows = unwind_index(image)
    _, fdes = eh_frame_records(image, index_sections)
    indexed = {(row["start"], row["fde"]) for row in unwind_rows}
    actual_fdes = {(row["start"], row["end"], row["fde"]) for row in fdes}

    path = PACKET / "instructions.tsv"
    rows = list(csv.DictReader(path.open(), delimiter="\t"))
    extents = {}
    instruction_bytes = {}
    for row in rows:
        va, end, fde_start, fde_end, fde_record = (
            int(row[key], 16) for key in
            ("va", "end_va", "fde_start_va", "fde_end_va", "fde_record_va")
        )
        raw = bytes.fromhex(row["bytes"])
        assert raw and end == va + len(raw)
        assert text["address"] <= va < end <= text["address"] + text["size"]
        offset = text["offset"] + va - text["address"]
        assert image[offset:offset + len(raw)] == raw
        instruction_bytes[va] = raw
        assert (fde_start, fde_record) in indexed
        assert (fde_start, fde_end, fde_record) in actual_fdes
        extents.setdefault(fde_start, {"end": fde_end, "fde": fde_record, "spans": []})["spans"].append((va, end))

    assert set(extents) == {0x1546570, 0x1567ad0}
    for start, extent in extents.items():
        assert extent["spans"]
        ordered = sorted(extent["spans"])
        assert ordered[0][0] == start and ordered[-1][1] == extent["end"]
        assert all(left[1] == right[0] for left, right in zip(ordered, ordered[1:]))

    expected = {
        0x1546597: bytes.fromhex("4889d7"),
        0x154659A: bytes.fromhex("ff15b8a9f904"),
        0x15465A0: bytes.fromhex("4438f8"),
        0x1567ADE: bytes.fromhex("7321"),
        0x1567AD5: bytes.fromhex("8b4f04"),
        0x1567AD8: bytes.fromhex("81f900100e00"),
        0x1567AE2: bytes.fromhex("b8c5b3a291"),
        0x1567AE7: bytes.fromhex("480fafc2"),
        0x1567AEB: bytes.fromhex("48c1e82b"),
        0x1567AF3: bytes.fromhex("81f9905f0100"),
        0x1567AF9: bytes.fromhex("732b"),
        0x1567B3C: bytes.fromhex("488d3d3febecfe"),
    }
    assert all(instruction_bytes.get(va) == raw for va, raw in expected.items())
    call_disp = struct.unpack_from("<i", instruction_bytes[0x154659A], 2)[0]
    assert 0x154659A + 6 + call_disp == 0x64e0f58
    literal_disp = struct.unpack_from("<i", instruction_bytes[0x1567B3C], 3)[0]
    assert 0x1567B3C + 7 + literal_disp == 0x436682

    entries = struct.iter_unpack(
        "<QQq", image[rela["offset"]:rela["offset"] + rela["size"]]
    )
    relocations = {slot: (info, addend) for slot, info, addend in entries}
    assert relocations[0x64e0f58] == (8, 0x1567ad0)

    literal_va = 0x436682
    literal = b"\x13hour out of range: "
    offset = rodata["offset"] + literal_va - rodata["address"]
    assert image[offset:offset + len(literal)] == literal

    multiplier = 0x91a2b3c5
    assert all(((value * multiplier) >> 43) == value // 3600 for value in range(90_000))
    assert ((89_999 * multiplier) >> 43) == 24
    assert 90_000 >= 0x15f90
    print(
        f"verified target digest, {len(rows)} instruction spans in 2 complete FDE extents, "
        "relative relocation, range literal, and 90,000 arithmetic inputs"
    )


if __name__ == "__main__":
    main()
