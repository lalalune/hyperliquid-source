#!/usr/bin/env python3
"""Static verifier for RE-009-node115-db-crate-map.

Authenticates node #115 (artifacts/node/115/hl-node), maps all 5 observed
`db/src/*.rs` diagnostic source paths (`block_reader.rs`, `db_home.rs`,
`db_hub.rs`, `owned_db_home.rs`, `rocks_db.rs`), verifies all 28 `Location`
records, their 18 enclosing FDE extents, and key instruction/constant anchors
for `owned_db_home`, `db_home`, `db_hub`, `rocks_db`, and `block_reader`.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PACKET_DIR = Path(__file__).resolve().parent
RECORDS_PATH = PACKET_DIR / "records.json"

TARGET_REL = "artifacts/node/115/hl-node"
TARGET_SIZE = 105896032
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

sys.path.insert(0, str(ROOT / "tools"))
from elf_index import unwind_index  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

DB_FILES = [
    "db/src/block_reader.rs",
    "db/src/db_home.rs",
    "db/src/db_hub.rs",
    "db/src/owned_db_home.rs",
    "db/src/rocks_db.rs",
]

# All 28 Location records across the 5 db/src/*.rs files.
EXPECTED_LOCATIONS = [
    ("db/src/block_reader.rs", 27, 70, 0x6445180),
    ("db/src/block_reader.rs", 29, 26, 0x644AB80),
    ("db/src/block_reader.rs", 45, 114, 0x6445168),
    ("db/src/db_home.rs", 21, 24, 0x6432DB8),
    ("db/src/db_home.rs", 21, 24, 0x648B948),
    ("db/src/db_home.rs", 21, 24, 0x64B7E78),
    ("db/src/db_home.rs", 85, 13, 0x648B960),
    ("db/src/db_home.rs", 85, 13, 0x64B7E90),
    ("db/src/db_home.rs", 286, 44, 0x648B868),
    ("db/src/db_home.rs", 291, 13, 0x648B8A8),
    ("db/src/db_home.rs", 291, 88, 0x648B8C0),
    ("db/src/db_home.rs", 302, 21, 0x648B8D8),
    ("db/src/db_home.rs", 302, 106, 0x648B8F0),
    ("db/src/db_home.rs", 309, 29, 0x648B908),
    ("db/src/db_home.rs", 310, 34, 0x648B920),
    ("db/src/db_home.rs", 317, 27, 0x648B890),
    ("db/src/db_hub.rs", 25, 38, 0x646E338),
    ("db/src/db_hub.rs", 25, 38, 0x649D948),
    ("db/src/db_hub.rs", 51, 18, 0x646E350),
    ("db/src/db_hub.rs", 51, 18, 0x649D960),
    ("db/src/db_hub.rs", 62, 41, 0x64089C8),
    ("db/src/db_hub.rs", 66, 14, 0x64089E0),
    ("db/src/db_hub.rs", 68, 14, 0x64089F8),
    ("db/src/owned_db_home.rs", 21, 9, 0x6408BD0),
    ("db/src/owned_db_home.rs", 72, 37, 0x646E320),
    ("db/src/owned_db_home.rs", 72, 37, 0x64B0A78),
    ("db/src/rocks_db.rs", 58, 49, 0x648F260),
    ("db/src/rocks_db.rs", 58, 49, 0x64B0A90),
]

EXPECTED_FDES = [
    ("block_reader_l27", 0x2A191E0, 0x2A195A7),
    ("block_reader_l29", 0x2B2BE60, 0x2B2C4F1),
    ("block_reader_l45", 0x2A0ACC0, 0x2A0B327),
    ("db_home_discovery_1", 0x25D3F20, 0x25D4CAB),
    ("db_home_discovery_2", 0x4468E30, 0x44699C0),
    ("db_home_discovery_3", 0x59FFA30, 0x5A007BB),
    ("db_home_validate_live", 0x44699C0, 0x4469BD8),
    ("db_home_validate_slow", 0x5A007C0, 0x5A00AF9),
    ("db_home_lifecycle", 0x44681E0, 0x4468B62),
    ("db_hub_init_live", 0x38B3AD0, 0x38B3F8C),
    ("db_hub_init_slow", 0x4E33EF0, 0x4E342A5),
    ("db_hub_lookup_live_1", 0x3D4C7C0, 0x3D4CBE0),
    ("db_hub_lookup_live_2", 0x3D4CBE0, 0x3D4D000),
    ("db_hub_lookup_live_3", 0x3D4D000, 0x3D4D420),
    ("db_hub_lookup_slow_1", 0x57C58D0, 0x57C5CF0),
    ("db_hub_lookup_slow_2", 0x57C5CF0, 0x57C6110),
    ("db_hub_lookup_slow_3", 0x57C6110, 0x57C6530),
    ("db_hub_l62_68", 0x1692CA0, 0x1692FE9),
    ("owned_db_home_validate", 0x16961B0, 0x1696729),
    ("owned_db_open_live", 0x4524660, 0x4524ADB),
    ("owned_db_open_slow", 0x57C6530, 0x57C70B4),
]

EXPECTED_ANCHORS = [
    # owned_db_home.rs:21: rejects paths containing "checkpoint" (10 bytes: "checkpoi" + "nt")
    (0x16961CC, "4983ff0a", "owned_db_home_validate", "compare path len against 10 ('checkpoint')"),
    (0x16961DC, "48b8636865636b706f69", "owned_db_home_validate", "load 8-byte ASCII literal 'checkpoi'"),
    (0x16961FA, "4881f76e740000", "owned_db_home_validate", "compare 2-byte ASCII literal 'nt'"),
    (0x169621D, "48b8636865636b706f69", "owned_db_home_validate", "exact-length-10 'checkpoi' check"),
    (0x169622F, "4881f16e740000", "owned_db_home_validate", "exact-length-10 'nt' check"),
    # owned_db_home.rs:72 & rocks_db.rs:58: live & slow open options
    (0x45247F2, "be00400000", "owned_db_open_live", "BLOCK_SIZE = 0x4000 (16 KiB)"),
    (0x452482E, "be00000008", "owned_db_open_live", "COMPANION_BYTES = 0x0800_0000 (128 MiB)"),
    (0x57C661B, "bf00400000", "owned_db_open_slow", "slow BLOCK_SIZE = 0x4000 (16 KiB)"),
    (0x57C671B, "be00000008", "owned_db_open_slow", "slow COMPANION_BYTES = 0x0800_0000 (128 MiB)"),
    (0x57C6872, "49bc0000000000000080", "owned_db_open_slow", "ERROR_NICHE = 0x8000_0000_0000_0000"),
    # db_home.rs:85: checks EvmState / db_bundle path guard
    (0x4469A72, "488d35dffffefb", "db_home_validate_live", "reference 'EvmState' literal in .rodata"),
    (0x4469B5D, "488d3d9140fefb", "db_home_validate_live", "reference 'db_home contains db_bundle in path: '"),
]

EXPECTED_RODATA_LITERALS = [
    (0x459A58, "EvmState"),
    (0x44DBF6, "db_home contains db_bundle in path: "),
    (0x47B3E2, "OwnedDbDirError"),
]


def load_elf(target_path: Path):
    data = target_path.read_bytes()
    if len(data) != TARGET_SIZE:
        raise ValueError(f"size mismatch {len(data)} != {TARGET_SIZE}")
    digest = hashlib.sha256(data).hexdigest()
    if digest != TARGET_SHA256:
        raise ValueError(f"sha256 mismatch {digest}")
    sections, header = unwind_index(data)
    _, fdes = eh_frame_records(data, sections)
    indexed = {(r["start"], r["fde"]) for r in header}
    bounds = {(r["start"], r["end"]) for r in fdes if (r["start"], r["fde"]) in indexed}
    by_name = {s["name"]: s for s in sections}
    rela = by_name[".rela.dyn"]
    relocs = {
        slot: addend
        for slot, info, addend in struct.iter_unpack(
            "<QQq", data[rela["offset"] : rela["offset"] + rela["size"]]
        )
        if (info & 0xFFFFFFFF) == 8
    }
    return data, sections, by_name, bounds, relocs


def read_va(data: bytes, sections: list, va: int, size: int) -> bytes:
    sec = next((s for s in sections if s["address"] <= va and va + size <= s["address"] + s["size"]), None)
    if sec is None or sec["offset"] == 0:
        raise ValueError(f"VA 0x{va:x}..0x{va+size:x} not file-backed")
    off = sec["offset"] + (va - sec["address"])
    return data[off : off + size]


def build_records() -> dict:
    return {
        "target": {"path": TARGET_REL, "size": TARGET_SIZE, "sha256": TARGET_SHA256},
        "source_files": DB_FILES,
        "locations": [
            {"file": f, "line": ln, "col": col, "slot": f"0x{slot:x}"}
            for f, ln, col, slot in EXPECTED_LOCATIONS
        ],
        "fdes": [
            {"name": n, "start": f"0x{s:x}", "end": f"0x{e:x}"}
            for n, s, e in EXPECTED_FDES
        ],
        "anchors": [
            {"va": f"0x{va:x}", "bytes": hx, "fde": fde, "role": role}
            for va, hx, fde, role in EXPECTED_ANCHORS
        ],
        "rodata_literals": [
            {"va": f"0x{va:x}", "text": txt}
            for va, txt in EXPECTED_RODATA_LITERALS
        ],
    }


def verify_record_dict(data: bytes, sections: list, by_name: dict, bounds: set, relocs: dict, record: dict) -> dict:
    # 1. All 28 Location records across all 5 db/src/*.rs files
    seen_files = set()
    for loc in record["locations"]:
        slot = int(loc["slot"], 16)
        expected_file = loc["file"].encode("utf-8")
        str_va = relocs.get(slot)
        if str_va is None:
            raise ValueError(f"Location slot 0x{slot:x} missing R_X86_64_RELATIVE relocation")
        flen, line, col = struct.unpack("<QII", read_va(data, sections, slot + 8, 16))
        actual_file = read_va(data, sections, str_va, flen)
        if actual_file != expected_file or line != loc["line"] or col != loc["col"]:
            raise ValueError(
                f"Location 0x{slot:x} mismatch: {actual_file!r}:{line}:{col} != {expected_file!r}:{loc['line']}:{loc['col']}"
            )
        seen_files.add(loc["file"])
    if sorted(seen_files) != sorted(record["source_files"]):
        raise ValueError(f"db source file coverage mismatch: {sorted(seen_files)}")

    # 2. All 21 FDE extents
    fde_map = {}
    for fde in record["fdes"]:
        s, e = int(fde["start"], 16), int(fde["end"], 16)
        if (s, e) not in bounds:
            raise ValueError(f"FDE {fde['name']} 0x{s:x}..0x{e:x} not in indexed .eh_frame")
        fde_map[fde["name"]] = (s, e)

    # 3. All instruction anchors
    for anc in record["anchors"]:
        va = int(anc["va"], 16)
        expected = bytes.fromhex(anc["bytes"])
        s, e = fde_map[anc["fde"]]
        if not (s <= va < va + len(expected) <= e):
            raise ValueError(f"anchor 0x{va:x} outside FDE {anc['fde']}")
        actual = read_va(data, sections, va, len(expected))
        if actual != expected:
            raise ValueError(f"anchor 0x{va:x} bytes mismatch: {actual.hex()} != {expected.hex()}")

    # 4. Rodata string literals
    for lit in record["rodata_literals"]:
        va = int(lit["va"], 16)
        exp = lit["text"].encode("utf-8")
        act = read_va(data, sections, va, len(exp))
        if act != exp:
            raise ValueError(f"rodata literal 0x{va:x} mismatch: {act!r} != {exp!r}")

    return {
        "source_files": len(seen_files),
        "locations": len(record["locations"]),
        "fdes": len(fde_map),
        "anchors": len(record["anchors"]),
        "literals": len(record["rodata_literals"]),
    }


def run_negative_controls(data, sections, by_name, bounds, relocs, record) -> int:
    def clone():
        return json.loads(json.dumps(record))

    controls = []
    # 1. Wrong Location line number
    c1 = clone()
    c1["locations"][0]["line"] += 1
    controls.append(("bad_location_line", c1))
    # 2. Corrupted "checkpoint" ASCII immediate in owned_db_home
    c2 = clone()
    c2["anchors"][1]["bytes"] = "48b8636865636b706f68"
    controls.append(("bad_checkpoint_literal", c2))
    # 3. Corrupted BLOCK_SIZE immediate
    c3 = clone()
    c3["anchors"][5]["bytes"] = "be00200000"
    controls.append(("bad_block_size", c3))
    # 4. Corrupted ERROR_NICHE immediate
    c4 = clone()
    c4["anchors"][9]["bytes"] = "49bc0100000000000080"
    controls.append(("bad_error_niche", c4))
    # 5. Corrupted FDE end
    c5 = clone()
    c5["fdes"][0]["end"] = "0x2a195a0"
    controls.append(("bad_fde_end", c5))
    # 6. Corrupted rodata literal
    c6 = clone()
    c6["rodata_literals"][0]["text"] = "EvmStatX"
    controls.append(("bad_rodata_literal", c6))

    for name, mutated in controls:
        try:
            verify_record_dict(data, sections, by_name, bounds, relocs, mutated)
        except ValueError:
            continue
        raise AssertionError(f"negative control {name} passed")
    return len(controls)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, default=ROOT / TARGET_REL)
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    data, sections, by_name, bounds, relocs = load_elf(args.target)
    record = build_records() if args.write or not RECORDS_PATH.is_file() else json.loads(RECORDS_PATH.read_text())
    stats = verify_record_dict(data, sections, by_name, bounds, relocs, record)
    if args.write:
        RECORDS_PATH.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    rejected = run_negative_controls(data, sections, by_name, bounds, relocs, record)
    print(
        f"RE-009-node115-db-crate-map verified: "
        f"{stats['source_files']}/5 db files, {stats['locations']} Locations, "
        f"{stats['fdes']} FDEs, {stats['anchors']} anchors, {stats['literals']} literals, "
        f"{rejected}/{rejected} negative controls rejected."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
