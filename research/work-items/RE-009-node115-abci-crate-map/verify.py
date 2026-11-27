#!/usr/bin/env python3
"""Static verifier for RE-009-node115-abci-crate-map.

Authenticates node #115 (artifacts/node/115/hl-node), maps all 4 observed
`l1/src/abci/*.rs` diagnostic source paths (`abci_hash.rs`, `engine.rs`,
`hash_signature_tracker.rs`, `state.rs`), verifies all 57 `Location` records,
their enclosing FDE extents, 24 instruction anchors, and 10 `.rodata` diagnostic
literals, plus 6 negative/corruption controls.
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

ABCI_FILES = [
    "l1/src/abci/abci_hash.rs",
    "l1/src/abci/engine.rs",
    "l1/src/abci/hash_signature_tracker.rs",
    "l1/src/abci/state.rs",
]

# All 57 Location records across the 4 l1/src/abci/*.rs files in node #115.
EXPECTED_LOCATIONS = [
    ("l1/src/abci/abci_hash.rs", 28, 37, 0x644D5C0),
    ("l1/src/abci/abci_hash.rs", 28, 37, 0x64AA290),
    ("l1/src/abci/engine.rs", 168, 13, 0x64510D8),
    ("l1/src/abci/engine.rs", 168, 13, 0x64B7F58),
    ("l1/src/abci/engine.rs", 169, 13, 0x6451060),
    ("l1/src/abci/engine.rs", 169, 13, 0x64B7EE0),
    ("l1/src/abci/engine.rs", 170, 13, 0x6451078),
    ("l1/src/abci/engine.rs", 170, 13, 0x64B7EF8),
    ("l1/src/abci/engine.rs", 171, 13, 0x6451090),
    ("l1/src/abci/engine.rs", 171, 13, 0x64B7F10),
    ("l1/src/abci/engine.rs", 172, 13, 0x64510A8),
    ("l1/src/abci/engine.rs", 172, 13, 0x64B7F28),
    ("l1/src/abci/engine.rs", 175, 17, 0x64510C0),
    ("l1/src/abci/engine.rs", 175, 17, 0x64B7F40),
    ("l1/src/abci/engine.rs", 262, 17, 0x6451130),
    ("l1/src/abci/engine.rs", 262, 17, 0x64B7FB0),
    ("l1/src/abci/engine.rs", 316, 46, 0x6451100),
    ("l1/src/abci/engine.rs", 316, 46, 0x64B7F80),
    ("l1/src/abci/engine.rs", 332, 25, 0x649C468),
    ("l1/src/abci/engine.rs", 339, 17, 0x649C450),
    ("l1/src/abci/engine.rs", 431, 21, 0x6451048),
    ("l1/src/abci/engine.rs", 431, 21, 0x64B7EC8),
    ("l1/src/abci/engine.rs", 514, 35, 0x646E840),
    ("l1/src/abci/engine.rs", 557, 17, 0x6479CE0),
    ("l1/src/abci/hash_signature_tracker.rs", 107, 28, 0x643B2F0),
    ("l1/src/abci/hash_signature_tracker.rs", 107, 28, 0x64BC860),
    ("l1/src/abci/hash_signature_tracker.rs", 123, 32, 0x643B308),
    ("l1/src/abci/hash_signature_tracker.rs", 123, 32, 0x64BC878),
    ("l1/src/abci/hash_signature_tracker.rs", 174, 42, 0x643B2C0),
    ("l1/src/abci/hash_signature_tracker.rs", 174, 42, 0x64BC830),
    ("l1/src/abci/hash_signature_tracker.rs", 184, 22, 0x643B2D8),
    ("l1/src/abci/hash_signature_tracker.rs", 184, 22, 0x64BC848),
    ("l1/src/abci/state.rs", 76, 77, 0x6476750),
    ("l1/src/abci/state.rs", 79, 100, 0x6476778),
    ("l1/src/abci/state.rs", 82, 21, 0x6476790),
    ("l1/src/abci/state.rs", 102, 40, 0x64767D8),
    ("l1/src/abci/state.rs", 113, 9, 0x64767C0),
    ("l1/src/abci/state.rs", 123, 37, 0x64767A8),
    ("l1/src/abci/state.rs", 151, 17, 0x6437460),
    ("l1/src/abci/state.rs", 151, 17, 0x649D9C8),
    ("l1/src/abci/state.rs", 151, 35, 0x6437478),
    ("l1/src/abci/state.rs", 151, 35, 0x649D9E0),
    ("l1/src/abci/state.rs", 161, 83, 0x649D9F8),
    ("l1/src/abci/state.rs", 193, 56, 0x6437490),
    ("l1/src/abci/state.rs", 193, 56, 0x649DA10),
    ("l1/src/abci/state.rs", 195, 17, 0x64374A8),
    ("l1/src/abci/state.rs", 195, 17, 0x649DA28),
    ("l1/src/abci/state.rs", 195, 64, 0x64374C0),
    ("l1/src/abci/state.rs", 195, 64, 0x649DA40),
    ("l1/src/abci/state.rs", 201, 9, 0x642D338),
    ("l1/src/abci/state.rs", 201, 9, 0x64AA230),
    ("l1/src/abci/state.rs", 201, 32, 0x642D350),
    ("l1/src/abci/state.rs", 201, 32, 0x64AA248),
    ("l1/src/abci/state.rs", 340, 21, 0x642D368),
    ("l1/src/abci/state.rs", 340, 21, 0x64AA260),
    ("l1/src/abci/state.rs", 460, 78, 0x642D310),
    ("l1/src/abci/state.rs", 460, 78, 0x64AA208),
]

EXPECTED_FDES = [
    ("abci_hash_live", 0x2BB37C0, 0x2BB39C3),
    ("abci_hash_slow_1", 0x548D8C0, 0x548DAC3),
    ("abci_hash_slow_2", 0x548DAD0, 0x548DCD3),
    ("engine_apply_live", 0x2D23610, 0x2D2561C),
    ("engine_apply_slow_1", 0x5A04E40, 0x5A065F8),
    ("engine_apply_slow_2", 0x5A06600, 0x5A07EB6),
    ("engine_end_root_live", 0x2D25620, 0x2D275C3),
    ("engine_end_root_slow_1", 0x5A07EC0, 0x5A0871C),
    ("engine_end_root_slow_2", 0x5A08720, 0x5A08F7C),
    ("engine_evm_maintenance", 0x4D98C40, 0x4D98F80),
    ("engine_tar_evm", 0x38C40F0, 0x38C51EE),
    ("engine_straggler_evm", 0x3D5DCA0, 0x3D5DFB0),
    ("tracker_watermark_1", 0x27604D0, 0x27605CD),
    ("tracker_watermark_2", 0x27605D0, 0x27606CD),
    ("tracker_record_live_l1", 0x27606D0, 0x2760BBC),
    ("tracker_record_live_abci", 0x2760BC0, 0x27610AC),
    ("tracker_record_slow_abci", 0x5AFADD0, 0x5AFB3A3),
    ("state_restore_l76_82", 0x3C12800, 0x3C12AF5),
    ("state_loader_l123", 0x3C13520, 0x3C13609),
    ("state_serialize_l151_live", 0x26A2C80, 0x26A326E),
    ("state_hash_l193_live", 0x26A2810, 0x26A2C7E),
    ("state_freeze_l201_live", 0x22ED1F0, 0x22ED70A),
    ("state_helper_l340_live", 0x229B760, 0x229B88E),
    ("state_exec_l460_live", 0x22EC9B0, 0x22ED1EC),
]

EXPECTED_ANCHORS = [
    (0x2BB3897, "488d15229d8903", "abci_hash_live", "reference abci_hash.rs:28 Location"),
    (0x2BB38B7, "498b4728", "abci_hash_live", "read state height [r15+0x28]"),
    (0x2BB38E9, "e852911900", "abci_hash_live", "emit computed abci hash record"),
    (0x5A07EE2, "48b8917efb3a70ce88d2", "engine_end_root_slow_1", "magic multiplier for height % 10000 == 0"),
    (0x5A07EF0, "48c1c804", "engine_end_root_slow_1", "ror 4 for height % 10000 == 0"),
    (0x5A07EF4, "48b9cc10c7bab88d0600", "engine_end_root_slow_1", "upper bound 0x68db8bac710cc for % 10000"),
    (0x5A07F0C, "4c39bef0100000", "engine_end_root_slow_1", "compare hardfork height [S+0x10f0]"),
    (0x5A07F85, "488b8ec8390000", "engine_end_root_slow_1", "load periodic root cadence [S+0x39c8]"),
    (0x4D98C61, "85f6", "engine_evm_maintenance", "branch tar (flag!=0) vs prune (flag==0)"),
    (0x4D98CFA, "488d051e326bfb", "engine_evm_maintenance", "reference 'tar_evm_checkpoints failed: '"),
    (0x4D98D51, "be64000000", "engine_evm_maintenance", "prune_lowest_evm_checkpoints keep=100 (0x64)"),
    (0x4D98D9F, "488d05b7026afb", "engine_evm_maintenance", "reference 'prune_lowest_evm_checkpoints failed'"),
    (0x38C479E, "48b85555555555555505", "engine_tar_evm", "capacity bound in daily tar builder"),
    (0x27605E4, "488b8780000000", "tracker_watermark_2", "load running max watermark [tracker+0x80]"),
    (0x2760627, "493b5c2410", "tracker_watermark_2", "compare height against seal target"),
    (0x276063A, "4881eb50c30000", "tracker_watermark_2", "saturating cutoff height - 50000 (0xc350)"),
    (0x5AFB227, "4939c7", "tracker_record_slow_abci", "slow watermark unsigned max compare"),
    (0x5AFB284, "4881ea50c30000", "tracker_record_slow_abci", "slow saturating cutoff height - 50000"),
    (0x3C128CA, "498b442428", "state_restore_l76_82", "load persisted checkpoint height [S+0x28]"),
    (0x3C128D4, "4c39f8", "state_restore_l76_82", "compare persisted height against requested"),
    (0x3C1352F, "488d1572328602", "state_loader_l123", "reference state.rs:123:37 Location"),
    (0x3C1353B, "4883f801", "state_loader_l123", "compare loader tag with 1"),
    (0x22ED1F0, "55", "state_freeze_l201_live", "state freeze-height check entry"),
    (0x22EC9C9, "3da2010000", "state_exec_l460_live", "compare action result against 0x1a2 success"),
]

EXPECTED_RODATA_LITERALS = [
    (0x44BF20, "tar_evm_checkpoints failed: "),
    (0x43905E, "prune_lowest_evm_checkpoints failed"),
    (0x7A1478, "no evm state checkpoints to tar"),
    (0x7A1497, "TAR_COMPLETE"),
    (0x7A14AB, "daily evm checkpoint tar already exists, skipping"),
    (0x7BD544, "straggler evm state checkpoint"),
    (0x5F41D3, "computed exchange abci hash"),
    (0x5F41EE, "serialized abci state"),
    (0x5EADC8, "linked abci state"),
    (0x5EADD9, "assertion failed: freeze_height >="),
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
    return data, sections, bounds, relocs


def read_va(data: bytes, sections: list, va: int, size: int) -> bytes:
    sec = next((s for s in sections if s["address"] <= va and va + size <= s["address"] + s["size"]), None)
    if sec is None or sec["offset"] == 0:
        raise ValueError(f"VA 0x{va:x}..0x{va+size:x} not file-backed")
    off = sec["offset"] + (va - sec["address"])
    return data[off : off + size]


def build_records() -> dict:
    return {
        "target": {"path": TARGET_REL, "size": TARGET_SIZE, "sha256": TARGET_SHA256},
        "source_files": ABCI_FILES,
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


def verify_record_dict(data: bytes, sections: list, bounds: set, relocs: dict, record: dict) -> dict:
    seen_files = set()
    for loc in record["locations"]:
        slot = int(loc["slot"], 16)
        expected_file = loc["file"].encode("utf-8")
        str_va = relocs.get(slot)
        if str_va is None:
            raise ValueError(f"Location slot 0x{slot:x} missing relocation")
        flen, line, col = struct.unpack("<QII", read_va(data, sections, slot + 8, 16))
        actual_file = read_va(data, sections, str_va, flen)
        if actual_file != expected_file or line != loc["line"] or col != loc["col"]:
            raise ValueError(
                f"Location 0x{slot:x} mismatch: {actual_file!r}:{line}:{col} != {expected_file!r}:{loc['line']}:{loc['col']}"
            )
        seen_files.add(loc["file"])
    if sorted(seen_files) != sorted(record["source_files"]):
        raise ValueError(f"abci source file coverage mismatch: {sorted(seen_files)}")

    fde_map = {}
    for fde in record["fdes"]:
        s, e = int(fde["start"], 16), int(fde["end"], 16)
        if (s, e) not in bounds:
            raise ValueError(f"FDE {fde['name']} 0x{s:x}..0x{e:x} not in indexed .eh_frame")
        fde_map[fde["name"]] = (s, e)

    for anc in record["anchors"]:
        va = int(anc["va"], 16)
        expected = bytes.fromhex(anc["bytes"])
        s, e = fde_map[anc["fde"]]
        if not (s <= va < va + len(expected) <= e):
            raise ValueError(f"anchor 0x{va:x} outside FDE {anc['fde']}")
        actual = read_va(data, sections, va, len(expected))
        if actual != expected:
            raise ValueError(f"anchor 0x{va:x} bytes mismatch: {actual.hex()} != {expected.hex()}")

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


def run_negative_controls(data, sections, bounds, relocs, record) -> int:
    def clone():
        return json.loads(json.dumps(record))

    controls = []
    # 1. Bad Location line
    c1 = clone()
    c1["locations"][0]["line"] += 1
    controls.append(("bad_location_line", c1))
    # 2. Bad % 10000 magic multiplier
    c2 = clone()
    c2["anchors"][3]["bytes"] = "48b8927efb3a70ce88d2"
    controls.append(("bad_cadence_multiplier", c2))
    # 3. Bad prune keep count (100 -> 99)
    c3 = clone()
    c3["anchors"][10]["bytes"] = "be63000000"
    controls.append(("bad_prune_keep_100", c3))
    # 4. Bad tracker prune window 50000
    c4 = clone()
    c4["anchors"][15]["bytes"] = "4881eb4fc30000"
    controls.append(("bad_tracker_prune_window", c4))
    # 5. Bad action success code 0x1a2
    c5 = clone()
    c5["anchors"][23]["bytes"] = "3da3010000"
    controls.append(("bad_action_success_code", c5))
    # 6. Bad rodata literal
    c6 = clone()
    c6["rodata_literals"][3]["text"] = "TAR_COMPLETZ"
    controls.append(("bad_tar_complete_literal", c6))

    for name, mutated in controls:
        try:
            verify_record_dict(data, sections, bounds, relocs, mutated)
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

    data, sections, bounds, relocs = load_elf(args.target)
    record = build_records() if args.write or not RECORDS_PATH.is_file() else json.loads(RECORDS_PATH.read_text())
    stats = verify_record_dict(data, sections, bounds, relocs, record)
    if args.write:
        RECORDS_PATH.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    rejected = run_negative_controls(data, sections, bounds, relocs, record)
    print(
        f"RE-009-node115-abci-crate-map verified: "
        f"{stats['source_files']}/4 abci files, {stats['locations']} Locations, "
        f"{stats['fdes']} FDEs, {stats['anchors']} anchors, {stats['literals']} literals, "
        f"{rejected}/{rejected} negative controls rejected."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
