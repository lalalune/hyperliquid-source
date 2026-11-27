#!/usr/bin/env python3
"""Static verifier for RE-009-node115-exchange-root-capture-and-db-paths.

Verifies against node #115 (artifacts/node/115/hl-node):
1. All 74 contiguous `Exchange` state-root field capture offsets (`rsp+0x128..=0x370`)
   in BOTH live (`0x269a1b0..0x269ab6b`) and slow (`0x4e34ce0..0x4e3569b`) engines,
   proving exact 74/74 slot->offset layout parity between live and slow builds.
2. `db/src/db_home.rs:286..317` (`0x44681e0..0x4468b62`) checkpoint path formatting
   (`"/checkpoint"` at `.rodata 0x434739` and `"/lt_hashes.json"` at `.rodata 0x44f3c9`).
3. `0x51520f0..0x51528fb` timer maturity arithmetic (`0x515218d..0x51522cd`: `f64`
   delay seconds -> `Duration::from_secs_f64` slot `0x64e0f70 -> 0x15ed960`,
   `1_000_000_000` ns/s `0x3b9aca00`, `i64::MAX` clamp `0x7fffffffffffffff`,
   `NaiveDateTime::checked_add_signed` slot `0x64e0f78 -> 0x162a9a0`, `cmp [r15], edx; setge dl`).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

import capstone

ROOT = Path(__file__).resolve().parents[3]
PACKET_DIR = Path(__file__).resolve().parent
RECORDS_PATH = PACKET_DIR / "records.json"

TARGET_REL = "artifacts/node/115/hl-node"
TARGET_SIZE = 105896032
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

sys.path.insert(0, str(ROOT / "tools"))
from elf_index import unwind_index  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

EXPECTED_FDES = [
    ("exchange_root_capture_live", 0x269A1B0, 0x269AB6B),
    ("exchange_root_capture_slow", 0x4E34CE0, 0x4E3569B),
    ("db_home_checkpoint_save", 0x44681E0, 0x4468B62),
    ("tracker_timer_callback", 0x51520F0, 0x51528FB),
]

# All 74 contiguous Exchange field offsets captured at rsp+0x128..=rsp+0x370 (step 8).
EXPECTED_74_OFFSETS = [
    0x0000, 0x07C0, 0x0080, 0x07D8, 0x0968, 0x0B9A, 0x0B98, 0x09F8,
    0x0670, 0x0B78, 0x0A78, 0x09B0, 0x0A18, 0x0B99, 0x0B90, 0x0A38,
    0x3AC0, 0x3AD8, 0x3AF0, 0x4158, 0x4168, 0x3C58, 0x41E8, 0x0BA0,
    0x3F08, 0x0D88, 0x4200, 0x4220, 0x10E8, 0x4178, 0x4288, 0x4294,
    0x4228, 0x3CE8, 0x3F88, 0x4188, 0x3FA8, 0x3FC8, 0x42AC, 0x4230,
    0x4238, 0x10F8, 0x4240, 0x3A00, 0x3A40, 0x3A80, 0x1108, 0x3D40,
    0x4198, 0x3FF8, 0x4018, 0x4038, 0x37E0, 0x42AD, 0x4058, 0x40A0,
    0x40C0, 0x41A8, 0x41D8, 0x4250, 0x42A0, 0x42AE, 0x4268, 0x37F0,
    0x4138, 0x42AF, 0x3830, 0x3D78, 0x3858, 0x42B0, 0x4270, 0x3D98,
    0x3E50, 0x3908,
]

EXPECTED_ANCHORS = [
    (0x44683A8, "488d358ac3fcfb", "db_home_checkpoint_save", "reference '/checkpoint' literal"),
    (0x446857F, "488d35436efefb", "db_home_checkpoint_save", "reference '/lt_hashes.json' literal (1)"),
    (0x44685D9, "488d35e96dfefb", "db_home_checkpoint_save", "reference '/lt_hashes.json' literal (2)"),
    (0x515218D, "f20f1000", "tracker_timer_callback", "load f64 delay seconds from [tracker+0x88]"),
    (0x51521AA, "ff15c0ed3801", "tracker_timer_callback", "call Duration::from_secs_f64 via slot 0x64e0f70"),
    (0x51521B2, "b900ca9a3b", "tracker_timer_callback", "load 1_000_000_000 ns/s (0x3b9aca00)"),
    (0x51521C6, "48b8ffffffffffffff7f", "tracker_timer_callback", "load i64::MAX clamp (0x7fffffffffffffff)"),
    (0x5152207, "ff156bed3801", "tracker_timer_callback", "call checked_add_signed via slot 0x64e0f78"),
    (0x51522CA, "413917", "tracker_timer_callback", "compare current_time >= inserted_time + delay"),
    (0x51522CD, "0f9dc2", "tracker_timer_callback", "setge dl (timer mature flag)"),
]

EXPECTED_SLOTS = [
    ("duration_from_secs_f64", 0x64E0F70, 0x15ED960),
    ("naive_datetime_checked_add_signed", 0x64E0F78, 0x162A9A0),
]

EXPECTED_LITERALS = [
    (0x43473B, "/checkpoint"),
    (0x44F3CB, "/lt_hashes.json"),
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


def extract_74_captures(data: bytes, sections: list, start: int, end: int) -> list[tuple[int, int]]:
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.syntax = capstone.CS_OPT_SYNTAX_INTEL
    code = read_va(data, sections, start, end - start)
    last_lea = {}
    caps = {}
    for ins in md.disasm(code, start):
        if ins.mnemonic == "lea" and "[r15" in ins.op_str:
            reg = ins.op_str.split(",")[0].strip()
            off_s = ins.op_str.split("[r15")[1].split("]")[0].strip()
            off = 0 if not off_s else int(off_s.replace(" ", ""), 16)
            last_lea[reg] = off
        elif ins.mnemonic == "mov" and ins.op_str.startswith("qword ptr [rsp + "):
            slot = int(ins.op_str.split("[rsp + ")[1].split("]")[0], 16)
            src = ins.op_str.split(",")[1].strip()
            if 0x128 <= slot <= 0x370:
                if src == "r15":
                    caps[slot] = 0
                elif src in last_lea:
                    caps[slot] = last_lea[src]
    return sorted(caps.items())


def build_records() -> dict:
    return {
        "target": {"path": TARGET_REL, "size": TARGET_SIZE, "sha256": TARGET_SHA256},
        "fdes": [{"name": n, "start": f"0x{s:x}", "end": f"0x{e:x}"} for n, s, e in EXPECTED_FDES],
        "capture_slots": [
            {"index": i, "rsp_offset": f"0x{0x128 + i * 8:x}", "exchange_offset": f"0x{off:x}"}
            for i, off in enumerate(EXPECTED_74_OFFSETS)
        ],
        "anchors": [
            {"va": f"0x{va:x}", "bytes": hx, "fde": fde, "role": role}
            for va, hx, fde, role in EXPECTED_ANCHORS
        ],
        "relocation_slots": [
            {"name": n, "slot": f"0x{slot:x}", "target": f"0x{t:x}"}
            for n, slot, t in EXPECTED_SLOTS
        ],
        "rodata_literals": [{"va": f"0x{va:x}", "text": txt} for va, txt in EXPECTED_LITERALS],
    }


def verify_record_dict(data: bytes, sections: list, bounds: set, relocs: dict, record: dict) -> dict:
    fde_map = {}
    for fde in record["fdes"]:
        s, e = int(fde["start"], 16), int(fde["end"], 16)
        if (s, e) not in bounds:
            raise ValueError(f"FDE {fde['name']} 0x{s:x}..0x{e:x} not in indexed .eh_frame")
        fde_map[fde["name"]] = (s, e)

    expected_pairs = [
        (int(r["rsp_offset"], 16), int(r["exchange_offset"], 16))
        for r in record["capture_slots"]
    ]
    live_pairs = extract_74_captures(data, sections, *fde_map["exchange_root_capture_live"])
    slow_pairs = extract_74_captures(data, sections, *fde_map["exchange_root_capture_slow"])
    if live_pairs != expected_pairs:
        raise ValueError(f"live capture mismatch: {len(live_pairs)} vs {len(expected_pairs)}")
    if slow_pairs != expected_pairs:
        raise ValueError(f"slow capture mismatch: {len(slow_pairs)} vs {len(expected_pairs)}")

    for anc in record["anchors"]:
        va = int(anc["va"], 16)
        exp = bytes.fromhex(anc["bytes"])
        s, e = fde_map[anc["fde"]]
        if not (s <= va < va + len(exp) <= e):
            raise ValueError(f"anchor 0x{va:x} outside FDE {anc['fde']}")
        act = read_va(data, sections, va, len(exp))
        if act != exp:
            raise ValueError(f"anchor 0x{va:x} mismatch: {act.hex()} != {exp.hex()}")

    for sl in record["relocation_slots"]:
        slot = int(sl["slot"], 16)
        target = int(sl["target"], 16)
        if relocs.get(slot) != target:
            raise ValueError(f"slot 0x{slot:x} target mismatch")

    for lit in record["rodata_literals"]:
        va = int(lit["va"], 16)
        exp = lit["text"].encode("utf-8")
        act = read_va(data, sections, va, len(exp))
        if act != exp:
            raise ValueError(f"rodata literal 0x{va:x} mismatch: {act!r} != {exp!r}")

    return {
        "fdes": len(fde_map),
        "capture_slots": len(expected_pairs),
        "anchors": len(record["anchors"]),
        "slots": len(record["relocation_slots"]),
        "literals": len(record["rodata_literals"]),
    }


def run_negative_controls(data, sections, bounds, relocs, record) -> int:
    def clone():
        return json.loads(json.dumps(record))

    controls = []
    # 1. Corrupt tracker +0x3e50 offset in slot 72
    c1 = clone()
    c1["capture_slots"][72]["exchange_offset"] = "0x3e58"
    controls.append(("corrupted_3e50_capture_slot", c1))
    # 2. Drop one capture slot (73 instead of 74)
    c2 = clone()
    c2["capture_slots"].pop()
    controls.append(("truncated_capture_table", c2))
    # 3. Corrupt "/lt_hashes.json" literal
    c3 = clone()
    c3["rodata_literals"][1]["text"] = "/lt_hashes.jsox"
    controls.append(("corrupted_lt_hashes_literal", c3))
    # 4. Corrupt ns/s constant 0x3b9aca00
    c4 = clone()
    c4["anchors"][5]["bytes"] = "b901ca9a3b"
    controls.append(("corrupted_ns_per_sec", c4))
    # 5. Invert setge -> setl in timer maturity check
    c5 = clone()
    c5["anchors"][9]["bytes"] = "0f9cc2"
    controls.append(("inverted_timer_setge", c5))
    # 6. Corrupt Duration::from_secs_f64 slot target
    c6 = clone()
    c6["relocation_slots"][0]["target"] = "0x15ed964"
    controls.append(("corrupted_duration_slot", c6))

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

    data, sections, _, bounds, relocs = load_elf(args.target)
    record = build_records() if args.write or not RECORDS_PATH.is_file() else json.loads(RECORDS_PATH.read_text())
    stats = verify_record_dict(data, sections, bounds, relocs, record)
    if args.write:
        RECORDS_PATH.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    rejected = run_negative_controls(data, sections, bounds, relocs, record)
    print(
        f"RE-009-node115-exchange-root-capture-and-db-paths verified: "
        f"{stats['capture_slots']}/74 live==slow Exchange capture offsets, "
        f"{stats['fdes']} FDEs, {stats['anchors']} anchors, {stats['slots']} reloc slots, "
        f"{stats['literals']} literals, {rejected}/{rejected} negative controls rejected."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
