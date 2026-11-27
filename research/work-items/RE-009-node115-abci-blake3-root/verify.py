#!/usr/bin/env python3
"""Static verifier for RE-009-node115-abci-blake3-root.

Proves that node #115's state-root digest path
(`0x548dad0 -> slot 0x64e7820 -> 0x41c5140 -> 0x160bee0 / 0x160b3a0 / 0x160bcd0`)
is exact standard unkeyed BLAKE3:
- Standard 8-word BLAKE3 IV at .rodata 0x457ae0..0x457b00
- 1024-byte chunking (0x400) and CHUNK_END (0x02) in 0x160b3a0
- ROOT (0x08) flag and 5-arm platform finalize jump table at 0x46ab4c in 0x160bcd0
- All 4 SIMD/portable compress targets via .rela.dyn slots
  (0x160d200 portable, 0x633d0c0 SSE2, 0x633fac0 SSE4.1/AVX2, 0x6345bc0 AVX-512)
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

BLAKE3_IV_VA = 0x457AE0
BLAKE3_IV = [
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
]

EXPECTED_FDES = [
    ("abci_hash_slow_2", 0x548DAD0, 0x548DCD3),
    ("outer_root_digest", 0x41C5140, 0x41C540A),
    ("blake3_platform_detect", 0x160BEE0, 0x160BF68),
    ("blake3_hasher_update", 0x160B3A0, 0x160BCCE),
    ("blake3_hasher_finalize", 0x160BCD0, 0x160BDA0),
]

EXPECTED_ANCHORS = [
    (0x548DB1A, "ff15009d0501", "abci_hash_slow_2", "call outer_root_digest via slot 0x64e7820"),
    (0x41C52D8, "ff15aaa13102", "outer_root_digest", "call Platform::detect (0x160bee0) via slot 0x64df488"),
    (0x41C52F5, "0f100de42729fc", "outer_root_digest", "load BLAKE3 IV[0..4] from .rodata 0x457ae0"),
    (0x41C5301, "0f1015e82729fc", "outer_root_digest", "load BLAKE3 IV[4..8] from .rodata 0x457af0"),
    (0x41C5367, "888424fb000000", "outer_root_digest", "store platform selector byte at context+0x6b"),
    (0x41C5387, "ff1583a13102", "outer_root_digest", "call Hasher::update (0x160b3a0) via slot 0x64df510"),
    (0x41C539A, "ff1578a13102", "outer_root_digest", "call Hasher::finalize (0x160bcd0) via slot 0x64df518"),
    (0x160B3DC, "41bf00040000", "blake3_hasher_update", "1024-byte (0x400) BLAKE3 chunk length"),
    (0x160B412, "0c02", "blake3_hasher_update", "OR domain flag CHUNK_END (0x02)"),
    (0x160BD08, "0c08", "blake3_hasher_finalize", "OR domain flag ROOT (0x08)"),
    (0x160BD12, "488d3533eee5fe", "blake3_hasher_finalize", "load 5-arm platform finalize jump table 0x46ab4c"),
    (0x160BD33, "ff15175ced04", "blake3_hasher_finalize", "call compress_in_place SSE4.1/AVX2 via slot 0x64e1950"),
    (0x160BD4C, "ff15065ced04", "blake3_hasher_finalize", "call compress_in_place AVX-512 via slot 0x64e1958"),
    (0x160BD65, "ff15f55bed04", "blake3_hasher_finalize", "call compress_in_place portable via slot 0x64e1960"),
    (0x160BD7E, "ff15e45bed04", "blake3_hasher_finalize", "call compress_in_place SSE2 via slot 0x64e1968"),
]

EXPECTED_SLOTS = [
    ("outer_root_digest", 0x64E7820, 0x41C5140),
    ("blake3_platform_detect", 0x64DF488, 0x160BEE0),
    ("blake3_hasher_update", 0x64DF510, 0x160B3A0),
    ("blake3_hasher_finalize", 0x64DF518, 0x160BCD0),
    ("compress_portable", 0x64E1960, 0x160D200),
    ("compress_sse2", 0x64E1968, 0x633D0C0),
    ("compress_sse41_avx2", 0x64E1950, 0x633FAC0),
    ("compress_avx512", 0x64E1958, 0x6345BC0),
]

FINALIZE_JT_BASE = 0x46AB4C
FINALIZE_JT_TARGETS = [0x160BD54, 0x160BD6D, 0x160BD22, 0x160BD22, 0x160BD3B]


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
        "blake3_iv": {"va": f"0x{BLAKE3_IV_VA:x}", "words": [f"0x{w:08x}" for w in BLAKE3_IV]},
        "fdes": [{"name": n, "start": f"0x{s:x}", "end": f"0x{e:x}"} for n, s, e in EXPECTED_FDES],
        "anchors": [
            {"va": f"0x{va:x}", "bytes": hx, "fde": fde, "role": role}
            for va, hx, fde, role in EXPECTED_ANCHORS
        ],
        "relocation_slots": [
            {"name": n, "slot": f"0x{slot:x}", "target": f"0x{t:x}"}
            for n, slot, t in EXPECTED_SLOTS
        ],
        "finalize_jump_table": {
            "base": f"0x{FINALIZE_JT_BASE:x}",
            "arms": [f"0x{t:x}" for t in FINALIZE_JT_TARGETS],
        },
    }


def verify_record_dict(data: bytes, sections: list, bounds: set, relocs: dict, record: dict) -> dict:
    iv_va = int(record["blake3_iv"]["va"], 16)
    actual_iv = list(struct.unpack("<8I", read_va(data, sections, iv_va, 32)))
    expected_iv = [int(w, 16) for w in record["blake3_iv"]["words"]]
    if actual_iv != expected_iv:
        raise ValueError(f"BLAKE3 IV mismatch at 0x{iv_va:x}")

    fde_map = {}
    for fde in record["fdes"]:
        s, e = int(fde["start"], 16), int(fde["end"], 16)
        if (s, e) not in bounds:
            raise ValueError(f"FDE {fde['name']} 0x{s:x}..0x{e:x} not in indexed .eh_frame")
        fde_map[fde["name"]] = (s, e)

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
            raise ValueError(f"slot 0x{slot:x} target 0x{relocs.get(slot, 0):x} != 0x{target:x}")

    jt = record["finalize_jump_table"]
    jbase = int(jt["base"], 16)
    for i, arm_hex in enumerate(jt["arms"]):
        rel = struct.unpack("<i", read_va(data, sections, jbase + i * 4, 4))[0]
        if jbase + rel != int(arm_hex, 16):
            raise ValueError(f"finalize jump table arm {i} -> 0x{jbase+rel:x} != {arm_hex}")

    return {
        "fdes": len(fde_map),
        "anchors": len(record["anchors"]),
        "slots": len(record["relocation_slots"]),
        "jt_arms": len(jt["arms"]),
    }


def run_negative_controls(data, sections, bounds, relocs, record) -> int:
    def clone():
        return json.loads(json.dumps(record))

    controls = []
    c1 = clone()
    c1["blake3_iv"]["words"][0] = "0x6a09e668"
    controls.append(("corrupted_blake3_iv", c1))
    c2 = clone()
    c2["anchors"][7]["bytes"] = "41bf00020000"
    controls.append(("corrupted_chunk_len_1024", c2))
    c3 = clone()
    c3["anchors"][9]["bytes"] = "0c04"
    controls.append(("corrupted_root_flag_8", c3))
    c4 = clone()
    c4["relocation_slots"][4]["target"] = "0x160d204"
    controls.append(("corrupted_portable_compress_slot", c4))
    c5 = clone()
    c5["finalize_jump_table"]["arms"][4] = "0x160bd22"
    controls.append(("corrupted_avx512_jt_arm", c5))

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
        f"RE-009-node115-abci-blake3-root verified: "
        f"8/8 BLAKE3 IV words, {stats['fdes']} FDEs, {stats['anchors']} anchors, "
        f"{stats['slots']} reloc slots, {stats['jt_arms']} finalize JT arms, "
        f"{rejected}/{rejected} negative controls rejected."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
