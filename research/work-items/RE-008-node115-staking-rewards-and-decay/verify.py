#!/usr/bin/env python3
"""Verify node #115 CStaking reward emission rate, periodic bucket guards, commission split, and 0.99 decay."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import struct
import sys
from pathlib import Path

PACKET_DIR = Path(__file__).resolve().parent
REPO_ROOT = PACKET_DIR.parents[2]
BINARY_PATH = REPO_ROOT / "artifacts" / "node" / "115" / "hl-node"
FDE_TSV = REPO_ROOT / "work" / "index" / "node-115-fde.tsv"
RECORDS_PATH = PACKET_DIR / "records.json"

EXPECTED_BINARY_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
)
EXPECTED_BINARY_SIZE = 105_896_032

FUNCTIONS = [
    ("reward_rate_per_step", 0x3C38360, 0x3C3854E),
    ("maybe_stage_distribute_and_decay", 0x3C3F780, 0x3C403F7),
    ("stage_reward", 0x422C320, 0x422C95F),
    ("stage_validator_reward_closure", 0x3D66500, 0x3D66A5D),
    ("distribute_staged_rewards", 0x422ABF0, 0x422C320),
    ("decay_staking", 0x422A630, 0x422ABE5),
]

RODATA_F64_ANCHORS = [
    ("seconds_per_year_365_25d", 0x459058, 31_557_600.0, "0x417e187e00000000"),
    ("ms_per_second", 0x459A60, 1_000.0, "0x408f400000000000"),
    ("emission_base_factor", 0x4596B0, 0.015, "0x3f8eb851eb851eb8"),
    ("emission_quadratic_coeff", 0x459420, -0.5, "0xbfe0000000000000"),
    ("commission_bps_scale", 0x459B50, 0.0001, "0x3f1a36e2eb1c432d"),
    ("reward_fraction_ceiling", 0x4590B8, 1.01, "0x3ff028f5c28f5c29"),
    ("staking_decay_factor", 0x459208, 0.99, "0x3fefae147ae147ae"),
    ("positive_infinity", 0x459010, float("inf"), "0x7ff0000000000000"),
]

RODATA_STR_ANCHORS = [
    ("c_staking_stage_reward", 0x7BBE59, "c_staking_stage_reward"),
    ("c_staking_distribute_staged_rewards", 0x7BBE6F, "c_staking_distribute_staged_rewards"),
    ("decay_staking", 0x7BBEE3, "decay_staking"),
]

# Key instruction windows inside the 6 FDEs (name, func, start_va, end_va, expected_bytes_hex)
WINDOWS = [
    ("reward_rate_sqrt_max_quadratic", "reward_rate_per_step", 0x3C3850D, 0x3C38539,
     "f20f51c0f20f1015971182fcf20f5fc2f20f5ed0660f28c2f20f59c2f20f5905ef0e82fcf20f58c2f20f5ec1"),
    ("periodic_stage_bucket_guard", "maybe_stage_distribute_and_decay", 0x3C3F8A5, 0x3C3F8BB,
     "498b8ec00200004839c87607498986c00200004839c8"),
    ("periodic_distribute_bucket_guard", "maybe_stage_distribute_and_decay", 0x3C3FA5B, 0x3C3FA71,
     "498b8ed00200004839c87607498986d00200004839c8"),
    ("periodic_decay_bucket_guard", "maybe_stage_distribute_and_decay", 0x3C402A7, 0x3C402BD,
     "498b8eb00200004839c87607498986b00200004839c8"),
    ("stage_reward_calls_rate", "stage_reward", 0x422C371, 0x422C376, "e8eabfa0ff"),
    ("stage_closure_reserve_cap", "stage_validator_reward_closure", 0x3D669E6, 0x3D66A16,
     "4c8b63084d89e54d29fd7312488d357f0a72024531ed31ffff15a4e477024c896b084d29ec498b1e4889d84c01e07228"),
    ("distribute_commission_bps_guard", "distribute_staged_rewards", 0x422B0D0, 0x422B0E6,
     "f20f590578ea22fcf20f100dd8df22fc660f2ec8731a"),
    ("distribute_delegator_share_guard", "distribute_staged_rewards", 0x422B747, 0x422B76B,
     "f20f5e842430020000660f57c9660f2ec17246f20f100d56d922fc660f2ec8b900000000"),
    ("decay_asymmetric_drop_and_099", "decay_staking", 0x422A7A0, 0x422A7D8,
     "488b02488b4a084889ce4829c672e166480f6ece660f620d546a22fc660f5c0dac5922fc660f28c1660f15c1f20f58c1f20f590530ea22fc"),
]


def parse_sections(blob: bytes) -> dict[str, tuple[int, int, int]]:
    e_shoff = struct.unpack_from("<Q", blob, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", blob, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", blob, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", blob, 0x3E)[0]
    shstr_off = struct.unpack_from("<Q", blob, e_shoff + e_shstrndx * e_shentsize + 24)[0]
    secs = {}
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name, _sh_type, _sh_flags, sh_addr, sh_offset, sh_size, _sh_link, _sh_info = (
            struct.unpack_from("<IIQQQQII", blob, off)
        )
        end = blob.find(b"\0", shstr_off + sh_name)
        secs[blob[shstr_off + sh_name : end].decode("latin1")] = (sh_addr, sh_offset, sh_size)
    return secs


def load_fde_map() -> dict[int, int]:
    fdes: dict[int, int] = {}
    with FDE_TSV.open("r", encoding="utf-8") as fh:
        fh.readline()
        for line in fh:
            parts = line.strip().split("\t")
            if len(parts) >= 2:
                s = int(parts[0], 16) if parts[0].startswith("0x") else int(parts[0])
                e = int(parts[1], 16) if parts[1].startswith("0x") else int(parts[1])
                fdes[s] = e
    return fdes


def build_records(data: bytes) -> dict[str, object]:
    secs = parse_sections(data)
    t_addr, t_off, _ = secs[".text"]
    r_addr, r_off, _ = secs[".rodata"]
    fde_map = load_fde_map()

    fn_rows = []
    for name, s, e in FUNCTIONS:
        if fde_map.get(s) != e:
            raise ValueError(f"FDE mismatch for {name}: got {fde_map.get(s)}, expected 0x{e:x}")
        body = data[t_off + (s - t_addr) : t_off + (e - t_addr)]
        fn_rows.append(
            {
                "name": name,
                "start_va": f"0x{s:x}",
                "end_va": f"0x{e:x}",
                "size": len(body),
                "sha256": hashlib.sha256(body).hexdigest(),
            }
        )

    f64_rows = []
    for name, va, expected_val, expected_bits in RODATA_F64_ANCHORS:
        raw = data[r_off + (va - r_addr) : r_off + (va - r_addr) + 8]
        bits = f"0x{struct.unpack('<Q', raw)[0]:016x}"
        val = struct.unpack("<d", raw)[0]
        if bits != expected_bits:
            raise ValueError(f"rodata f64 mismatch for {name}: got {bits}, expected {expected_bits}")
        f64_rows.append(
            {
                "name": name,
                "va": f"0x{va:x}",
                "bits": bits,
                "value": "inf" if val == float("inf") else val,
            }
        )

    str_rows = []
    for name, va, expected_text in RODATA_STR_ANCHORS:
        raw = data[r_off + (va - r_addr) : r_off + (va - r_addr) + len(expected_text)]
        actual = raw.decode("ascii")
        if actual != expected_text:
            raise ValueError(f"rodata str mismatch for {name}: got {actual!r}")
        str_rows.append({"name": name, "va": f"0x{va:x}", "length": len(actual), "text": actual})

    win_rows = []
    for name, fn, s, e, exp_hex in WINDOWS:
        raw = data[t_off + (s - t_addr) : t_off + (e - t_addr)]
        if raw.hex() != exp_hex:
            raise ValueError(f"window bytes mismatch for {name}: got {raw.hex()}, expected {exp_hex}")
        win_rows.append(
            {
                "name": name,
                "function": fn,
                "start_va": f"0x{s:x}",
                "end_va": f"0x{e:x}",
                "size": len(raw),
                "hex": raw.hex(),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        )

    return {
        "schema_version": 1,
        "work_item": "RE-008-node115-staking-rewards-and-decay",
        "target_binary": {
            "path": "artifacts/node/115/hl-node",
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        },
        "summary": {
            "functions": len(fn_rows),
            "total_function_bytes": sum(r["size"] for r in fn_rows),
            "rodata_f64_anchors": len(f64_rows),
            "rodata_str_anchors": len(str_rows),
            "instruction_windows": len(win_rows),
            "total_window_bytes": sum(r["size"] for r in win_rows),
        },
        "functions": fn_rows,
        "rodata_f64_anchors": f64_rows,
        "rodata_str_anchors": str_rows,
        "windows": win_rows,
    }


def verify_records(records: dict[str, object], data: bytes) -> None:
    tb = records["target_binary"]
    if tb["sha256"] != EXPECTED_BINARY_SHA256 or tb["size"] != EXPECTED_BINARY_SIZE:
        raise ValueError("target_binary metadata mismatch")
    if hashlib.sha256(data).hexdigest() != EXPECTED_BINARY_SHA256:
        raise ValueError("on-disk binary SHA-256 mismatch")
    rebuilt = build_records(data)
    if rebuilt != records:
        raise ValueError("rebuilt records diverge from committed records.json")


def run_negative_controls(records: dict[str, object], data: bytes) -> int:
    mutations = []

    m1 = copy.deepcopy(records)
    m1["functions"][0]["sha256"] = "0" * 64
    mutations.append(("corrupted_function_sha256", m1))

    m2 = copy.deepcopy(records)
    m2["rodata_f64_anchors"][2]["bits"] = "0x3ff0000000000000"
    mutations.append(("corrupted_emission_base_factor", m2))

    m3 = copy.deepcopy(records)
    m3["windows"][0]["hex"] = "00" * m3["windows"][0]["size"]
    mutations.append(("corrupted_window_bytes", m3))

    m4 = copy.deepcopy(records)
    m4["rodata_str_anchors"][0]["text"] = "wrong_timer"
    mutations.append(("corrupted_rodata_str", m4))

    for name, mutated in mutations:
        try:
            verify_records(mutated, data)
        except ValueError:
            continue
        raise AssertionError(f"negative control {name} was unexpectedly accepted")
    return len(mutations)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    data = BINARY_PATH.read_bytes()
    if args.write:
        records = build_records(data)
        RECORDS_PATH.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
        verify_records(records, data)
    else:
        records = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))
        verify_records(records, data)

    neg = run_negative_controls(records, data) if args.self_test else 0
    s = records["summary"]
    print(
        f"RE-008-node115-staking-rewards-and-decay verified: "
        f"{s['functions']} FDEs ({s['total_function_bytes']} B), "
        f"{s['rodata_f64_anchors']} f64 anchors, "
        f"{s['rodata_str_anchors']} str anchors, "
        f"{s['instruction_windows']} windows ({s['total_window_bytes']} B)"
        + (f", {neg}/{neg} negative controls rejected." if args.self_test else ".")
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
