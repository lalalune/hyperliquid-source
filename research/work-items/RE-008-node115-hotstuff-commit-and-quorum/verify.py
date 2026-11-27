#!/usr/bin/env python3
"""Verify node #115 HotStuff-2 two-chain commit rule, 128-bit 2/3 stake quorum, and register_block guards."""

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
    ("hotstuff_two_chain_commit", 0x2E157C0, 0x2E197F5),
    ("register_block", 0x2E1DA10, 0x2E1F73C),
    ("commit_chain_lookup_helper", 0x2E1F740, 0x2E1F9A5),
    ("validator_stakes_has_quorum", 0x4D3E1A0, 0x4D3E30D),
    ("vote_and_msg_router", 0x2E08B90, 0x2E098D2),
]

WINDOWS = [
    ("two_chain_genesis_zero_hash_simd", "hotstuff_two_chain_commit", 0x2E15B9B, 0x2E15BBD,
     "f30f6f4048f30f6f4858660febc8660fefc0660f76c10f50c083f00f0f846d0a0000"),
    ("two_chain_consecutive_round_check", "hotstuff_two_chain_commit", 0x2E15D12, 0x2E15D50,
     "488b0048ffc048c7c1ffffffff480f44c1498d9c24a00000004d8d7c24504d397424184889da490f44d7488b124883c202480f42d14839d00f85da080000"),
    ("two_chain_monotonic_committed_round", "hotstuff_two_chain_commit", 0x2E15E38, 0x2E15E59,
     "488b0848ffc148c7c0ffffffff480f45c1488b8a800300004839c80f86500e0000"),
    ("register_block_stale_tag_3", "register_block", 0x2E1DA72, 0x2E1DA84,
     "498b85c8020000b1034839c50f827a010000"),
    ("register_block_not_new_tag_4", "register_block", 0x2E1DBEE, 0x2E1DBFE,
     "b1044c8b2c244c8b7424084c8b642410"),
    ("quorum_u128_strict_two_thirds", "validator_stakes_has_quorum", 0x4D3E2E4, 0x4D3E305,
     "4889c14889c648c1ee3fba030000004889d848f7e24801c94839c14819d60f92c0"),
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

    win_rows = []
    for name, fn, s, e, exp_hex in WINDOWS:
        raw = data[t_off + (s - t_addr) : t_off + (e - t_addr)]
        if raw.hex() != exp_hex:
            raise ValueError(f"window mismatch for {name}: got {raw.hex()}, expected {exp_hex}")
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
        "work_item": "RE-008-node115-hotstuff-commit-and-quorum",
        "target_binary": {
            "path": "artifacts/node/115/hl-node",
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        },
        "summary": {
            "functions": len(fn_rows),
            "total_function_bytes": sum(r["size"] for r in fn_rows),
            "instruction_windows": len(win_rows),
            "total_window_bytes": sum(r["size"] for r in win_rows),
        },
        "functions": fn_rows,
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
    m2["windows"][1]["hex"] = "00" * m2["windows"][1]["size"]
    mutations.append(("corrupted_two_chain_window", m2))

    m3 = copy.deepcopy(records)
    m3["windows"][5]["hex"] = "00" * m3["windows"][5]["size"]
    mutations.append(("corrupted_quorum_u128_window", m3))

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
        f"RE-008-node115-hotstuff-commit-and-quorum verified: "
        f"{s['functions']} FDEs ({s['total_function_bytes']} B), "
        f"{s['instruction_windows']} windows ({s['total_window_bytes']} B)"
        + (f", {neg}/{neg} negative controls rejected." if args.self_test else ".")
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
