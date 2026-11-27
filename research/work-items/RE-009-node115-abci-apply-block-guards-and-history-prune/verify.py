#!/usr/bin/env python3
"""Verify RE-009 node #115 AbciEngine apply_block guards, history split_off cutoff, and BlockReader entry points."""

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

EXPECTED_FDES = [
    ("abci_engine_apply_block", 0x5A04E40, 0x5A065F8),
    ("abci_history_split_off", 0x4DE5AD0, 0x4DE603E),
    ("block_reader_block", 0x2A191E0, 0x2A195A7),
    ("block_reader_range_query_inclusive", 0x2A0ACC0, 0x2A0B327),
]

EXPECTED_ANCHORS = [
    ("abci_hardfork_freeze_check", 0x5A04EC3, "4c8b89e81000004c8b91f01000004983f90175134c8b41284d39c20f82f01300000f844b130000"),
    ("abci_round_monotonic_check", 0x5A04EEA, "4939fd0f862a130000"),
    ("abci_parent_round_eq_check", 0x5A04EF3, "4c8b41304c894424104939f80f8545130000"),
    ("abci_parent_time_eq_check", 0x5A04F05, "4c8b4118488b79204c8944241048897c24184939f00f854d1300004839d70f8544130000"),
    ("abci_features_v3_check", 0x5A04F52, "80b99a0b0000030f8557130000"),
    ("abci_history_split_cutoff", 0x5A05EA1, "41807c2410000f8414010000498b44241848ffc048c7c1ffffffff480f45c848898c24d8000000498d9c2400040000488dbc2498000000488d9424d80000004889dee8e8fb3dff"),
    ("abci_panic_round_gt_parent", 0x5A0621D, "488d15bc1cab00be26000000488d3deb43f3fae994"),
    ("abci_panic_not_frozen", 0x5A06235, "488d151c1dab00be29000000488d3d1644f3faeb7f"),
    ("abci_panic_features_ok", 0x5A062B6, "488d15831cab00be1d000000488d3d7843f3fa"),
    ("block_reader_block_lea", 0x2A19258, "488d35d05ea2fd"),
    ("block_reader_range_lea", 0x2A0AEEB, "488d35eceea3fd"),
]

EXPECTED_LITERALS = [
    ("assert_round_gt_parent", 0x93A61B, "assertion failed: round > parent_round"),
    ("assert_features_ok", 0x93A641, "assertion failed: features_ok"),
    ("assert_not_frozen", 0x93A65E, "assertion failed: !self.state.is_frozen()"),
    ("computed_abci_digest_tpl", 0x44C994, "computed abci digest at height="),
    ("block_reader_block_name", 0x43F132, "BlockReader::block"),
    ("block_reader_range_name", 0x449DE1, "BlockReader::range_query_inclusive"),
]


def parse_elf_sections(data: bytes) -> dict[str, tuple[int, int, int]]:
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
    shstr_off = struct.unpack_from("<Q", data, e_shoff + e_shstrndx * e_shentsize + 24)[0]
    secs: dict[str, tuple[int, int, int]] = {}
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name, _sh_type, _sh_flags, sh_addr, sh_offset, sh_size = struct.unpack_from(
            "<IIQQQQ", data, off
        )
        end = data.find(b"\0", shstr_off + sh_name)
        secs[data[shstr_off + sh_name : end].decode("latin1")] = (sh_addr, sh_offset, sh_size)
    return secs


def load_fde_map() -> dict[int, int]:
    fdes: dict[int, int] = {}
    if not FDE_TSV.exists():
        return fdes
    with FDE_TSV.open("r", encoding="utf-8") as fh:
        fh.readline()
        for line in fh:
            parts = line.strip().split("\t")
            if len(parts) >= 2:
                s = int(parts[0], 16) if parts[0].startswith("0x") else int(parts[0])
                e = int(parts[1], 16) if parts[1].startswith("0x") else int(parts[1])
                fdes[s] = e
    return fdes


def read_section_bytes(
    data: bytes, secs: dict[str, tuple[int, int, int]], sec_name: str, va: int, length: int
) -> bytes:
    sh_addr, sh_offset, sh_size = secs[sec_name]
    rel = va - sh_addr
    if rel < 0 or rel + length > sh_size:
        raise ValueError(f"VA 0x{va:x}+{length} outside {sec_name}")
    return data[sh_offset + rel : sh_offset + rel + length]


def build_records(data: bytes) -> dict[str, object]:
    secs = parse_elf_sections(data)
    fde_map = load_fde_map()
    fdes_out = []
    for label, start, end in EXPECTED_FDES:
        if fde_map and fde_map.get(start) != end:
            raise ValueError(f"FDE mismatch for {label}: {fde_map.get(start)} != 0x{end:x}")
        body = read_section_bytes(data, secs, ".text", start, end - start)
        fdes_out.append(
            {
                "label": label,
                "start_va": f"0x{start:x}",
                "end_va": f"0x{end:x}",
                "size": end - start,
                "sha256": hashlib.sha256(body).hexdigest(),
            }
        )
    anchors_out = [
        {
            "label": label,
            "va": f"0x{va:x}",
            "bytes_hex": read_section_bytes(data, secs, ".text", va, len(hex_s) // 2).hex(),
        }
        for label, va, hex_s in EXPECTED_ANCHORS
    ]
    literals_out = [
        {
            "label": label,
            "va": f"0x{va:x}",
            "text": read_section_bytes(data, secs, ".rodata", va, len(txt)).decode("ascii"),
        }
        for label, va, txt in EXPECTED_LITERALS
    ]
    return {
        "schema_version": 1,
        "work_item": "RE-009-node115-abci-apply-block-guards-and-history-prune",
        "target_binary": {
            "path": "artifacts/node/115/hl-node",
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        },
        "apply_block_invariants": {
            "required_feature_version": 3,
            "feature_version_offset": "0xb9a",
            "hardfork_tag_offset": "0x10e8",
            "hardfork_height_offset": "0x10f0",
            "state_time_offset": "0x18",
            "state_height_offset": "0x28",
            "state_round_offset": "0x30",
            "history_prune_cutoff_rule": "watermark.saturating_add(1)",
        },
        "fdes": fdes_out,
        "anchors": anchors_out,
        "literals": literals_out,
    }


def verify_records(records: dict[str, object], data: bytes) -> None:
    tb = records["target_binary"]
    if tb["sha256"] != EXPECTED_BINARY_SHA256 or tb["size"] != EXPECTED_BINARY_SIZE:
        raise ValueError("target_binary metadata mismatch")
    if hashlib.sha256(data).hexdigest() != EXPECTED_BINARY_SHA256:
        raise ValueError("on-disk binary SHA-256 mismatch")

    inv = records["apply_block_invariants"]
    if inv["required_feature_version"] != 3 or inv["feature_version_offset"] != "0xb9a":
        raise ValueError("apply_block_invariants mismatch")

    secs = parse_elf_sections(data)
    if len(records["fdes"]) != len(EXPECTED_FDES):
        raise ValueError("FDE count mismatch")
    for row, (label, start, end) in zip(records["fdes"], EXPECTED_FDES):
        if row["label"] != label or int(row["start_va"], 16) != start or int(row["end_va"], 16) != end:
            raise ValueError(f"FDE descriptor mismatch for {label}")
        body = read_section_bytes(data, secs, ".text", start, end - start)
        if hashlib.sha256(body).hexdigest() != row["sha256"]:
            raise ValueError(f"FDE sha256 mismatch for {label}")

    if len(records["anchors"]) != len(EXPECTED_ANCHORS):
        raise ValueError("anchor count mismatch")
    for row, (label, va, hex_s) in zip(records["anchors"], EXPECTED_ANCHORS):
        if row["label"] != label or int(row["va"], 16) != va or row["bytes_hex"] != hex_s:
            raise ValueError(f"anchor mismatch for {label}")
        actual = read_section_bytes(data, secs, ".text", va, len(hex_s) // 2).hex()
        if actual != hex_s:
            raise ValueError(f"binary anchor mismatch for {label}")

    if len(records["literals"]) != len(EXPECTED_LITERALS):
        raise ValueError("literal count mismatch")
    for row, (label, va, txt) in zip(records["literals"], EXPECTED_LITERALS):
        if row["label"] != label or int(row["va"], 16) != va or row["text"] != txt:
            raise ValueError(f"literal mismatch for {label}")
        actual = read_section_bytes(data, secs, ".rodata", va, len(txt)).decode("ascii")
        if actual != txt:
            raise ValueError(f"binary literal mismatch for {label}")


def run_negative_controls(records: dict[str, object], data: bytes) -> int:
    mutations = []
    m1 = copy.deepcopy(records)
    m1["apply_block_invariants"]["required_feature_version"] = 2
    mutations.append(("wrong_feature_version", m1))

    m2 = copy.deepcopy(records)
    m2["fdes"][0]["sha256"] = "0" * 64
    mutations.append(("corrupted_fde_sha256", m2))

    m3 = copy.deepcopy(records)
    m3["anchors"][4]["bytes_hex"] = "90" * (len(m3["anchors"][4]["bytes_hex"]) // 2)
    mutations.append(("corrupted_anchor", m3))

    m4 = copy.deepcopy(records)
    m4["literals"][2]["text"] = "X" * len(m4["literals"][2]["text"])
    mutations.append(("corrupted_literal", m4))

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
        verify_records(records, data)
        RECORDS_PATH.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    else:
        records = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))
        verify_records(records, data)

    neg = run_negative_controls(records, data) if args.self_test else 0
    print(
        f"RE-009-node115-abci-apply-block-guards-and-history-prune verified: "
        f"{len(EXPECTED_FDES)} FDEs, {len(EXPECTED_ANCHORS)} anchors, {len(EXPECTED_LITERALS)} literals"
        + (f", {neg}/{neg} negative controls rejected." if args.self_test else ".")
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
