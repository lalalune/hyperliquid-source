#!/usr/bin/env python3
"""Verify RE-009 node #115 DbHub 29-kind 3-shard routing and ABCI state/tracker/engine schema."""

from __future__ import annotations

import argparse
import bisect
import copy
import hashlib
import json
import struct
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
BINARY_PATH = REPO_ROOT / "artifacts" / "node" / "115" / "hl-node"
FDE_TSV = REPO_ROOT / "work" / "index" / "node-115-fde.tsv"
RECORDS_PATH = Path(__file__).resolve().parent / "records.json"

EXPECTED_BINARY_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
)
EXPECTED_BINARY_SIZE = 105_896_032

SHARD_0_MASK = 0x031F_FEFF
SHARD_1_MASK = 0x00E0_0100
PREFIX_TABLE_VA = 0x6479DF0
PREFIX_RODATA_VA = 0x7BD4ED

EXPECTED_29_PREFIXES = [
    "cA", "lu", "nf", "bi", "Ps", "uf", "aT", "rh", "et", "fH",
    "aH", "oh", "ts", "th", "up", "ua", "se", "gP", "de", "dr",
    "vb", "Et", "En", "Eb", "so", "sq", "Ea", "Ec", "Es",
]

EXPECTED_FDES = [
    ("db_hub_live_route_0", 0x3D4C7C0, 0x3D4CBE0),
    ("db_hub_live_route_1", 0x3D4CBE0, 0x3D4D000),
    ("db_hub_live_route_2", 0x3D4D000, 0x3D4D420),
    ("db_hub_slow_route_0", 0x57C58D0, 0x57C5CF0),
    ("hst_serialize_live", 0x275EF30, 0x275F127),
    ("hst_serialize_adu_helper", 0x282D550, 0x282D611),
    ("hst_serialize_h_helper", 0x282CCC0, 0x282CD89),
    ("hst_live_prune_drain", 0x2760030, 0x2760227),
    ("quorum_status_serialize", 0x28A05E0, 0x28A0856),
    ("state_serialize_checkpoint", 0x26A2C80, 0x26A326E),
    ("engine_daily_evm_tar", 0x38C40F0, 0x38C51EE),
    ("engine_straggler_filter", 0x3D5DCA0, 0x3D5DFB0),
]

EXPECTED_ANCHORS = [
    ("db_hub_live_shard0_bt", 0x3D4C7E5, "b8fffe1f03440fa3f8"),
    ("db_hub_live_tier_cmp", 0x3D4C7FA, "4080fd14"),
    ("db_hub_live_shard1_bt", 0x3D4C825, "b80001e000440fa3f8"),
    ("db_hub_live_prefix_lea", 0x3D4C899, "488d0550d572024e8b24f8"),
    ("db_hub_live_shard2_mov", 0x3D4CACB, "41b502"),
    ("db_hub_slow_shard0_bt", 0x57C58F5, "b8fffe1f03440fa3f8"),
    ("db_hub_slow_shard1_bt", 0x57C5935, "b80001e000440fa3f8"),
    ("db_hub_slow_prefix_lea", 0x57C59A9, "488d0588b6ce004e8b24f8"),
    ("hst_ser_tracker_field", 0x275EF7F, "488d35a27be9fd4889e7ba07000000"),
    ("hst_ser_qrs_field", 0x275EFE4, "488d4b48488d35407be9fd4889e7ba03000000"),
    ("hst_ser_hqh_field", 0x275F00F, "488d8b80000000488d35157be9fd4889e7ba15000000"),
    ("hst_ser_htm_field", 0x275F035, "488d4b60488d35077be9fd4889e7ba03000000"),
    ("hst_ser_adu_field", 0x282D564, "488d35df95dcfdba03000000"),
    ("hst_ser_h_field", 0x282CCD4, "488d35729edcfdba01000000"),
    ("hst_live_drain_cutoff", 0x2760048, "488b467831f6482de8030000480f43f0"),
    ("hst_live_drain_stride", 0x27600F0, "49837e200074374983c668"),
    ("quorum_status_N_lit", 0x28A0677, "488d35e5e9d5fdba01000000"),
    ("quorum_status_Q_lit", 0x28A06AD, "488d1556f0d5fd4c8d0daae9d5fd"),
    ("state_dev_null_check", 0x26A2CE4, "48b82f6465762f6e756c493306410fb64e084883f16c4809c1"),
    ("state_rmp_ext_check", 0x26A2DA4, "488d153a2cdcfdb903000000e8ebceeffe"),
    ("state_json_cap_0x80", 0x26A2E1B, "bf80000000"),
    ("engine_daily_tar_lea", 0x38C4478, "488d359c4ab7fc"),
    ("engine_straggler_mfd", 0x3D5DD85, "488d356eea6efc"),
    ("engine_straggler_msg", 0x3D5DE14, "488d0529f7a5fc"),
    ("engine_straggler_bounds", 0x3D5DE80, "488b4424504c3b287326488b04244c3b28721d488b4424484c3b280f86"),
]

EXPECTED_LITERALS = [
    ("db_kind_prefixes_29", 0x7BD4ED, "cAlunfbiPsufaTrhetfHaHohtsthupuasegPdedrvbEtEnEbsosqEaEcEs"),
    ("hst_fields_rodata", 0x5F6B28, "trackerqrshighest_quorum_heighthtmaduh"),
    ("quorum_status_NQ", 0x5FF063, "NOQ"),
    ("rmp_ext", 0x4659E5, "rmp"),
    ("json_indent_2sp", 0x5F3CC0, "  "),
    ("serialized_abci_state", 0x5F41EE, "serialized abci state"),
    ("daily_evm_checkpoints_tpl", 0x438F1D, "/data/daily_evm_checkpoints/"),
    ("marked_for_deletion_tpl", 0x44C7FC, "/MARKED_FOR_DELETION"),
    ("straggler_evm_checkpoint", 0x7BD544, "straggler evm state checkpoint"),
    ("periodic_status_missing", 0x44DB86, "periodic_abci_state_status_base_dir does not exist:"),
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
        name = data[shstr_off + sh_name : end].decode("latin1")
        secs[name] = (sh_addr, sh_offset, sh_size)
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
        raise ValueError(f"VA 0x{va:x}+{length} outside section {sec_name}")
    return data[sh_offset + rel : sh_offset + rel + length]


def extract_rela_prefix_table(
    data: bytes, secs: dict[str, tuple[int, int, int]]
) -> list[dict[str, object]]:
    _r_addr, r_off, r_sz = secs[".rela.dyn"]
    slot_to_addend: dict[int, int] = {}
    for off in range(r_off, r_off + r_sz, 24):
        r_offset, r_info, r_addend = struct.unpack_from("<QQq", data, off)
        if (r_info & 0xFFFFFFFF) == 8:
            if PREFIX_TABLE_VA <= r_offset < PREFIX_TABLE_VA + 29 * 8:
                slot_to_addend[r_offset] = r_addend
    rows = []
    for idx in range(29):
        slot = PREFIX_TABLE_VA + idx * 8
        if slot not in slot_to_addend:
            raise ValueError(f"missing R_X86_64_RELATIVE relocation at 0x{slot:x}")
        target = slot_to_addend[slot]
        prefix = read_section_bytes(data, secs, ".rodata", target, 2).decode("ascii")
        if (SHARD_0_MASK >> idx) & 1:
            shard = 0
        elif (SHARD_1_MASK >> idx) & 1:
            shard = 1
        else:
            shard = 2
        rows.append(
            {
                "index": idx,
                "slot_va": f"0x{slot:x}",
                "target_va": f"0x{target:x}",
                "prefix": prefix,
                "shard": shard,
                "core_l1_tier": idx <= 0x14,
            }
        )
    return rows


def build_records(data: bytes) -> dict[str, object]:
    secs = parse_elf_sections(data)
    fde_map = load_fde_map()
    fdes_out = []
    for label, start, end in EXPECTED_FDES:
        if fde_map and fde_map.get(start) != end:
            raise ValueError(
                f"FDE mismatch for {label}: index has {fde_map.get(start)}, expected 0x{end:x}"
            )
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

    anchors_out = []
    for label, va, expected_hex in EXPECTED_ANCHORS:
        raw = read_section_bytes(data, secs, ".text", va, len(expected_hex) // 2).hex()
        anchors_out.append({"label": label, "va": f"0x{va:x}", "bytes_hex": raw})

    literals_out = []
    for label, va, expected_text in EXPECTED_LITERALS:
        raw = read_section_bytes(data, secs, ".rodata", va, len(expected_text)).decode("ascii")
        literals_out.append({"label": label, "va": f"0x{va:x}", "text": raw})

    prefix_table = extract_rela_prefix_table(data, secs)
    return {
        "schema_version": 1,
        "work_item": "RE-009-node115-db-hub-routing-and-abci-schema",
        "target_binary": {
            "path": "artifacts/node/115/hl-node",
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        },
        "db_hub_routing": {
            "prefix_table_va": f"0x{PREFIX_TABLE_VA:x}",
            "prefix_rodata_va": f"0x{PREFIX_RODATA_VA:x}",
            "shard_0_mask": f"0x{SHARD_0_MASK:08x}",
            "shard_1_mask": f"0x{SHARD_1_MASK:08x}",
            "core_l1_tier_max_index": 0x14,
            "entries": prefix_table,
        },
        "hash_signature_tracker_schema": {
            "wire_fields": ["tracker", "qrs", "highest_quorum_height", "htm", "adu", "h"],
            "qrs_entry_size_bytes": 0x68,
            "pending_cutoff_window": 1000,
            "quorum_status_tags": ["N", "Q"],
        },
        "checkpoint_serialization": {
            "skip_path": "/dev/null",
            "rmp_extension": "rmp",
            "json_initial_capacity": 0x80,
            "json_indent": "  ",
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

    secs = parse_elf_sections(data)
    routing = records["db_hub_routing"]
    if int(routing["shard_0_mask"], 16) != SHARD_0_MASK:
        raise ValueError("shard_0_mask mismatch")
    if int(routing["shard_1_mask"], 16) != SHARD_1_MASK:
        raise ValueError("shard_1_mask mismatch")
    if (SHARD_0_MASK & SHARD_1_MASK) != 0:
        raise ValueError("shard 0 and shard 1 masks overlap")

    entries = routing["entries"]
    if len(entries) != 29:
        raise ValueError(f"expected 29 db_hub prefix entries, got {len(entries)}")
    live_table = extract_rela_prefix_table(data, secs)
    if entries != live_table:
        raise ValueError("db_hub 29-entry prefix table diverges from ELF .rela.dyn/.rodata")
    if [e["prefix"] for e in entries] != EXPECTED_29_PREFIXES:
        raise ValueError("29-prefix sequence mismatch")
    shard_counts = {0: 0, 1: 0, 2: 0}
    for e in entries:
        shard_counts[e["shard"]] += 1
    if shard_counts != {0: 22, 1: 4, 2: 3}:
        raise ValueError(f"unexpected shard distribution: {shard_counts}")

    fdes = records["fdes"]
    if len(fdes) != len(EXPECTED_FDES):
        raise ValueError("FDE count mismatch")
    for row, (label, start, end) in zip(fdes, EXPECTED_FDES):
        if row["label"] != label or int(row["start_va"], 16) != start or int(row["end_va"], 16) != end:
            raise ValueError(f"FDE descriptor mismatch for {label}")
        body = read_section_bytes(data, secs, ".text", start, end - start)
        if hashlib.sha256(body).hexdigest() != row["sha256"]:
            raise ValueError(f"FDE SHA-256 mismatch for {label}")

    anchors = records["anchors"]
    if len(anchors) != len(EXPECTED_ANCHORS):
        raise ValueError("anchor count mismatch")
    for row, (label, va, expected_hex) in zip(anchors, EXPECTED_ANCHORS):
        if row["label"] != label or int(row["va"], 16) != va or row["bytes_hex"] != expected_hex:
            raise ValueError(f"anchor record mismatch for {label}")
        actual = read_section_bytes(data, secs, ".text", va, len(expected_hex) // 2).hex()
        if actual != expected_hex:
            raise ValueError(f"binary anchor bytes mismatch for {label} at 0x{va:x}")

    literals = records["literals"]
    if len(literals) != len(EXPECTED_LITERALS):
        raise ValueError("literal count mismatch")
    for row, (label, va, expected_text) in zip(literals, EXPECTED_LITERALS):
        if row["label"] != label or int(row["va"], 16) != va or row["text"] != expected_text:
            raise ValueError(f"literal record mismatch for {label}")
        actual = read_section_bytes(data, secs, ".rodata", va, len(expected_text)).decode("ascii")
        if actual != expected_text:
            raise ValueError(f"binary literal mismatch for {label} at 0x{va:x}")

    schema = records["hash_signature_tracker_schema"]
    if schema["wire_fields"] != ["tracker", "qrs", "highest_quorum_height", "htm", "adu", "h"]:
        raise ValueError("HashSignatureTracker wire_fields mismatch")
    if schema["qrs_entry_size_bytes"] != 0x68 or schema["pending_cutoff_window"] != 1000:
        raise ValueError("HashSignatureTracker drain constants mismatch")
    if schema["quorum_status_tags"] != ["N", "Q"]:
        raise ValueError("QuorumStatus tags mismatch")


def run_negative_controls(records: dict[str, object], data: bytes) -> int:
    mutations = []

    m1 = copy.deepcopy(records)
    m1["db_hub_routing"]["shard_0_mask"] = "0x031ffefe"
    mutations.append(("corrupted_shard_0_mask", m1))

    m2 = copy.deepcopy(records)
    m2["db_hub_routing"]["entries"][26]["prefix"] = "XX"
    mutations.append(("corrupted_prefix_entry", m2))

    m3 = copy.deepcopy(records)
    m3["fdes"][0]["sha256"] = "0" * 64
    mutations.append(("corrupted_fde_sha256", m3))

    m4 = copy.deepcopy(records)
    m4["anchors"][0]["bytes_hex"] = "90" * (len(m4["anchors"][0]["bytes_hex"]) // 2)
    mutations.append(("corrupted_anchor_bytes", m4))

    m5 = copy.deepcopy(records)
    m5["literals"][0]["text"] = "X" * len(m5["literals"][0]["text"])
    mutations.append(("corrupted_rodata_literal", m5))

    m6 = copy.deepcopy(records)
    m6["hash_signature_tracker_schema"]["wire_fields"] = ["tracker", "qrs"]
    mutations.append(("corrupted_hst_wire_fields", m6))

    for name, mutated in mutations:
        try:
            verify_records(mutated, data)
        except ValueError:
            continue
        raise AssertionError(f"negative control {name} was unexpectedly accepted")
    return len(mutations)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="Write records.json deterministically")
    parser.add_argument("--self-test", action="store_true", help="Run negative controls")
    args = parser.parse_args()

    data = BINARY_PATH.read_bytes()
    if args.write:
        records = build_records(data)
        verify_records(records, data)
        RECORDS_PATH.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    else:
        records = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))
        verify_records(records, data)

    neg_count = run_negative_controls(records, data) if args.self_test else 0
    print(
        f"RE-009-node115-db-hub-routing-and-abci-schema verified: "
        f"29/29 db_hub prefixes (22/4/3 shards), {len(EXPECTED_FDES)} FDEs, "
        f"{len(EXPECTED_ANCHORS)} anchors, {len(EXPECTED_LITERALS)} literals"
        + (f", {neg_count}/{neg_count} negative controls rejected." if args.self_test else ".")
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
