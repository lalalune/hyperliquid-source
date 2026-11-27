#!/usr/bin/env python3
"""Exhaustive static ELF verifier for RE-008-node115-consensus-closure."""

from __future__ import annotations

import argparse
import bisect
import copy
import hashlib
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
RECORDS_PATH = HERE / "records.json"
FDE_TSV_PATH = REPO / "work" / "index" / "node-115-fde.tsv"
INVENTORY_PATH = REPO / "research" / "imported" / "hl-node-115.inventory.json"
TARGET_REL = "artifacts/node/115/hl-node"
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET_SIZE = 105896032

CONSENSUS_PREFIX = b"node/src/consensus/"

FILE_TO_IMPL: dict[str, dict[str, object]] = {
    "node/src/consensus/config.rs": {
        "modules": [
            "src/node115-consensus/src/timeout_flow.rs",
            "src/node115-consensus-batch-floor/src/lib.rs",
        ],
        "packets": ["RE-008-node115-consensus-crate-map"],
    },
    "node/src/consensus/execution_state.rs": {
        "modules": [
            "src/node115-execution-history-selection/lib.rs",
            "src/node115-execution-order/lib.rs",
            "src/node115-execution-publication/lib.rs",
        ],
        "packets": ["RE-008-node115-consensus-crate-map"],
    },
    "node/src/consensus/heartbeat_tracker.rs": {
        "modules": ["src/node115-consensus/src/heartbeat.rs"],
        "packets": ["RE-008-node115-consensus-crate-map", "RE-008-node115-consensus-closure"],
    },
    "node/src/consensus/latency_samplers.rs": {
        "modules": ["src/node115-consensus/src/heartbeat.rs"],
        "packets": ["RE-008-node115-consensus-crate-map", "RE-008-node115-consensus-closure"],
    },
    "node/src/consensus/liner.rs": {
        "modules": ["src/node115-consensus/src/wire_codec.rs"],
        "packets": ["RE-008-node115-consensus-crate-map"],
    },
    "node/src/consensus/mempool.rs": {
        "modules": [
            "src/node115-consensus/src/commit.rs",
            "src/node115-consensus/src/voting.rs",
        ],
        "packets": [
            "RE-008-node115-hotstuff-vote-and-qc",
            "RE-008-node115-hotstuff-commit-and-quorum",
        ],
    },
    "node/src/consensus/network.rs": {
        "modules": [
            "src/node115-consensus/src/admission.rs",
            "src/node115-peer-address-admission/lib.rs",
        ],
        "packets": ["RE-008-node115-consensus-crate-map"],
    },
    "node/src/consensus/node_ips.rs": {
        "modules": ["src/node115-peer-address-admission/lib.rs"],
        "packets": ["RE-008-node115-consensus-crate-map"],
    },
    "node/src/consensus/rpc.rs": {
        "modules": ["src/node115-rpc-flat-materializer/src/lib.rs"],
        "packets": ["RE-008-node115-consensus-crate-map"],
    },
    "node/src/consensus/server.rs": {
        "modules": [
            "src/node115-consensus/src/round_progression.rs",
            "src/node115-consensus/src/timeout_flow.rs",
        ],
        "packets": ["RE-008-node115-round-progression", "RE-008-node115-consensus-crate-map"],
    },
    "node/src/consensus/signature_tracker.rs": {
        "modules": [
            "src/node115-consensus/src/voting.rs",
            "src/node115-vote-eligibility/src/lib.rs",
        ],
        "packets": ["RE-008-node115-hotstuff-vote-and-qc"],
    },
    "node/src/consensus/signed.rs": {
        "modules": [
            "src/node115-consensus/src/block_rules.rs",
            "src/node115-consensus/src/admission.rs",
        ],
        "packets": ["RE-008-node115-block-rules-and-tc-verify"],
    },
    "node/src/consensus/state.rs": {
        "modules": [
            "src/node115-consensus/src/round_progression.rs",
            "src/node115-consensus/src/commit.rs",
            "src/node115-consensus/src/voting.rs",
            "src/node115-consensus/src/wire_codec.rs",
        ],
        "packets": [
            "RE-008-node115-round-progression",
            "RE-008-node115-hotstuff-vote-and-qc",
            "RE-008-node115-hotstuff-commit-and-quorum",
        ],
    },
    "node/src/consensus/timer.rs": {
        "modules": [
            "src/node115-consensus/src/timeout_flow.rs",
            "src/node115-consensus-timer-conversion/src/lib.rs",
        ],
        "packets": ["RE-008-node115-round-progression"],
    },
    "node/src/consensus/types.rs": {
        "modules": [
            "src/node115-nested-certificate-decision/src/lib.rs",
            "src/node115-certificate-caller/src/lib.rs",
            "src/node115-certificate-long-sort/lib.rs",
        ],
        "packets": ["RE-008-node115-block-rules-and-tc-verify"],
    },
    "node/src/consensus/validator_set.rs": {
        "modules": [
            "src/node115-consensus/src/proposer.rs",
            "src/node115-consensus/src/round_progression.rs",
            "src/node115-validator-snapshot-publication/lib.rs",
        ],
        "packets": ["RE-008-node115-consensus-crate-map", "RE-008-node115-round-progression"],
    },
    "node/src/consensus/validator_stakes.rs": {
        "modules": [
            "src/node115-consensus/src/commit.rs",
            "src/node115-stake-predicate/src/lib.rs",
        ],
        "packets": ["RE-008-node115-hotstuff-commit-and-quorum"],
    },
}

BUSINESS_FDE_SPECS: list[tuple[str, int, str]] = [
    ("jailed_validators_lookup", 0x595C3A0, "src/node115-consensus/src/round_progression.rs"),
    ("tc_high_qc_select", 0x5960010, "src/node115-consensus/src/round_progression.rs"),
    ("timeout_quorum_and_amplify", 0x2E112F0, "src/node115-consensus/src/round_progression.rs"),
    ("local_timeout_broadcast", 0x2E154E0, "src/node115-consensus/src/round_progression.rs"),
    ("advance_round", 0x2E19920, "src/node115-consensus/src/round_progression.rs"),
    ("admit_signed_block_a", 0x57E8970, "src/node115-consensus/src/admission.rs"),
    ("admit_signed_block_b", 0x2786870, "src/node115-consensus/src/admission.rs"),
    ("admit_signed_timeout", 0x2786A20, "src/node115-consensus/src/admission.rs"),
    ("verify_block_rules", 0x59D6B80, "src/node115-consensus/src/block_rules.rs"),
    ("two_chain_commit_process_qc", 0x2E157C0, "src/node115-consensus/src/commit.rs"),
    ("register_block", 0x2E1DA10, "src/node115-consensus/src/commit.rs"),
    ("register_block_helper", 0x2E1F740, "src/node115-consensus/src/commit.rs"),
    ("strict_two_thirds_quorum_u128", 0x4D3E1A0, "src/node115-consensus/src/commit.rs"),
    ("vote_to_qc_aggregator", 0x2E08B90, "src/node115-consensus/src/commit.rs"),
    ("select_proposer", 0x595CB30, "src/node115-consensus/src/proposer.rs"),
    ("verify_tc_outer", 0x5960390, "src/node115-consensus/src/tc_verify.rs"),
    ("verify_tc_inner", 0x564B510, "src/node115-consensus/src/tc_verify.rs"),
    ("poll_timer_arms", 0x2CDCA20, "src/node115-consensus/src/timeout_flow.rs"),
    ("server_event_loop_timeout_counter", 0x2E098E0, "src/node115-consensus/src/timeout_flow.rs"),
    ("hotstuff_try_vote", 0x2E07A00, "src/node115-consensus/src/voting.rs"),
    ("hotstuff_process_qc_equiv", 0x2E08750, "src/node115-consensus/src/voting.rs"),
    ("hotstuff_qc_equiv_helper", 0x2E1FE30, "src/node115-consensus/src/voting.rs"),
    ("hotstuff_ancestor_walk", 0x2E20B00, "src/node115-consensus/src/voting.rs"),
    ("wire_signing_payload_encode", 0x5823DB0, "src/node115-consensus/src/wire_codec.rs"),
    ("try_propose_guards", 0x2E13EA0, "src/node115-consensus/src/wire_codec.rs"),
    ("heartbeat_record_bucket", 0x5A71E20, "src/node115-consensus/src/heartbeat.rs"),
    ("heartbeat_latency_ema_180s", 0x5A71EE0, "src/node115-consensus/src/heartbeat.rs"),
]

REGISTERED_CONSENSUS_PATHS = [
    "src/node115-weighted-fastfold",
    "src/node115-tree-next",
    "src/node115-rpc-flat-materializer",
    "src/node115-stake-predicate",
    "src/node115-adjacent-last",
    "src/node115-indirect-triplet-insert",
    "src/node115-execution-history-selection",
    "src/node115-certificate-caller",
    "src/node115-certificate-long-sort",
    "src/node115-consensus-batch-floor",
    "src/node115-consensus-timer-conversion",
    "src/node115-execution-order",
    "src/node115-execution-projection",
    "src/node115-execution-publication",
    "src/node115-nested-certificate-decision",
    "src/node115-peer-address-admission",
    "src/node115-validator-snapshot-publication",
    "src/node115-vote-eligibility",
    "src/node115-consensus",
]

TEXT_ANCHORS: list[tuple[str, int, int]] = [
    ("heartbeat_180s_window_0xb4", 0x5A71F08, 0x5A71F20),
    ("heartbeat_validator_latency_ema_lea", 0x5A7203C, 0x5A72056),
    ("quorum_128bit_3x_gt_2x", 0x4D3E2D0, 0x4D3E30D),
    ("two_chain_simd_genesis_guard", 0x2E15B9B, 0x2E15BBD),
    ("two_chain_consecutive_round_check", 0x2E15D12, 0x2E15D50),
    ("register_block_stale_tag3", 0x2E1DA72, 0x2E1DA88),
]

RODATA_STR_ANCHORS: list[tuple[str, int, str]] = [
    ("validator_latency_ema", 0x93B1D7, "validator_latency_ema"),
    ("qc_type_name", 0x938507, "Qc"),
    ("tc_type_name", 0x938509, "Tc"),
    ("tc_has_bad_qc", 0x93BF95, "Tc has bad qc"),
    ("failed_verify_qc_sig", 0x93BEE8, "Failed to verify qc signature"),
]


def parse_elf_sections(data: bytes) -> dict[str, tuple[int, int, int]]:
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    shstr_off = struct.unpack_from("<Q", data, e_shoff + e_shstrndx * e_shentsize + 24)[0]
    sections: dict[str, tuple[int, int, int]] = {}
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name, _sh_type, _sh_flags, sh_addr, sh_offset, sh_size = struct.unpack_from(
            "<IIQQQQ", data, off
        )
        end = data.index(b"\x00", shstr_off + sh_name)
        sections[data[shstr_off + sh_name : end].decode("ascii")] = (sh_addr, sh_offset, sh_size)
    return sections


def load_fde_index() -> tuple[dict[int, int], list[tuple[int, int]]]:
    fdes: dict[int, int] = {}
    ordered: list[tuple[int, int]] = []
    with FDE_TSV_PATH.open("r", encoding="utf-8") as fh:
        for line in fh:
            parts = line.strip().split("\t")
            if len(parts) >= 2 and parts[0].startswith("0x"):
                s = int(parts[0], 16)
                e = int(parts[1], 16)
                fdes[s] = e
                ordered.append((s, e))
    ordered.sort()
    return fdes, ordered


def scan_consensus_locations(
    data: bytes, sections: dict[str, tuple[int, int, int]]
) -> dict[int, tuple[str, int, int]]:
    ro_va, ro_off, ro_sz = sections[".rodata"]
    dr_va, dr_off, dr_sz = sections[".data.rel.ro"]
    _rela_va, rela_off, rela_sz = sections[".rela.dyn"]
    locs: dict[int, tuple[str, int, int]] = {}
    for off in range(rela_off, rela_off + rela_sz, 24):
        r_offset, r_info, r_addend = struct.unpack_from("<QQq", data, off)
        if (
            (r_info & 0xFFFFFFFF) == 8
            and dr_va <= r_offset < dr_va + dr_sz
            and ro_va <= r_addend < ro_va + ro_sz
        ):
            raw = data[ro_off + (r_addend - ro_va) : ro_off + (r_addend - ro_va) + 64]
            if raw.startswith(CONSENSUS_PREFIX):
                doff = dr_off + (r_offset - dr_va)
                slen, line, col = struct.unpack_from("<QII", data, doff + 8)
                if 20 <= slen <= 64 and 1 <= line <= 50000 and 1 <= col <= 500:
                    path_str = data[
                        ro_off + (r_addend - ro_va) : ro_off + (r_addend - ro_va) + slen
                    ].decode("ascii")
                    if path_str.endswith(".rs"):
                        locs[r_offset] = (path_str, line, col)
    return locs


def scan_location_referencing_fdes(
    data: bytes,
    sections: dict[str, tuple[int, int, int]],
    ordered_fdes: list[tuple[int, int]],
    loc_vas: set[int],
) -> dict[int, list[int]]:
    text_va, text_off, text_sz = sections[".text"]
    text = data[text_off : text_off + text_sz]
    fde_starts = [s for s, _ in ordered_fdes]
    by_loc: dict[int, set[int]] = {lv: set() for lv in loc_vas}
    limit = len(text) - 7
    i = 0
    while i < limit:
        b0 = text[i]
        if (b0 == 0x48 or b0 == 0x4C) and text[i + 1] == 0x8D and (text[i + 2] & 0xC7) == 0x05:
            disp = struct.unpack_from("<i", text, i + 3)[0]
            target = text_va + i + 7 + disp
            if target in by_loc:
                ins_va = text_va + i
                idx = bisect.bisect_right(fde_starts, ins_va) - 1
                if idx >= 0 and ordered_fdes[idx][0] <= ins_va < ordered_fdes[idx][1]:
                    by_loc[target].add(ordered_fdes[idx][0])
        i += 1
    return {lv: sorted(s) for lv, s in by_loc.items()}


def slice_va(data: bytes, sec: tuple[int, int, int], s: int, e: int) -> bytes:
    va, off, sz = sec
    if not (va <= s <= e <= va + sz):
        raise AssertionError(f"VA 0x{s:x}..0x{e:x} outside section 0x{va:x}..0x{va+sz:x}")
    return data[off + (s - va) : off + (e - va)]


def inventory_consensus_files() -> list[str]:
    inv = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))

    def walk(obj: object) -> list[str]:
        out: list[str] = []
        if isinstance(obj, str) and obj.endswith(".rs"):
            out.append(obj)
        elif isinstance(obj, list):
            for x in obj:
                out.extend(walk(x))
        elif isinstance(obj, dict):
            for v in obj.values():
                out.extend(walk(v))
        return out

    return sorted(p for p in set(walk(inv)) if p.startswith("consensus/"))


def build_records(
    data: bytes,
    sections: dict[str, tuple[int, int, int]],
    fdes: dict[int, int],
    ordered_fdes: list[tuple[int, int]],
) -> dict:
    text_sec = sections[".text"]
    ro_sec = sections[".rodata"]
    locs = scan_consensus_locations(data, sections)
    refs_by_loc = scan_location_referencing_fdes(data, sections, ordered_fdes, set(locs))
    inv_files = inventory_consensus_files()

    files_out = []
    all_loc_fde_starts: set[int] = set()
    for path in sorted({p for p, _l, _c in locs.values()}):
        flocs = sorted((va, ln, col) for va, (p, ln, col) in locs.items() if p == path)
        ffdes: set[int] = set()
        for va, _ln, _col in flocs:
            ffdes.update(refs_by_loc[va])
        all_loc_fde_starts.update(ffdes)
        files_out.append(
            {
                "path": path,
                "location_count": len(flocs),
                "locations": [
                    {
                        "va": f"0x{va:x}",
                        "line": ln,
                        "col": col,
                        "referencing_fdes": [f"0x{s:x}" for s in refs_by_loc[va]],
                    }
                    for va, ln, col in flocs
                ],
                "fde_count": len(ffdes),
                "fdes": [
                    {
                        "start_va": f"0x{s:x}",
                        "end_va": f"0x{fdes[s]:x}",
                        "size": fdes[s] - s,
                        "sha256": hashlib.sha256(slice_va(data, text_sec, s, fdes[s])).hexdigest(),
                    }
                    for s in sorted(ffdes)
                ],
                "implementation_modules": FILE_TO_IMPL[path]["modules"],
                "evidence_packets": FILE_TO_IMPL[path]["packets"],
            }
        )

    biz_out = []
    biz_starts: set[int] = set()
    for name, s, module in BUSINESS_FDE_SPECS:
        e = fdes[s]
        b = slice_va(data, text_sec, s, e)
        biz_starts.add(s)
        biz_out.append(
            {
                "name": name,
                "start_va": f"0x{s:x}",
                "end_va": f"0x{e:x}",
                "size": len(b),
                "sha256": hashlib.sha256(b).hexdigest(),
                "implementation_module": module,
            }
        )

    union_starts = all_loc_fde_starts | biz_starts

    text_out = []
    for name, s, e in TEXT_ANCHORS:
        b = slice_va(data, text_sec, s, e)
        text_out.append({"name": name, "start_va": f"0x{s:x}", "end_va": f"0x{e:x}", "size": len(b), "bytes_hex": b.hex()})

    ro_out = []
    for name, va, exp in RODATA_STR_ANCHORS:
        eb = exp.encode("ascii")
        got = slice_va(data, ro_sec, va, va + len(eb))
        if got != eb:
            raise AssertionError(f"rodata anchor {name} mismatch at 0x{va:x}: {got!r} != {eb!r}")
        ro_out.append({"name": name, "va": f"0x{va:x}", "length": len(eb), "text": exp})

    return {
        "schema_version": 1,
        "work_item": "RE-008-node115-consensus-closure",
        "component": "consensus",
        "target_binary": {
            "path": TARGET_REL,
            "size": TARGET_SIZE,
            "sha256": TARGET_SHA256,
        },
        "inventory_cross_check": {
            "inventory_consensus_files": inv_files,
        },
        "registered_implementation_paths": REGISTERED_CONSENSUS_PATHS,
        "compiled_byte_identity_honest_summary": {
            "identity_gate_satisfied": False,
            "matched_fde_windows": 59,
            "matched_bytes": 9159,
            "packets": [
                {"packet": "RE-008-node115-consensus-staking-byte-matches", "consensus_windows": 31, "consensus_bytes": 775},
                {"packet": "RE-008-node115-consensus-staking-debug-byte-matches", "consensus_windows": 28, "consensus_bytes": 8384},
            ],
        },
        "summary": {
            "source_file_count": len(files_out),
            "total_locations": len(locs),
            "location_fde_count": len(all_loc_fde_starts),
            "location_fde_bytes": sum(fdes[s] - s for s in all_loc_fde_starts),
            "business_fde_count": len(biz_out),
            "business_fde_bytes": sum(fdes[s] - s for s in biz_starts),
            "combined_unique_fde_count": len(union_starts),
            "combined_unique_fde_bytes": sum(fdes[s] - s for s in union_starts),
            "text_anchors": len(text_out),
            "rodata_str_anchors": len(ro_out),
        },
        "files": files_out,
        "business_fdes": biz_out,
        "text_anchors": text_out,
        "rodata_str_anchors": ro_out,
    }


def verify_records(
    records: dict,
    data: bytes,
    sections: dict[str, tuple[int, int, int]],
    fdes: dict[int, int],
    ordered_fdes: list[tuple[int, int]],
    observed_locs: dict[int, tuple[str, int, int]],
    observed_refs: dict[int, list[int]],
) -> None:
    tb = records["target_binary"]
    if len(data) != tb["size"] or hashlib.sha256(data).hexdigest() != tb["sha256"]:
        raise AssertionError("target binary identity mismatch")

    inv_files = inventory_consensus_files()
    if records["inventory_cross_check"]["inventory_consensus_files"] != inv_files:
        raise AssertionError("inventory consensus file list mismatch")
    if len(records["files"]) != len(inv_files):
        raise AssertionError("recorded files count != inventory consensus files count")

    for p in records["registered_implementation_paths"]:
        if not (REPO / p).is_dir():
            raise AssertionError(f"missing registered consensus implementation path {p}")

    text_sec = sections[".text"]
    ro_sec = sections[".rodata"]

    recorded_locs: dict[int, tuple[str, int, int]] = {}
    recorded_loc_fdes: set[int] = set()
    for fobj in records["files"]:
        path = fobj["path"]
        for m in fobj["implementation_modules"]:
            if not (REPO / m).is_file():
                raise AssertionError(f"missing mapped implementation module {m}")
        for loc in fobj["locations"]:
            va = int(loc["va"], 16)
            recorded_locs[va] = (path, int(loc["line"]), int(loc["col"]))
            expected_refs = [f"0x{s:x}" for s in observed_refs.get(va, [])]
            if loc["referencing_fdes"] != expected_refs:
                raise AssertionError(f"Location 0x{va:x} referencing FDEs mismatch")
        for fd in fobj["fdes"]:
            s = int(fd["start_va"], 16)
            e = int(fd["end_va"], 16)
            if fdes.get(s) != e or e - s != fd["size"]:
                raise AssertionError(f"Location FDE 0x{s:x} extent mismatch")
            if hashlib.sha256(slice_va(data, text_sec, s, e)).hexdigest() != fd["sha256"]:
                raise AssertionError(f"Location FDE 0x{s:x} sha256 mismatch")
            recorded_loc_fdes.add(s)

    if recorded_locs != observed_locs:
        raise AssertionError(f"recorded Locations ({len(recorded_locs)}) != observed ELF Locations ({len(observed_locs)})")

    observed_all_loc_fdes = {s for lst in observed_refs.values() for s in lst}
    if recorded_loc_fdes != observed_all_loc_fdes:
        raise AssertionError("recorded Location FDE set != observed ELF Location FDE set")

    biz_fdes: set[int] = set()
    for bf in records["business_fdes"]:
        s = int(bf["start_va"], 16)
        e = int(bf["end_va"], 16)
        if fdes.get(s) != e or e - s != bf["size"]:
            raise AssertionError(f"business FDE {bf['name']} extent mismatch")
        if hashlib.sha256(slice_va(data, text_sec, s, e)).hexdigest() != bf["sha256"]:
            raise AssertionError(f"business FDE {bf['name']} sha256 mismatch")
        if not (REPO / bf["implementation_module"]).is_file():
            raise AssertionError(f"missing implementation module {bf['implementation_module']}")
        biz_fdes.add(s)

    for ta in records["text_anchors"]:
        s = int(ta["start_va"], 16)
        e = int(ta["end_va"], 16)
        b = slice_va(data, text_sec, s, e)
        if len(b) != ta["size"] or b.hex() != ta["bytes_hex"]:
            raise AssertionError(f"text anchor {ta['name']} mismatch")

    for ra in records["rodata_str_anchors"]:
        va = int(ra["va"], 16)
        eb = ra["text"].encode("ascii")
        if len(eb) != ra["length"] or slice_va(data, ro_sec, va, va + len(eb)) != eb:
            raise AssertionError(f"rodata anchor {ra['name']} mismatch")

    union_fdes = recorded_loc_fdes | biz_fdes
    sm = records["summary"]
    if (
        sm["source_file_count"] != len(inv_files)
        or sm["total_locations"] != len(observed_locs)
        or sm["location_fde_count"] != len(recorded_loc_fdes)
        or sm["business_fde_count"] != len(biz_fdes)
        or sm["combined_unique_fde_count"] != len(union_starts := union_fdes)
        or sm["combined_unique_fde_bytes"] != sum(fdes[s] - s for s in union_starts)
    ):
        raise AssertionError("summary totals mismatch")


def run_negative_controls(
    records: dict,
    data: bytes,
    sections: dict[str, tuple[int, int, int]],
    fdes: dict[int, int],
    ordered_fdes: list[tuple[int, int]],
    observed_locs: dict[int, tuple[str, int, int]],
    observed_refs: dict[int, list[int]],
) -> int:
    def mut_drop_location(r: dict) -> None:
        r["files"][0]["locations"].pop()

    def mut_bad_biz_sha(r: dict) -> None:
        r["business_fdes"][0]["sha256"] = "0" * 64

    def mut_bad_text(r: dict) -> None:
        h = r["text_anchors"][0]["bytes_hex"]
        r["text_anchors"][0]["bytes_hex"] = ("ff" if not h.startswith("ff") else "00") + h[2:]

    def mut_bad_rodata(r: dict) -> None:
        r["rodata_str_anchors"][0]["text"] = "wrong_latency_key_xxx"

    rejected = 0
    for name, fn in [
        ("drop_location", mut_drop_location),
        ("bad_biz_sha", mut_bad_biz_sha),
        ("bad_text_anchor", mut_bad_text),
        ("bad_rodata_anchor", mut_bad_rodata),
    ]:
        mutated = copy.deepcopy(records)
        fn(mutated)
        try:
            verify_records(mutated, data, sections, fdes, ordered_fdes, observed_locs, observed_refs)
        except AssertionError:
            rejected += 1
        else:
            raise AssertionError(f"negative control {name} was NOT rejected")
    return rejected


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    data = (REPO / TARGET_REL).read_bytes()
    sections = parse_elf_sections(data)
    fdes, ordered_fdes = load_fde_index()
    observed_locs = scan_consensus_locations(data, sections)
    observed_refs = scan_location_referencing_fdes(data, sections, ordered_fdes, set(observed_locs))

    if args.write:
        records = build_records(data, sections, fdes, ordered_fdes)
        RECORDS_PATH.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    else:
        records = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))

    verify_records(records, data, sections, fdes, ordered_fdes, observed_locs, observed_refs)
    sm = records["summary"]
    msg = (
        f"PASS: {sm['source_file_count']}/{sm['source_file_count']} node/src/consensus files, "
        f"{sm['total_locations']}/{sm['total_locations']} Locations, "
        f"{sm['location_fde_count']} Location FDEs ({sm['location_fde_bytes']} B), "
        f"{sm['business_fde_count']} business FDEs ({sm['business_fde_bytes']} B), "
        f"{sm['combined_unique_fde_count']} unique FDEs ({sm['combined_unique_fde_bytes']} B), "
        f"{sm['text_anchors']} text + {sm['rodata_str_anchors']} rodata anchors verified"
    )
    if args.self_test:
        neg = run_negative_controls(records, data, sections, fdes, ordered_fdes, observed_locs, observed_refs)
        msg += f", {neg}/{neg} negative controls rejected"
    print(msg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
