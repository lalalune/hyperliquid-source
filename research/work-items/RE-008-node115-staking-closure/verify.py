#!/usr/bin/env python3
"""Exhaustive static ELF verifier for RE-008-node115-staking-closure."""

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

# Core components.json patterns ("l1/staking.rs", "l1/c_staking/*") + closely coupled staking files.
CORE_STAKING_PATHS = {
    "l1/src/staking.rs",
    "l1/src/c_staking/jailing.rs",
}
EXTENDED_STAKING_PATHS = {
    "l1/src/staking.rs",
    "l1/src/c_staking/jailing.rs",
    "l1/src/exchange/stake_requirement.rs",
    "l1/src/action/vote_global.rs",
}

FILE_TO_IMPL: dict[str, dict[str, object]] = {
    "l1/src/c_staking/jailing.rs": {
        "scope_tier": "core",
        "modules": ["src/node115-staking/src/jailing.rs"],
        "packets": ["RE-008-node115-staking-jailing", "RE-008-node115-staking-crate-map"],
    },
    "l1/src/staking.rs": {
        "scope_tier": "core",
        "modules": [
            "src/node115-staking/src/snapshot.rs",
            "src/node115-staking/src/stake_requirement.rs",
            "src/node115-validator-epoch-ring/src/lib.rs",
            "src/node115-staking-projection/src/lib.rs",
            "src/node115-staking-weight-comparison/lib.rs",
        ],
        "packets": [
            "RE-008-node115-staking-jailing",
            "RE-008-node115-staking-crate-map",
            "RE-008-node115-staking-governance-and-requirements",
        ],
    },
    "l1/src/exchange/stake_requirement.rs": {
        "scope_tier": "extended",
        "modules": ["src/node115-staking/src/stake_requirement.rs"],
        "packets": [
            "RE-008-node115-staking-crate-map",
            "RE-008-node115-staking-governance-and-requirements",
        ],
    },
    "l1/src/action/vote_global.rs": {
        "scope_tier": "extended",
        "modules": [
            "src/node115-governance-codec/src/lib.rs",
            "src/node115-governance-vote-state/lib.rs",
            "src/node115-vote-choice-weight/lib.rs",
        ],
        "packets": ["RE-008-node115-staking-crate-map"],
    },
}

# All 38 reconstructed & verified CStaking/staking business-logic FDEs across node115-staking.
BUSINESS_FDE_SPECS: list[tuple[str, int, str]] = [
    ("jailing_dispatch", 0x3C3C260, "src/node115-staking/src/jailing.rs"),
    ("jailing_protected_check", 0x3C35A10, "src/node115-staking/src/jailing.rs"),
    ("jailing_prune_expired", 0x3C35FE0, "src/node115-staking/src/jailing.rs"),
    ("snapshot_epoch_lookup", 0x36C8430, "src/node115-staking/src/snapshot.rs"),
    ("snapshot_epoch_quorum", 0x36C7F70, "src/node115-staking/src/snapshot.rs"),
    ("snapshot_unique_profiles", 0x36C7B30, "src/node115-staking/src/snapshot.rs"),
    ("snapshot_val_to_signer", 0x36CA5B0, "src/node115-staking/src/snapshot.rs"),
    ("admission_action_gate", 0x2BDB230, "src/node115-staking/src/admission.rs"),
    ("admission_signer_check", 0x4D907C0, "src/node115-staking/src/admission.rs"),
    ("admission_other_chain", 0x36C2030, "src/node115-staking/src/admission.rs"),
    ("delegation_action_handler", 0x2C68BB0, "src/node115-staking/src/delegation.rs"),
    ("delegation_c_staking_apply", 0x3C34FD0, "src/node115-staking/src/delegation.rs"),
    ("delegation_delegate_inner", 0x4221F40, "src/node115-staking/src/delegation.rs"),
    ("delegation_undelegate_inner", 0x4221510, "src/node115-staking/src/delegation.rs"),
    ("delegation_epoch_min_a", 0x42258D0, "src/node115-staking/src/delegation.rs"),
    ("delegation_epoch_min_b", 0x4225A30, "src/node115-staking/src/delegation.rs"),
    ("governance_propose", 0x3C348B0, "src/node115-staking/src/governance.rs"),
    ("governance_vote", 0x3C33F10, "src/node115-staking/src/governance.rs"),
    ("governance_prune_expired", 0x3C33520, "src/node115-staking/src/governance.rs"),
    ("validator_action_handler", 0x2C77640, "src/node115-staking/src/validator_lifecycle.rs"),
    ("validator_lifecycle", 0x3C3D480, "src/node115-staking/src/validator_lifecycle.rs"),
    ("validator_validate_profile_outer", 0x3C3A700, "src/node115-staking/src/validator_lifecycle.rs"),
    ("validator_profile_validate", 0x469B540, "src/node115-staking/src/validator_lifecycle.rs"),
    ("validator_register_active", 0x4225B80, "src/node115-staking/src/validator_lifecycle.rs"),
    ("withdrawal_queue_create", 0x3C3BBD0, "src/node115-staking/src/withdrawal_queue.rs"),
    ("withdrawal_queue_query", 0x36CB770, "src/node115-staking/src/withdrawal_queue.rs"),
    ("withdrawal_queue_drain", 0x3C3B790, "src/node115-staking/src/withdrawal_queue.rs"),
    ("rewards_emission_rate", 0x3C38360, "src/node115-staking/src/rewards.rs"),
    ("rewards_periodic_buckets", 0x3C3F780, "src/node115-staking/src/rewards.rs"),
    ("rewards_stage_outer", 0x422C320, "src/node115-staking/src/rewards.rs"),
    ("rewards_stage_reserve_cap", 0x3D66500, "src/node115-staking/src/rewards.rs"),
    ("rewards_distribute_staged", 0x422ABF0, "src/node115-staking/src/rewards.rs"),
    ("rewards_decay_staking", 0x422A630, "src/node115-staking/src/rewards.rs"),
    ("stake_req_iter_next", 0x294CEB0, "src/node115-staking/src/stake_requirement.rs"),
    ("stake_req_collect_a", 0x235A050, "src/node115-staking/src/stake_requirement.rs"),
    ("stake_req_count_category", 0x2C58C70, "src/node115-staking/src/stake_requirement.rs"),
    ("staking_validator_stake_rollup", 0x3DD9480, "src/node115-staking/src/stake_requirement.rs"),
    ("staking_saturating_sum_stakes", 0x4351DE0, "src/node115-staking/src/stake_requirement.rs"),
]

# Key .rodata IEEE-754 f64 anchors proven across node115-staking modules.
F64_ANCHORS: list[tuple[str, int, str]] = [
    ("seconds_per_year_31557600", 0x459058, "417e187e00000000"),
    ("staking_decay_0_99", 0x459208, "3fefae147ae147ae"),
    ("emission_base_0_015", 0x4596B0, "3f8eb851eb851eb8"),
    ("gov_mainnet_long_518400s", 0x459418, "411fa40000000000"),
    ("gov_mainnet_short_86400s", 0x459AC0, "40f5180000000000"),
    ("withdrawal_delay_7d_604800s", 0x450D00, "4122750000000000"),
]

# Key .text instruction anchors spanning jailing, validator profile, gov_vote, rewards, stake_requirement.
TEXT_ANCHORS: list[tuple[str, int, int]] = [
    ("gov_vote_4x_boost_shift_guard", 0x3C343CB, 0x3C343E2),
    ("gov_prune_ge_end_time", 0x3C336E8, 0x3C33704),
    ("stake_req_table_mul_checked", 0x294CF53, 0x294CF6A),
    ("staking_rollup_saturating_add", 0x4351E40, 0x4351E4F),
    ("validator_commission_cap_10000", 0x469B6EC, 0x469B710),
    ("rewards_emission_sqrt_guard", 0x3C383B0, 0x3C383D4),
]

REGISTERED_STAKING_CRATES = [
    "src/node115-staking-error-text",
    "src/node115-validator-epoch-ring",
    "src/node115-link-staking-state",
    "src/node115-staking-projection",
    "src/node115-staking-weight-comparison",
    "src/node115-validator-unregister",
    "src/node115-staking",
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


def scan_staking_locations(
    data: bytes, sections: dict[str, tuple[int, int, int]]
) -> dict[int, tuple[str, int, int]]:
    ro_va, ro_off, ro_sz = sections[".rodata"]
    dr_va, dr_off, dr_sz = sections[".data.rel.ro"]
    _rela_va, rela_off, rela_sz = sections[".rela.dyn"]
    prefixes = tuple(p.encode("ascii") for p in sorted(EXTENDED_STAKING_PATHS))
    locs: dict[int, tuple[str, int, int]] = {}
    for off in range(rela_off, rela_off + rela_sz, 24):
        r_offset, r_info, r_addend = struct.unpack_from("<QQq", data, off)
        if (
            (r_info & 0xFFFFFFFF) == 8
            and dr_va <= r_offset < dr_va + dr_sz
            and ro_va <= r_addend < ro_va + ro_sz
        ):
            raw = data[ro_off + (r_addend - ro_va) : ro_off + (r_addend - ro_va) + 48]
            if any(raw.startswith(p) for p in prefixes):
                doff = dr_off + (r_offset - dr_va)
                slen, line, col = struct.unpack_from("<QII", data, doff + 8)
                if 10 <= slen <= 64 and 1 <= line <= 50000 and 1 <= col <= 500:
                    path_str = data[
                        ro_off + (r_addend - ro_va) : ro_off + (r_addend - ro_va) + slen
                    ].decode("ascii")
                    if path_str in EXTENDED_STAKING_PATHS:
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


def check_inventory_parity() -> tuple[list[str], list[str]]:
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

    all_rs = set(walk(inv))
    core_inv = sorted(p for p in all_rs if p == "staking.rs" or p.startswith("c_staking/"))
    ext_inv = sorted(
        p
        for p in all_rs
        if p in ("staking.rs", "c_staking/jailing.rs", "exchange/stake_requirement.rs", "action/vote_global.rs")
    )
    return core_inv, ext_inv


def build_records(
    data: bytes,
    sections: dict[str, tuple[int, int, int]],
    fdes: dict[int, int],
    ordered_fdes: list[tuple[int, int]],
) -> dict:
    text_sec = sections[".text"]
    ro_sec = sections[".rodata"]
    locs = scan_staking_locations(data, sections)
    refs_by_loc = scan_location_referencing_fdes(data, sections, ordered_fdes, set(locs))
    core_inv, ext_inv = check_inventory_parity()

    files_out = []
    all_loc_fde_starts: set[int] = set()
    core_loc_count = 0
    core_loc_fdes: set[int] = set()
    for path in sorted(EXTENDED_STAKING_PATHS):
        flocs = sorted((va, ln, col) for va, (p, ln, col) in locs.items() if p == path)
        ffdes: set[int] = set()
        for va, _ln, _col in flocs:
            ffdes.update(refs_by_loc[va])
        all_loc_fde_starts.update(ffdes)
        if path in CORE_STAKING_PATHS:
            core_loc_count += len(flocs)
            core_loc_fdes.update(ffdes)
        files_out.append(
            {
                "path": path,
                "scope_tier": FILE_TO_IMPL[path]["scope_tier"],
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
    loc_bytes = sum(fdes[s] - s for s in all_loc_fde_starts)
    biz_bytes = sum(fdes[s] - s for s in biz_starts)
    union_bytes = sum(fdes[s] - s for s in union_starts)

    f64_out = []
    for name, va, exp_hex in F64_ANCHORS:
        raw_u64 = struct.unpack_from("<Q", slice_va(data, ro_sec, va, va + 8), 0)[0]
        got_hex = f"{raw_u64:016x}"
        if got_hex != exp_hex:
            raise AssertionError(f"f64 anchor {name} mismatch: {got_hex} != {exp_hex}")
        val = struct.unpack_from("<d", slice_va(data, ro_sec, va, va + 8), 0)[0]
        f64_out.append({"name": name, "va": f"0x{va:x}", "ieee754_hex": got_hex, "value": val})

    text_out = []
    for name, s, e in TEXT_ANCHORS:
        b = slice_va(data, text_sec, s, e)
        text_out.append({"name": name, "start_va": f"0x{s:x}", "end_va": f"0x{e:x}", "size": len(b), "bytes_hex": b.hex()})

    return {
        "schema_version": 1,
        "work_item": "RE-008-node115-staking-closure",
        "component": "staking",
        "target_binary": {
            "path": TARGET_REL,
            "size": TARGET_SIZE,
            "sha256": TARGET_SHA256,
        },
        "inventory_cross_check": {
            "core_inventory_files": core_inv,
            "extended_inventory_files": ext_inv,
        },
        "registered_implementation_crates": REGISTERED_STAKING_CRATES,
        "compiled_byte_identity_honest_summary": {
            "identity_gate_satisfied": False,
            "matched_fde_windows": 169,
            "matched_bytes": 6107,
            "packets": [
                {"packet": "RE-008-node115-consensus-staking-byte-matches", "staking_windows": 162, "staking_bytes": 4050},
                {"packet": "RE-008-node115-consensus-staking-debug-byte-matches", "staking_windows": 7, "staking_bytes": 2057},
            ],
        },
        "summary": {
            "core_file_count": len(CORE_STAKING_PATHS),
            "core_location_count": core_loc_count,
            "core_location_fde_count": len(core_loc_fdes),
            "extended_file_count": len(EXTENDED_STAKING_PATHS),
            "total_locations": len(locs),
            "location_fde_count": len(all_loc_fde_starts),
            "location_fde_bytes": loc_bytes,
            "business_fde_count": len(biz_out),
            "business_fde_bytes": biz_bytes,
            "combined_unique_fde_count": len(union_starts),
            "combined_unique_fde_bytes": union_bytes,
            "f64_anchors": len(f64_out),
            "text_anchors": len(text_out),
        },
        "files": files_out,
        "business_fdes": biz_out,
        "f64_anchors": f64_out,
        "text_anchors": text_out,
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

    core_inv, ext_inv = check_inventory_parity()
    if records["inventory_cross_check"]["core_inventory_files"] != core_inv:
        raise AssertionError("core inventory file list mismatch")
    if records["inventory_cross_check"]["extended_inventory_files"] != ext_inv:
        raise AssertionError("extended inventory file list mismatch")

    for crate in records["registered_implementation_crates"]:
        if not (REPO / crate / "Cargo.toml").is_file():
            raise AssertionError(f"missing registered staking crate {crate}")

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

    for fa in records["f64_anchors"]:
        va = int(fa["va"], 16)
        raw_u64 = struct.unpack_from("<Q", slice_va(data, ro_sec, va, va + 8), 0)[0]
        if f"{raw_u64:016x}" != fa["ieee754_hex"]:
            raise AssertionError(f"f64 anchor {fa['name']} mismatch")

    for ta in records["text_anchors"]:
        s = int(ta["start_va"], 16)
        e = int(ta["end_va"], 16)
        b = slice_va(data, text_sec, s, e)
        if len(b) != ta["size"] or b.hex() != ta["bytes_hex"]:
            raise AssertionError(f"text anchor {ta['name']} mismatch")

    union_fdes = recorded_loc_fdes | biz_fdes
    sm = records["summary"]
    if (
        sm["total_locations"] != len(observed_locs)
        or sm["location_fde_count"] != len(recorded_loc_fdes)
        or sm["business_fde_count"] != len(biz_fdes)
        or sm["combined_unique_fde_count"] != len(union_fdes)
        or sm["combined_unique_fde_bytes"] != sum(fdes[s] - s for s in union_fdes)
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

    def mut_bad_f64(r: dict) -> None:
        r["f64_anchors"][0]["ieee754_hex"] = "0000000000000000"

    def mut_bad_text_anchor(r: dict) -> None:
        h = r["text_anchors"][0]["bytes_hex"]
        r["text_anchors"][0]["bytes_hex"] = ("ff" if not h.startswith("ff") else "00") + h[2:]

    rejected = 0
    for name, fn in [
        ("drop_location", mut_drop_location),
        ("bad_biz_sha", mut_bad_biz_sha),
        ("bad_f64", mut_bad_f64),
        ("bad_text_anchor", mut_bad_text_anchor),
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
    observed_locs = scan_staking_locations(data, sections)
    observed_refs = scan_location_referencing_fdes(data, sections, ordered_fdes, set(observed_locs))

    if args.write:
        records = build_records(data, sections, fdes, ordered_fdes)
        RECORDS_PATH.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    else:
        records = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))

    verify_records(records, data, sections, fdes, ordered_fdes, observed_locs, observed_refs)
    sm = records["summary"]
    msg = (
        f"PASS: {sm['core_file_count']}/{sm['core_file_count']} core + "
        f"{sm['extended_file_count']}/{sm['extended_file_count']} extended staking files, "
        f"{sm['total_locations']}/{sm['total_locations']} Locations, "
        f"{sm['location_fde_count']} Location FDEs ({sm['location_fde_bytes']} B), "
        f"{sm['business_fde_count']} business FDEs ({sm['business_fde_bytes']} B), "
        f"{sm['combined_unique_fde_count']} unique FDEs ({sm['combined_unique_fde_bytes']} B), "
        f"{sm['f64_anchors']} f64 + {sm['text_anchors']} text anchors verified"
    )
    if args.self_test:
        neg = run_negative_controls(records, data, sections, fdes, ordered_fdes, observed_locs, observed_refs)
        msg += f", {neg}/{neg} negative controls rejected"
    print(msg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
