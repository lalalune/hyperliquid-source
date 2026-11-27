#!/usr/bin/env python3
"""Static verifier and deterministic generator for RE-010-node115-l1-shared-closure."""

from __future__ import annotations

import argparse
import bisect
import copy
import fnmatch
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
RECORDS_PATH = HERE / "records.json"
COMPONENTS_PATH = REPO / "research" / "components.json"
FDE_TSV_PATH = REPO / "work" / "index" / "node-115-fde.tsv"
TARGET_REL = "artifacts/node/115/hl-node"
TARGET_SIZE = 105_896_032
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

LEA_RIP_RE = re.compile(rb"[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]")

BUSINESS_FDES: list[tuple[str, int, str]] = [
    ("chain_ext_sandbox_init", 0x46E7FF0, "l1/src/chain_ext.rs Sandbox 4-address BTreeSet lazy initializer"),
    ("chain_ext_mainnet_init", 0x46E83C0, "l1/src/chain_ext.rs Mainnet 4-address BTreeSet lazy initializer"),
    ("chain_ext_testnet_init", 0x46E87C0, "l1/src/chain_ext.rs Testnet 4-address BTreeSet lazy initializer"),
    ("nonce_set_check", 0x4228080, "l1/src/nonce_set.rs 7-rule nonce ring admission validator"),
    ("nonce_set_admit_wrapper", 0x4228310, "l1/src/nonce_set.rs 100/400 window selector and admit wrapper"),
    ("nonce_set_expanded_set_b", 0x421A3C0, "l1/src/nonce_set.rs 8-address expanded nonce window set B"),
    ("nonce_set_expanded_set_a", 0x421A520, "l1/src/nonce_set.rs 8-address expanded nonce window set A"),
    ("hyperliquidity_price_tick", 0x3BE2A50, "l1/src/hyperliquidity.rs 5-sig-digit price tick helper"),
    ("hyperliquidity_generate_ladder", 0x38BDDF0, "l1/src/hyperliquidity.rs 1.003x ladder generator"),
    ("hyperliquidity_funding_cost", 0x38BCB80, "l1/src/hyperliquidity.rs checked funding cost sum"),
    ("hyperliquidity_market_cap_band", 0x38BCAA0, "l1/src/hyperliquidity.rs market-cap band check"),
    ("decimal_scaler_core", 0x421E9D0, "l1-shared 96-bit decimal-to-u64 amount scaler"),
    ("decimal_from_binary_exp", 0x5C43C60, "l1-shared binary-exponent-to-Decimal96 converter"),
    ("decimal_from_f64", 0x43099F0, "l1-shared f64-to-Decimal96 parser"),
]

INSTRUCTION_ANCHORS: list[tuple[str, int, str]] = [
    ("chain_ext_jump_dispatch", 0x46F3FC5, "400fb6c7488d0d04530efc486304814801c8"),
    ("chain_ext_local_panic", 0x46F401E, "488d3d81a60efc488d1504f8d901be1b000000ff1581b6de01"),
    ("utils_rmp_keccak_sponge_init", 0x38D2DAD, "48c78424f00000008800000066c78424f80000000100"),
    ("utils_rmp_sha256_iv_load", 0x38D299D, "0f100d3c51b8fc0f294c24400f10154051b8fc"),
    ("utils_hard_link_inode_cmp", 0x38D7F86, "483b5c24687520483b6c2470751931c0"),
    ("nonce_set_de_strict_asc_loop", 0x4227E10, "4c39c2740f4c8b4af84c3b0a488d520872eeeb20"),
    ("raw_sig_tracker_bucket_cap_cmp", 0x368B335, "488d35fcd7dd02e88f70cc00483d97080000"),
    ("simulate_panic_explicit_panic_call", 0x2BDF881, "84c90f85b9faffff488d3d03bbbffd488d1559368b03be0e000000"),
    ("bole_user_state_loc_check", 0x2BB99D2, "488d15ff3b8903488dbc24800000004c89e6ff1546de9203"),
    ("agent_tracker_indexmap_stride_38", 0x3BE7A47, "488b78f84839ef0f83c5030000486bc7384901c6"),
    ("hyperliquidity_seed_max_levels", 0x38BC000, "554157415641554154534881ec080100"),
]

RODATA_LITERALS: list[tuple[str, int, str]] = [
    ("chain_ext_invalid_chain", 0x7DE6A6, "invalid chain"),
    ("simulate_panic_explicit_panic", 0x7DB393, "explicit panic"),
    ("utils_hard_link_temp_prefix", 0x439E44, "utils_hard_link_and_replace/"),
    ("nonce_set_invariant_label", 0x7C958C, "nonce invariant"),
]

RODATA_CONSTANTS: list[tuple[str, int, str]] = [
    ("sha256_iv", 0x457AE0, "67e6096a85ae67bb72f36e3c3af54fa57f520e518c68059babd9831f19cde05b"),
    ("chain_ext_jump_table", 0x7D92D4, "4aadf10305adf10333adf1031cadf103"),
    (
        "chain_ext_mainnet_rodata_addrs",
        0x7DB81E,
        "80f0cd23da5bf3a0101110cfd0f89c8a69a1384da82fe73bbd768bc15d1ef2f6142a21ff8bd762addf35aee8ef5658686142acd1e5ab5dbcdf8c51e8",
    ),
    (
        "chain_ext_sandbox_rodata_addrs",
        0x7DB85A,
        "a40cf273de4f77278b911dd4c6a023d60647d979a89a7f8ab7bcf9c57542e22dc0e4b768b0101762f027b2abfa8de836d8cdcce22af88bb8aacef849",
    ),
    (
        "chain_ext_testnet_rodata_addrs",
        0x7DB896,
        "3c83a5cae32a05e88ca6a0350edb540194851a764dbf394da4b348b88e8090d22051af83e4cbaef4946bf3135c7d15e4462b510f74b6e304aabb5b21",
    ),
]


def parse_elf_sections(data: bytes) -> dict[str, tuple[int, int, int]]:
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    shstr_off = struct.unpack_from("<Q", data, e_shoff + e_shstrndx * e_shentsize + 24)[0]
    sections: dict[str, tuple[int, int, int]] = {}
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name, _t, _f, sh_addr, sh_offset, sh_size = struct.unpack_from("<IIQQQQ", data, off)
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


def classify_l1_path(src_path: str, components: list[dict]) -> str:
    norm = "l1/" + src_path[len("l1/src/") :]
    for comp in components:
        for pat in comp["patterns"]:
            if fnmatch.fnmatch(norm, pat):
                return comp["id"]
    return "UNCLASSIFIED"


def scan_l1_shared_locations(
    data: bytes, sections: dict[str, tuple[int, int, int]], components: list[dict]
) -> dict[int, tuple[str, int, int]]:
    ro_va, ro_off, ro_sz = sections[".rodata"]
    dr_va, dr_off, dr_sz = sections[".data.rel.ro"]
    rela_va, rela_off, rela_sz = sections[".rela.dyn"]
    locs: dict[int, tuple[str, int, int]] = {}
    for off in range(rela_off, rela_off + rela_sz, 24):
        r_offset, r_info, r_addend = struct.unpack_from("<QQq", data, off)
        if (
            (r_info & 0xFFFFFFFF) == 8
            and dr_va <= r_offset < dr_va + dr_sz
            and ro_va <= r_addend < ro_va + ro_sz
        ):
            raw = data[ro_off + (r_addend - ro_va) : ro_off + (r_addend - ro_va) + 96]
            if raw.startswith(b"l1/src/"):
                doff = dr_off + (r_offset - dr_va)
                slen, line, col = struct.unpack_from("<QII", data, doff + 8)
                if 10 <= slen <= 128 and 1 <= line <= 50000 and 1 <= col <= 500:
                    try:
                        path_str = data[
                            ro_off + (r_addend - ro_va) : ro_off + (r_addend - ro_va) + slen
                        ].decode("ascii")
                    except UnicodeDecodeError:
                        continue
                    if path_str.endswith(".rs") and classify_l1_path(path_str, components) == "l1-shared":
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
    fde_to_locs: dict[int, set[int]] = {}
    for m in LEA_RIP_RE.finditer(text):
        i = m.start()
        if i + 7 > len(text):
            continue
        disp = struct.unpack_from("<i", text, i + 3)[0]
        target = text_va + i + 7 + disp
        if target in loc_vas:
            ins_va = text_va + i
            idx = bisect.bisect_right(fde_starts, ins_va) - 1
            if idx >= 0 and ordered_fdes[idx][0] <= ins_va < ordered_fdes[idx][1]:
                fde_to_locs.setdefault(ordered_fdes[idx][0], set()).add(target)
    return {s: sorted(vas) for s, vas in sorted(fde_to_locs.items())}


def build_records(
    data: bytes,
    fdes: dict[int, int],
    observed_locs: dict[int, tuple[str, int, int]],
    fde_to_locs: dict[int, list[int]],
) -> dict:
    obs_files = sorted({f for f, _, _ in observed_locs.values()})
    loc_rows = [
        {"va": hex(va), "file": f, "line": ln, "col": col}
        for va, (f, ln, col) in sorted(observed_locs.items(), key=lambda kv: (kv[1][0], kv[1][1], kv[0]))
    ]
    loc_fde_rows = []
    loc_bytes = 0
    for s, vas in sorted(fde_to_locs.items()):
        e = fdes[s]
        sz = e - s
        loc_bytes += sz
        files = sorted({observed_locs[v][0] for v in vas})
        loc_fde_rows.append(
            {
                "start": hex(s),
                "end": hex(e),
                "size": sz,
                "location_vas": [hex(v) for v in vas],
                "source_files": files,
            }
        )
    biz_rows = []
    biz_bytes = 0
    for name, s, role in BUSINESS_FDES:
        e = fdes[s]
        sz = e - s
        biz_bytes += sz
        biz_rows.append({"name": name, "start": hex(s), "end": hex(e), "size": sz, "role": role})
    return {
        "work_item": "RE-010-node115-l1-shared-closure",
        "component": "l1-shared",
        "target_binary": {
            "path": TARGET_REL,
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "coordinate_system": "ELF64 linked virtual address",
        },
        "observed_source_files": obs_files,
        "location_count": len(loc_rows),
        "locations": loc_rows,
        "l1_shared_location_fdes": loc_fde_rows,
        "l1_shared_business_fdes": biz_rows,
        "instruction_anchors": [
            {"name": name, "va": hex(va), "hex": hx} for name, va, hx in INSTRUCTION_ANCHORS
        ],
        "rodata_literals": [
            {"name": name, "va": hex(va), "ascii": txt} for name, va, txt in RODATA_LITERALS
        ],
        "rodata_constants": [
            {"name": name, "va": hex(va), "hex": hx} for name, va, hx in RODATA_CONSTANTS
        ],
        "summary": {
            "observed_source_files": len(obs_files),
            "location_count": len(loc_rows),
            "l1_shared_location_fdes": len(loc_fde_rows),
            "l1_shared_location_fde_bytes": loc_bytes,
            "l1_shared_business_fdes": len(biz_rows),
            "l1_shared_business_fde_bytes": biz_bytes,
            "combined_unique_fdes": len(loc_fde_rows) + len(biz_rows),
            "combined_unique_fde_bytes": loc_bytes + biz_bytes,
        },
    }


def verify_records(
    records: dict,
    data: bytes,
    sections: dict[str, tuple[int, int, int]],
    fdes: dict[int, int],
    observed_locs: dict[int, tuple[str, int, int]],
    fde_to_locs: dict[int, list[int]],
) -> None:
    tb = records["target_binary"]
    if len(data) != tb["size"] or tb["size"] != TARGET_SIZE:
        raise AssertionError("binary size mismatch")
    if hashlib.sha256(data).hexdigest() != tb["sha256"] or tb["sha256"] != TARGET_SHA256:
        raise AssertionError("binary sha256 mismatch")

    obs_files = sorted({f for f, _, _ in observed_locs.values()})
    if len(observed_locs) != records["location_count"]:
        raise AssertionError(f"location_count mismatch: {len(observed_locs)} != {records['location_count']}")
    if obs_files != records["observed_source_files"]:
        raise AssertionError(f"observed_source_files mismatch: {obs_files}")

    recorded_locs = {
        int(loc["va"], 16): (loc["file"], int(loc["line"]), int(loc["col"]))
        for loc in records["locations"]
    }
    if recorded_locs != observed_locs:
        raise AssertionError("recorded locations do not match ELF .data.rel.ro Locations")

    loc_starts: set[int] = set()
    loc_bytes = 0
    for entry in records["l1_shared_location_fdes"]:
        s = int(entry["start"], 16)
        e = int(entry["end"], 16)
        sz = int(entry["size"])
        if s in loc_starts:
            raise AssertionError(f"duplicate location FDE 0x{s:x}")
        loc_starts.add(s)
        if e - s != sz or fdes.get(s) != e:
            raise AssertionError(f"FDE mismatch at 0x{s:x}")
        loc_bytes += sz
    if loc_starts != set(fde_to_locs.keys()):
        raise AssertionError(
            f"location FDE completeness mismatch: recorded={len(loc_starts)} vs elf={len(fde_to_locs)}"
        )

    biz_starts: set[int] = set()
    biz_bytes = 0
    for entry in records["l1_shared_business_fdes"]:
        s = int(entry["start"], 16)
        e = int(entry["end"], 16)
        sz = int(entry["size"])
        if s in biz_starts or s in loc_starts:
            raise AssertionError(f"duplicate or overlapping business FDE 0x{s:x}")
        biz_starts.add(s)
        if e - s != sz or fdes.get(s) != e:
            raise AssertionError(f"business FDE mismatch for {entry['name']} at 0x{s:x}")
        biz_bytes += sz

    sm = records["summary"]
    if (
        sm["observed_source_files"] != len(obs_files)
        or sm["location_count"] != len(observed_locs)
        or sm["l1_shared_location_fdes"] != len(loc_starts)
        or sm["l1_shared_location_fde_bytes"] != loc_bytes
        or sm["l1_shared_business_fdes"] != len(biz_starts)
        or sm["l1_shared_business_fde_bytes"] != biz_bytes
        or sm["combined_unique_fdes"] != len(loc_starts) + len(biz_starts)
        or sm["combined_unique_fde_bytes"] != loc_bytes + biz_bytes
    ):
        raise AssertionError("summary counts mismatch")

    text_va, text_off, text_sz = sections[".text"]
    ro_va, ro_off, ro_sz = sections[".rodata"]

    for anc in records["instruction_anchors"]:
        va = int(anc["va"], 16)
        want = bytes.fromhex(anc["hex"])
        if not (text_va <= va and va + len(want) <= text_va + text_sz):
            raise AssertionError(f"anchor out of .text: {anc['name']}")
        got = data[text_off + (va - text_va) : text_off + (va - text_va) + len(want)]
        if got != want:
            raise AssertionError(f"anchor mismatch for {anc['name']}: {got.hex()} != {want.hex()}")

    for lit in records["rodata_literals"]:
        va = int(lit["va"], 16)
        want = lit["ascii"].encode("ascii")
        if not (ro_va <= va and va + len(want) <= ro_va + ro_sz):
            raise AssertionError(f"literal out of .rodata: {lit['name']}")
        got = data[ro_off + (va - ro_va) : ro_off + (va - ro_va) + len(want)]
        if got != want:
            raise AssertionError(f"literal mismatch for {lit['name']}: {got!r} != {want!r}")

    for cst in records["rodata_constants"]:
        va = int(cst["va"], 16)
        want = bytes.fromhex(cst["hex"])
        if not (ro_va <= va and va + len(want) <= ro_va + ro_sz):
            raise AssertionError(f"constant out of .rodata: {cst['name']}")
        got = data[ro_off + (va - ro_va) : ro_off + (va - ro_va) + len(want)]
        if got != want:
            raise AssertionError(f"constant mismatch for {cst['name']}: {got.hex()} != {want.hex()}")


def run_negative_controls(
    records: dict,
    data: bytes,
    sections: dict[str, tuple[int, int, int]],
    fdes: dict[int, int],
    observed_locs: dict[int, tuple[str, int, int]],
    fde_to_locs: dict[int, list[int]],
) -> int:
    mutations = [
        ("bad_loc_count", lambda r: r.update({"location_count": r["location_count"] + 1})),
        (
            "bad_fde_end",
            lambda r: r["l1_shared_business_fdes"][0].update({"end": "0x46e83b9", "size": 969}),
        ),
        (
            "bad_opcode",
            lambda r: r["instruction_anchors"][0].update({"hex": "400fb6c7488d0d04530efc486304814801c9"}),
        ),
        (
            "bad_literal",
            lambda r: r["rodata_literals"][0].update({"ascii": "invalid chaiX"}),
        ),
        (
            "bad_constant",
            lambda r: r["rodata_constants"][0].update({"hex": "00" + r["rodata_constants"][0]["hex"][2:]}),
        ),
    ]
    rejected = 0
    for name, mutate in mutations:
        bad = copy.deepcopy(records)
        mutate(bad)
        try:
            verify_records(bad, data, sections, fdes, observed_locs, fde_to_locs)
        except AssertionError:
            rejected += 1
        else:
            raise AssertionError(f"negative control {name} unexpectedly passed")
    return rejected


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--generate", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    components = json.loads(COMPONENTS_PATH.read_text(encoding="utf-8"))["components"]
    data = (REPO / TARGET_REL).read_bytes()
    sections = parse_elf_sections(data)
    fdes, ordered_fdes = load_fde_index()
    observed_locs = scan_l1_shared_locations(data, sections, components)
    fde_to_locs = scan_location_referencing_fdes(data, sections, ordered_fdes, set(observed_locs.keys()))

    if args.generate:
        records = build_records(data, fdes, observed_locs, fde_to_locs)
        RECORDS_PATH.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    else:
        records = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))

    verify_records(records, data, sections, fdes, observed_locs, fde_to_locs)
    neg = 0
    if args.self_test:
        neg = run_negative_controls(records, data, sections, fdes, observed_locs, fde_to_locs)
    sm = records["summary"]
    print(
        f"PASS: l1-shared closure verified — {sm['observed_source_files']}/8 files, "
        f"{sm['location_count']}/13 Locations, "
        f"{sm['l1_shared_location_fdes']}/39 Location FDEs ({sm['l1_shared_location_fde_bytes']} B), "
        f"{sm['l1_shared_business_fdes']}/14 business FDEs ({sm['l1_shared_business_fde_bytes']} B), "
        f"combined {sm['combined_unique_fdes']} unique FDEs ({sm['combined_unique_fde_bytes']} B), "
        f"{neg}/5 negative controls rejected"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
