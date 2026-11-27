#!/usr/bin/env python3
"""Verify node #115 constants (global_constants) gate-closure evidence and 12 CGU FDE byte matches."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

PACKET_DIR = Path(__file__).resolve().parent
REPO_ROOT = PACKET_DIR.parents[2]
BINARY_PATH = REPO_ROOT / "artifacts" / "node" / "115" / "hl-node"
FDE_TSV = REPO_ROOT / "work" / "index" / "node-115-fde.tsv"
SOURCE_PATH = PACKET_DIR / "lib.rs"
RECORDS_PATH = PACKET_DIR / "records.json"

sys.path.insert(0, str(REPO_ROOT / "tools"))
sys.path.insert(0, str(REPO_ROOT / "research" / "work-items" / "RE-002-node115-std-census"))
from byte_progress import compare  # noqa: E402
from census import object_functions  # noqa: E402
from elf_index import sections  # noqa: E402

EXPECTED_BINARY_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
)
EXPECTED_BINARY_SIZE = 105_896_032

EXPECTED_AWS_NAMES = [
    "Ec", "DummyTokyo", "DummyTokyo2", "GaOnchain", "GbOnchain",
    "NodeTestnet", "NodeTestnet2", "NodeTestnet3", "NodeTestnet4",
    "Ea", "Ea2", "Ea3", "EaMm", "EaTx",
    "HeavyTestnet", "HeavyMainnet", "Eb", "Ed", "Ee",
    "SoloTestnet", "SoloMainnet", "LockerTestnet", "LockerMainnet",
    "RpcTestnet", "RpcSandbox", "RpcMainnet", "RpcMainnet2",
    "Sa", "Sb", "Sc", "Sd", "WebSandbox", "SoloSandbox",
    "NvTestnet", "NvTestnet2", "NvMainnet", "NvMainnet2", "NvMainnet3",
    "JoinMainnet", "DummyNv",
    "FBinSpot", "FBinSpot2", "FBinSpot3", "FBinSpot4",
    "FBinSpot5", "FBinSpot6", "FBinSpot7", "FBinSpot8",
    "FBinPerp", "FBinPerp2",
    "FOkexSpot", "FOkexSpot2", "FOkexPerp",
    "FHuobiSpot", "FHuobiSpot2", "FHuobiSpot3", "FHuobiSpot4",
    "FHuobiPi", "FHuobiPerp",
    "FCobSpot", "FKraSpot", "FBybitSpot",
    "ScratchDummy", "ScratchCron", "OBinSpot", "FHlPerp",
    "GaHlPerp", "GaHlPerp2", "GaHlPerp3",
    "GbHlPerp", "GbHlPerp2", "GbHlPerp3",
    "GcHlPerp", "GcHlPerp2",
    "GdHlPerp", "GdHlPerp2",
    "GsHlPerp", "EaHlPerp", "EbHlPerp",
]

EXPECTED_RODATA_4671D0_ONES = [
    1, 2, 9, 10, 11, 12, 13, 15, 16, 18, 20, 22, 25, 26, 35, 36, 37, 38
]

# Complete 40-FDE classification of the global_constants CGU (0x1772f80..0x1778ad7, 23,050 B)
CGU_INVENTORY = [
    (0x1772f80, 0x1772f94, "matched_here", "<String as Display>::fmt (f.pad thunk #1)"),
    (0x1772fa0, 0x1773069, "sdallocx_wrapper", "aws_name_path (home_dir -> cham_dir -> format!(\"{cham}/aws_name\"))"),
    (0x1773070, 0x1773fc4, "serde_json_helper", "serde_json AwsName deserializer driver"),
    (0x1773fd0, 0x17740fe, "sdallocx_wrapper", "read_aws_name_fallback (read {cham}/aws_name -> trim -> from_str)"),
    (0x1774100, 0x1774be1, "matched_existing_byte_windows", "AwsName serde visit_str (already in research/byte-windows.json)"),
    (0x1774bf0, 0x1774c56, "matched_here", "LazyLock<StaticConfig> Once::call_once_force closure"),
    (0x1774c60, 0x1774c79, "matched_here", "Visitor::expecting(\"variant identifier\")"),
    (0x1774c80, 0x1774ce6, "matched_here", "LazyLock<StaticConfig> FnOnce::call_once vtable shim"),
    (0x1774cf0, 0x1774dc1, "sdallocx_drop_glue", "drop_in_place::<std::io::Error> (by-ref, jemalloc sdallocx + tzcntq)"),
    (0x1774dd0, 0x1774e37, "sdallocx_drop_glue", "drop_in_place::<serde_json::Error> (jemalloc sdallocx)"),
    (0x1774e40, 0x1774e59, "matched_here", "Visitor::expecting(\"VariantNotFound\")"),
    (0x1774e60, 0x17754f1, "matched_here", "AwsName::fmt (79-variant Display)"),
    (0x1775500, 0x1775dc6, "matched_here", "AwsName::from_str (79-variant parser)"),
    (0x1775dd0, 0x1775ede, "serde_json_helper", "serde_json::from_str::<StaticConfig> entry"),
    (0x1775ee0, 0x1775f46, "serde_json_helper", "serde_json StrRead::parse_whitespace"),
    (0x1775f50, 0x1776292, "serde_json_helper", "serde_json Deserializer::deserialize_struct"),
    (0x17762a0, 0x1776427, "serde_json_helper", "serde_json Deserializer::deserialize_ignored_any"),
    (0x1776430, 0x177667a, "serde_json_helper", "serde_json Deserializer::ignore_value"),
    (0x1776680, 0x1776908, "serde_json_helper", "serde_json Deserializer::ignore_string"),
    (0x1776910, 0x1776c17, "serde_json_helper", "serde_json Deserializer::ignore_number"),
    (0x1776c20, 0x1776c67, "serde_json_helper", "serde_json StrRead::peek"),
    (0x1776c70, 0x1776cbe, "serde_json_helper", "serde_json Error::syntax"),
    (0x1776cc0, 0x1776db2, "serde_json_helper", "serde_json StrRead::parse_str"),
    (0x1776dc0, 0x1776f41, "serde_json_helper", "serde_json StrRead::parse_str_bytes"),
    (0x1776f50, 0x177707a, "serde_json_helper", "serde_json StrRead::parse_escape"),
    (0x1777080, 0x17771a3, "serde_json_helper", "serde_json StrRead::decode_hex_escape"),
    (0x17771b0, 0x1777faf, "serde_json_helper", "StaticConfig serde MapAccess::visit_map"),
    (0x1777fb0, 0x1777fc4, "matched_here", "<String as Display>::fmt (f.pad thunk #2)"),
    (0x1777fd0, 0x177805b, "serde_json_helper", "serde_json MapAccess::next_key_seed"),
    (0x1778060, 0x17780b5, "sdallocx_drop_glue", "drop_in_place::<Box<serde_json::error::ErrorImpl>> (jemalloc sdallocx)"),
    (0x17780c0, 0x1778265, "sdallocx_wrapper", "cham_dir (probe {home}/cham else {home}/hl + create_dir_all)"),
    (0x1778270, 0x17782d7, "matched_here", "cham_dir create_dir_all outlined panic (\"could not create {dir}: {err}\")"),
    (0x17782e0, 0x17783dd, "sdallocx_wrapper", "home_dir (std::env::home_dir -> UTF-8 String, fallback getpwuid_r)"),
    (0x17783e0, 0x177858d, "sdallocx_wrapper", "read_aws_name (read {code_dir}/static_config -> serde_json -> fallback NvTestnet)"),
    (0x1778590, 0x17785a3, "matched_here", "<&str as Display>::fmt thunk"),
    (0x17785b0, 0x17785c9, "matched_here", "Visitor::expecting(\"unit\")"),
    (0x17785d0, 0x17785e9, "matched_existing_stream_f", "Visitor::expecting(\"struct StaticConfig\") (already in RE-015-node115-stream-f-byte-matches)"),
    (0x17785f0, 0x177876f, "sdallocx_wrapper", "StaticConfig::new (home_dir, cham_dir, code_dir, read_aws_name)"),
    (0x1778770, 0x177883e, "sdallocx_drop_glue", "drop_in_place::<std::io::Error> (by-value, jemalloc sdallocx + tzcntq)"),
    (0x1778840, 0x1778ad7, "matched_here", "str::trim (Unicode White_Space trim)"),
]

# 12 brand-new, zero-overlap, 100% relocation-qualified compiled-byte windows
# (symbol_match_tokens, start_va, end_va, label, expecting_string_or_none)
WINDOWS = [
    (("gc_aws_name_from_str",), 0x1775500, 0x1775dc6, "constants AwsName::from_str (0x1775500)", None),
    (("gc_aws_name_fmt",), 0x1774e60, 0x17754f1, "constants AwsName::fmt Display (0x1774e60)", None),
    (("gc_str_trim",), 0x1778840, 0x1778ad7, "constants str::trim Unicode whitespace (0x1778840)", None),
    (("gc_cham_dir_panic",), 0x1778270, 0x17782d7, "constants cham_dir create_dir_all panic (0x1778270)", None),
    (("call_once_force", "closure"), 0x1774bf0, 0x1774c56, "constants LazyLock<StaticConfig> Once::call_once_force (0x1774bf0)", None),
    (("FnOnce", "vtable"), 0x1774c80, 0x1774ce6, "constants LazyLock<StaticConfig> FnOnce::call_once shim (0x1774c80)", None),
    (("gc_expecting_variant_identifier",), 0x1774c60, 0x1774c79, "constants Visitor::expecting variant identifier (0x1774c60)", "variant identifier"),
    (("gc_expecting_variant_not_found",), 0x1774e40, 0x1774e59, "constants Visitor::expecting VariantNotFound (0x1774e40)", "VariantNotFound"),
    (("gc_expecting_unit",), 0x17785b0, 0x17785c9, "constants Visitor::expecting unit (0x17785b0)", "unit"),
    (("gc_disp_string_thunk",), 0x1772f80, 0x1772f94, "constants <String as Display>::fmt thunk #1 (0x1772f80)", None),
    (("gc_disp_string_thunk",), 0x1777fb0, 0x1777fc4, "constants <String as Display>::fmt thunk #2 (0x1777fb0)", None),
    (("gc_disp_str_thunk",), 0x1778590, 0x17785a3, "constants <&str as Display>::fmt thunk (0x1778590)", None),
]


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


def compile_object() -> tuple[bytes, str]:
    ver = subprocess.check_output(["rustc", "+1.95.0", "--version"], text=True).strip()
    with tempfile.TemporaryDirectory() as td:
        obj = Path(td) / "constants_gate_closure.o"
        subprocess.run(
            [
                "rustc",
                "+1.95.0",
                "--edition=2021",
                "--crate-type=rlib",
                "--crate-name=node115_constants_gate_closure",
                "-C",
                "opt-level=3",
                "-C",
                "overflow-checks=yes",
                "--emit=obj",
                str(SOURCE_PATH),
                "-o",
                str(obj),
            ],
            check=True,
        )
        return obj.read_bytes(), ver


def _make_va_to_off(data: bytes):
    secs = {s["name"]: s for s in sections(data)}
    def va_to_off(va: int) -> int:
        for s in secs.values():
            if s["address"] <= va < s["address"] + s["size"]:
                return s["offset"] + (va - s["address"])
        raise AssertionError(f"VA {hex(va)} not mapped")
    return secs, va_to_off


def _read_rela_relative_map(data: bytes, secs: dict) -> dict[int, int]:
    rela = secs[".rela.dyn"]
    rel_map: dict[int, int] = {}
    for off in range(rela["offset"], rela["offset"] + rela["size"], 24):
        r_off, r_info, r_addend = struct.unpack_from("<QQq", data, off)
        if (r_info & 0xFFFFFFFF) == 8:
            rel_map[r_off] = r_addend
    return rel_map


def verify_static_anchors(data: bytes) -> dict:
    secs, va_to_off = _make_va_to_off(data)
    rel_map = _read_rela_relative_map(data, secs)

    # 1. aws_name.rs:213:29 panic Location at 0x6411208 + 2 call sites (0x2e12c68, 0x2e12fde)
    loc_va = 0x6411208
    file_ptr = rel_map.get(loc_va)
    if file_ptr is None:
        raise AssertionError("missing .rela.dyn entry for 0x6411208")
    file_len, line_no, col_no = struct.unpack_from("<QII", data, va_to_off(loc_va + 8))
    file_str = data[va_to_off(file_ptr) : va_to_off(file_ptr) + file_len].decode("ascii")
    if (file_str, line_no, col_no) != ("global_constants/src/aws_name.rs", 213, 29):
        raise AssertionError(f"unexpected Location at 0x6411208: {(file_str, line_no, col_no)}")

    not_impl = data[va_to_off(0x481F69) : va_to_off(0x481F69) + 15].decode("ascii")
    if not_impl != "not implemented":
        raise AssertionError(f"unexpected panic string at 0x481f69: {not_impl!r}")

    # cmp byte ptr [r14 + 0xbd5], 0 -> 41 80 be d5 0b 00 00 00
    expected_cmp = bytes.fromhex("4180bed50b000000")
    for site in (0x2E12C68, 0x2E12FDE):
        got = data[va_to_off(site) : va_to_off(site) + len(expected_cmp)]
        if got != expected_cmp:
            raise AssertionError(f"missing Chain::Local cmp at {hex(site)}: {got.hex()}")

    # Verify both panic branches load 0x6411208 via lea rdx, [rip+disp]
    for site in (0x2E13A24, 0x2E13A3F):
        ins = data[va_to_off(site) : va_to_off(site) + 7]
        if ins[:3] != b"\x48\x8d\x15":
            raise AssertionError(f"expected lea rdx,[rip+disp] at {hex(site)}: {ins.hex()}")
        disp = struct.unpack_from("<i", ins, 3)[0]
        if site + 7 + disp != loc_va:
            raise AssertionError(f"lea target mismatch at {hex(site)}: {hex(site + 7 + disp)}")

    # 2. home_dir (0x17782e0) -> GOT 0x64e2410 -> std::env::home_dir (0x5c9abb0)
    call_ins = data[va_to_off(0x17782F4) : va_to_off(0x17782F4) + 6]
    if call_ins[:2] != b"\xff\x15":
        raise AssertionError(f"expected call *got(%rip) at 0x17782f4: {call_ins.hex()}")
    got_slot = 0x17782F4 + 6 + struct.unpack_from("<i", call_ins, 2)[0]
    std_home_va = rel_map.get(got_slot)
    if got_slot != 0x64E2410 or std_home_va != 0x5C9ABB0:
        raise AssertionError(f"unexpected home_dir GOT chain: {hex(got_slot)} -> {std_home_va}")
    # Verify "HOME" (0x454d4f48) literal in 0x5c9abb0..0x5c9ac40 and sysconf(_SC_GETPW_R_SIZE_MAX = 0x46)
    std_home_body = data[va_to_off(0x5C9ABB0) : va_to_off(0x5C9AC40)]
    if b"HOME" not in std_home_body or b"\xbf\x46\x00\x00\x00" not in std_home_body:
        raise AssertionError("std::env::home_dir missing HOME or sysconf(_SC_GETPW_R_SIZE_MAX=0x46)")

    # 3. .rodata 0x4671d0 (79 f64s) and .data.rel.ro 0x63f8788 / 0x6410ce8 (79 AwsName strings)
    f64_vals = struct.unpack_from("<79d", data, va_to_off(0x4671D0))
    ones = [i for i, v in enumerate(f64_vals) if v == 1.0]
    fives = [i for i, v in enumerate(f64_vals) if v == 5.0]
    if ones != EXPECTED_RODATA_4671D0_ONES or len(fives) != 61:
        raise AssertionError(f"unexpected 0x4671d0 f64 table: ones={ones}, fives={len(fives)}")

    for tbl_va in (0x63F8788, 0x6410CE8):
        names = []
        for i in range(79):
            ent = tbl_va + i * 16
            ptr = rel_map.get(ent)
            if ptr is None:
                raise AssertionError(f"missing reloc at {hex(ent)}")
            ln = struct.unpack_from("<Q", data, va_to_off(ent + 8))[0]
            names.append(data[va_to_off(ptr) : va_to_off(ptr) + ln].decode("ascii"))
        if names != EXPECTED_AWS_NAMES:
            raise AssertionError(f"AwsName string table mismatch at {hex(tbl_va)}")

    return {
        "aws_name_213_location": {
            "va": hex(loc_va),
            "file": file_str,
            "line": line_no,
            "col": col_no,
            "panic_message": not_impl,
            "chain_local_cmp_sites": ["0x2e12c68", "0x2e12fde"],
            "panic_load_sites": ["0x2e13a24", "0x2e13a3f"],
        },
        "home_dir_getpwuid_r": {
            "wrapper_va": "0x17782e0",
            "got_slot": hex(got_slot),
            "std_home_dir_va": hex(std_home_va),
            "env_var": "HOME",
            "sysconf_sc_getpw_r_size_max": 0x46,
        },
        "rodata_4671d0": {
            "va": "0x4671d0",
            "entries": 79,
            "ones_indices": ones,
            "fives_count": len(fives),
            "sha256": hashlib.sha256(data[va_to_off(0x4671D0) : va_to_off(0x4671D0) + 79 * 8]).hexdigest(),
        },
        "aws_name_string_tables": {
            "primary_va": "0x63f8788",
            "secondary_va": "0x6410ce8",
            "count": 79,
            "names_sha256": hashlib.sha256("\n".join(EXPECTED_AWS_NAMES).encode("ascii")).hexdigest(),
        },
    }


def build_records(data: bytes) -> dict:
    if len(data) != EXPECTED_BINARY_SIZE:
        raise AssertionError(f"size mismatch: {len(data)}")
    sha = hashlib.sha256(data).hexdigest()
    if sha != EXPECTED_BINARY_SHA256:
        raise AssertionError(f"sha256 mismatch: {sha}")

    _, va_to_off = _make_va_to_off(data)
    fdes = load_fde_map()
    anchors = verify_static_anchors(data)

    # Verify complete 40-FDE CGU inventory (0x1772f80..0x1778ad7) + adjacent Chain::fmt (0x1778c60)
    if fdes:
        actual_cgu = sorted((s, e) for s, e in fdes.items() if 0x1772F80 <= s <= 0x1778AD7)
        expected_cgu = [(s, e) for s, e, _, _ in CGU_INVENTORY]
        if actual_cgu != expected_cgu:
            raise AssertionError(f"CGU FDE inventory mismatch: {len(actual_cgu)} vs {len(expected_cgu)}")
        if fdes.get(0x1778C60) != 0x1778CCA:
            raise AssertionError("adjacent Chain::fmt FDE mismatch at 0x1778c60")

    cgu_rows = []
    cgu_category_counts: dict[str, int] = {}
    cgu_total_bytes = 0
    for s, e, cat, desc in CGU_INVENTORY:
        sz = e - s
        cgu_total_bytes += sz
        cgu_category_counts[cat] = cgu_category_counts.get(cat, 0) + 1
        cgu_rows.append(
            {
                "start": hex(s),
                "end": hex(e),
                "bytes": sz,
                "category": cat,
                "role": desc,
            }
        )

    obj_bytes, rustc_version = compile_object()
    compiled_funcs = list(object_functions(obj_bytes))

    def find_compiled(tokens: tuple[str, ...]):
        for syms, c_bytes, rels in compiled_funcs:
            if any(all(tok in sym for tok in tokens) for sym in syms):
                rel_dicts = [
                    {"offset": r[0], "type": r[1], "addend": r[2], "width": 4}
                    for r in rels
                ]
                return syms[0], c_bytes, rel_dicts
        raise AssertionError(f"compiled symbol not found for {tokens}")

    rows = []
    total_bytes = 0
    total_raw_equal = 0
    total_rel_qual = 0
    seen_starts = set()

    for sym_tokens, start_va, end_va, label, exp_str in WINDOWS:
        if start_va in seen_starts:
            raise AssertionError(f"duplicate start_va {hex(start_va)}")
        seen_starts.add(start_va)
        if fdes and fdes.get(start_va) != end_va:
            raise AssertionError(f"FDE mismatch at {hex(start_va)}: expected {hex(end_va)}, got {fdes.get(start_va)}")

        t_bytes = data[va_to_off(start_va) : va_to_off(end_va)]
        matched_sym, c_bytes, rels = find_compiled(sym_tokens)
        if len(c_bytes) != len(t_bytes):
            raise AssertionError(f"length mismatch for {sym_tokens} at {hex(start_va)}: {len(c_bytes)} vs {len(t_bytes)}")

        if exp_str is not None:
            disp = struct.unpack_from("<i", t_bytes, 14)[0]
            ln = struct.unpack_from("<I", t_bytes, 19)[0]
            str_va = start_va + 18 + disp
            got_str = data[va_to_off(str_va) : va_to_off(str_va) + ln].decode("ascii")
            if got_str != exp_str:
                raise AssertionError(f"expecting string mismatch at {hex(start_va)}: {got_str!r} != {exp_str!r}")

        cmp_res = compare(c_bytes, t_bytes, rels)
        if not cmp_res["relocation_qualified"] or cmp_res["non_relocation_difference_offsets"]:
            raise AssertionError(f"not relocation-qualified for {sym_tokens} at {hex(start_va)}: {cmp_res}")

        sz = end_va - start_va
        total_bytes += sz
        total_raw_equal += cmp_res["raw_equal_bytes"]
        total_rel_qual += 1

        rows.append(
            {
                "component": "constants",
                "symbol": matched_sym,
                "start": hex(start_va),
                "end": hex(end_va),
                "bytes": sz,
                "label": label,
                "expecting_string": exp_str,
                "target_body_sha256": hashlib.sha256(t_bytes).hexdigest(),
                "compiled_body_sha256": hashlib.sha256(c_bytes).hexdigest(),
                "raw_equal_bytes": cmp_res["raw_equal_bytes"],
                "relocation_bytes": cmp_res["relocation_bytes"],
                "relocation_qualified": True,
                "relocations": rels,
            }
        )

    return {
        "work_item": "RE-015-node115-constants-gate-closure",
        "target_path": "artifacts/node/115/hl-node",
        "target_sha256": sha,
        "rustc_version": rustc_version,
        "rustc_flags": [
            "--edition=2021",
            "--crate-type=rlib",
            "-C",
            "opt-level=3",
            "-C",
            "overflow-checks=yes",
        ],
        "source_sha256": hashlib.sha256(SOURCE_PATH.read_bytes()).hexdigest(),
        "summary": {
            "cgu_total_fdes": len(cgu_rows),
            "cgu_total_bytes": cgu_total_bytes,
            "cgu_category_counts": cgu_category_counts,
            "windows": len(rows),
            "total_bytes": total_bytes,
            "raw_equal_bytes": total_raw_equal,
            "relocation_qualified_windows": total_rel_qual,
        },
        "static_anchors": anchors,
        "cgu_inventory": cgu_rows,
        "windows": rows,
    }


def verify_records(records: dict, data: bytes, rebuild: bool = True) -> None:
    if records.get("target_sha256") != EXPECTED_BINARY_SHA256:
        raise AssertionError("target_sha256 mismatch in records")
    if len(data) != EXPECTED_BINARY_SIZE or hashlib.sha256(data).hexdigest() != EXPECTED_BINARY_SHA256:
        raise AssertionError("binary authentication failed")
    anchors = verify_static_anchors(data)
    if records.get("static_anchors") != anchors:
        raise AssertionError("static_anchors mismatch in records")
    if rebuild:
        fresh = build_records(data)
        if fresh["windows"] != records["windows"]:
            raise AssertionError("rebuilt windows differ from committed records.json")
        if fresh["cgu_inventory"] != records["cgu_inventory"]:
            raise AssertionError("rebuilt cgu_inventory differs from committed records.json")
        if fresh["summary"] != records["summary"]:
            raise AssertionError("rebuilt summary differs from committed records.json")
    else:
        _, va_to_off = _make_va_to_off(data)
        for row in records["windows"]:
            s = int(row["start"], 16)
            e = int(row["end"], 16)
            t_bytes = data[va_to_off(s) : va_to_off(e)]
            if hashlib.sha256(t_bytes).hexdigest() != row["target_body_sha256"]:
                raise AssertionError(f"body sha mismatch at {row['start']}")
            if row["expecting_string"] is not None:
                disp = struct.unpack_from("<i", t_bytes, 14)[0]
                ln = struct.unpack_from("<I", t_bytes, 19)[0]
                str_va = s + 18 + disp
                got = data[va_to_off(str_va) : va_to_off(str_va) + ln].decode("ascii")
                if got != row["expecting_string"]:
                    raise AssertionError(f"expecting string mismatch at {row['start']}")


def run_negative_controls(records: dict, data: bytes) -> int:
    rejected = 0

    # 1. Tampered target_sha256
    bad1 = copy.deepcopy(records)
    bad1["target_sha256"] = "0" * 64
    try:
        verify_records(bad1, data, rebuild=False)
    except AssertionError:
        rejected += 1

    # 2. Tampered target_body_sha256 on AwsName::from_str (0x1775500)
    bad2 = copy.deepcopy(records)
    bad2["windows"][0]["target_body_sha256"] = "f" * 64
    try:
        verify_records(bad2, data, rebuild=False)
    except AssertionError:
        rejected += 1

    # 3. Tampered aws_name.rs:213:29 line number in static_anchors
    bad3 = copy.deepcopy(records)
    bad3["static_anchors"]["aws_name_213_location"]["line"] = 999
    try:
        verify_records(bad3, data, rebuild=False)
    except AssertionError:
        rejected += 1

    # 4. Tampered expecting_string on Visitor::expecting window
    bad4 = copy.deepcopy(records)
    bad4["windows"][6]["expecting_string"] = "wrong identifier"
    try:
        verify_records(bad4, data, rebuild=False)
    except AssertionError:
        rejected += 1

    return rejected


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--generate", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    data = BINARY_PATH.read_bytes()
    if args.generate:
        recs = build_records(data)
        RECORDS_PATH.write_text(json.dumps(recs, indent=2) + "\n", encoding="utf-8")
        s = recs["summary"]
        print(
            f"Generated {s['windows']} windows ({s['total_bytes']} B, "
            f"{s['raw_equal_bytes']} raw-equal, {s['relocation_qualified_windows']}/{s['windows']} rel-qual; "
            f"CGU inventory {s['cgu_total_fdes']} FDEs / {s['cgu_total_bytes']} B)"
        )
        return 0

    recs = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))
    verify_records(recs, data, rebuild=True)
    if args.self_test:
        rej = run_negative_controls(recs, data)
        if rej != 4:
            raise AssertionError(f"expected 4 rejected negative controls, got {rej}")
        s = recs["summary"]
        print(
            f"SELF-TEST OK: {s['windows']}/{s['windows']} relocation-qualified, "
            f"{s['total_bytes']} B ({s['raw_equal_bytes']} raw-equal), "
            f"{s['cgu_total_fdes']} CGU FDEs classified, 4/4 negative controls rejected"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
