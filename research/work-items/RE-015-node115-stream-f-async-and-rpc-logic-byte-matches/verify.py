#!/usr/bin/env python3
"""Verify 38 strictly disjoint, 100% pure first-party Stream F (evm-rpc + info-api)
business-logic FDE byte matches (7,090 B) live-compiled with rustc +1.95.0 against node #115."""

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
BYTE_WINDOWS_PATH = REPO_ROOT / "research" / "byte-windows.json"
WORK_ITEMS_DIR = REPO_ROOT / "research" / "work-items"
SRC_PATH = PACKET_DIR / "main.rs"
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

# .data.rel.ro Location anchors proving defining crates & source lines
EXPECTED_LOCATIONS = [
    (0x642DC48, "evm_rpc/src/evm_store.rs", 452, 61),
    (0x6442DE0, "info_server/src/abci_state_info_handler.rs", 82, 16),
    (0x6442DF8, "info_server/src/abci_state_info_handler.rs", 81, 12),
]

# 38 strictly disjoint, 100% first-party business-logic FDEs (7,090 B):
#   - 1 evm-rpc FDE (94 B): evm_rpc/src/evm_store.rs:452 resolve_block_number
#   - 37 info-api FDEs (6,996 B): info_server/src/abci_state_info_handler.rs:81-82 async Future::poll
TARGET_WINDOWS = [
    ("evm-rpc", 0x232DF90, 0x232DFEE, "evm-rpc evm_store::resolve_block_number (0x232df90)"),
    ("info-api", 0x29781A0, 0x29782AB, "info-api abci_state_info_handler async poll (0x29781a0)"),
    ("info-api", 0x29782B0, 0x2978346, "info-api abci_state_info_handler async poll (0x29782b0)"),
    ("info-api", 0x2978350, 0x29783EE, "info-api abci_state_info_handler async poll (0x2978350)"),
    ("info-api", 0x29783F0, 0x29784A1, "info-api abci_state_info_handler async poll (0x29783f0)"),
    ("info-api", 0x29784B0, 0x2978571, "info-api abci_state_info_handler async poll (0x29784b0)"),
    ("info-api", 0x2978640, 0x29786D0, "info-api abci_state_info_handler async poll (0x2978640)"),
    ("info-api", 0x29786D0, 0x29787DB, "info-api abci_state_info_handler async poll (0x29786d0)"),
    ("info-api", 0x2978900, 0x2978994, "info-api abci_state_info_handler async poll (0x2978900)"),
    ("info-api", 0x29789A0, 0x2978A99, "info-api abci_state_info_handler async poll (0x29789a0)"),
    ("info-api", 0x2978AA0, 0x2978B34, "info-api abci_state_info_handler async poll (0x2978aa0)"),
    ("info-api", 0x2978C30, 0x2978CC2, "info-api abci_state_info_handler async poll (0x2978c30)"),
    ("info-api", 0x2978CD0, 0x2978DC9, "info-api abci_state_info_handler async poll (0x2978cd0)"),
    ("info-api", 0x2978DD0, 0x2978E91, "info-api abci_state_info_handler async poll (0x2978dd0)"),
    ("info-api", 0x2978EA0, 0x2978F34, "info-api abci_state_info_handler async poll (0x2978ea0)"),
    ("info-api", 0x2978F40, 0x2978FD0, "info-api abci_state_info_handler async poll (0x2978f40)"),
    ("info-api", 0x2978FD0, 0x29790C9, "info-api abci_state_info_handler async poll (0x2978fd0)"),
    ("info-api", 0x29790D0, 0x2979164, "info-api abci_state_info_handler async poll (0x29790d0)"),
    ("info-api", 0x2979170, 0x297927B, "info-api abci_state_info_handler async poll (0x2979170)"),
    ("info-api", 0x2979370, 0x2979429, "info-api abci_state_info_handler async poll (0x2979370)"),
    ("info-api", 0x29795C0, 0x297967F, "info-api abci_state_info_handler async poll (0x29795c0)"),
    ("info-api", 0x2979680, 0x2979779, "info-api abci_state_info_handler async poll (0x2979680)"),
    ("info-api", 0x2979780, 0x29797F9, "info-api abci_state_info_handler async poll (0x2979780)"),
    ("info-api", 0x2979800, 0x297990B, "info-api abci_state_info_handler async poll (0x2979800)"),
    ("info-api", 0x2979C10, 0x2979CA6, "info-api abci_state_info_handler async poll (0x2979c10)"),
    ("info-api", 0x2979CB0, 0x2979D61, "info-api abci_state_info_handler async poll (0x2979cb0)"),
    ("info-api", 0x2979D70, 0x2979E67, "info-api abci_state_info_handler async poll (0x2979d70)"),
    ("info-api", 0x2979F50, 0x297A049, "info-api abci_state_info_handler async poll (0x2979f50)"),
    ("info-api", 0x297A140, 0x297A1E0, "info-api abci_state_info_handler async poll (0x297a140)"),
    ("info-api", 0x297A1E0, 0x297A276, "info-api abci_state_info_handler async poll (0x297a1e0)"),
    ("info-api", 0x297A330, 0x297A3E1, "info-api abci_state_info_handler async poll (0x297a330)"),
    ("info-api", 0x297A3F0, 0x297A4A1, "info-api abci_state_info_handler async poll (0x297a3f0)"),
    ("info-api", 0x297A5B0, 0x297A661, "info-api abci_state_info_handler async poll (0x297a5b0)"),
    ("info-api", 0x297A730, 0x297A7C4, "info-api abci_state_info_handler async poll (0x297a730)"),
    ("info-api", 0x297A8E0, 0x297A976, "info-api abci_state_info_handler async poll (0x297a8e0)"),
    ("info-api", 0x297A980, 0x297AA16, "info-api abci_state_info_handler async poll (0x297a980)"),
    ("info-api", 0x297AB00, 0x297ABB1, "info-api abci_state_info_handler async poll (0x297ab00)"),
    ("info-api", 0x297ABC0, 0x297ACB9, "info-api abci_state_info_handler async poll (0x297abc0)"),
]


def _make_va_to_off(data: bytes):
    secs = {s["name"]: s for s in sections(data)}

    def va_to_off(va: int) -> int:
        for s in secs.values():
            if s["address"] <= va < s["address"] + s["size"]:
                return s["offset"] + (va - s["address"])
        raise AssertionError(f"VA {hex(va)} not mapped")

    return va_to_off, secs


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


def verify_locations(data: bytes) -> list[dict]:
    va_to_off, secs = _make_va_to_off(data)
    rela = secs[".rela.dyn"]
    relmap: dict[int, int] = {}
    for off in range(rela["offset"], rela["offset"] + rela["size"], 24):
        r_offset, _r_info, r_addend = struct.unpack_from("<QQq", data, off)
        relmap[r_offset] = r_addend

    verified = []
    for loc_va, exp_path, exp_line, exp_col in EXPECTED_LOCATIONS:
        foff = va_to_off(loc_va)
        ptr = relmap.get(loc_va)
        if ptr is None:
            raise AssertionError(f"missing .rela.dyn entry for Location {hex(loc_va)}")
        ln, line, col = struct.unpack_from("<QII", data, foff + 8)
        path_str = data[va_to_off(ptr) : va_to_off(ptr) + ln].decode("utf-8")
        if (path_str, line, col) != (exp_path, exp_line, exp_col):
            raise AssertionError(
                f"Location {hex(loc_va)} mismatch: got {(path_str, line, col)}, "
                f"expected {(exp_path, exp_line, exp_col)}"
            )
        verified.append({"location_va": hex(loc_va), "file": path_str, "line": line, "col": col})
    return verified


def compile_harness() -> tuple[list[tuple[str, bytes, list[dict]]], str]:
    ver = subprocess.check_output(["rustc", "+1.95.0", "--version"], text=True).strip()
    with tempfile.TemporaryDirectory() as td:
        obj_path = Path(td) / "stream_f_async_rpc.o"
        subprocess.run(
            [
                "rustc",
                "+1.95.0",
                "--edition=2021",
                "--crate-type=bin",
                "--crate-name=stream_f_async_rpc",
                "-C",
                "opt-level=3",
                "-C",
                "overflow-checks=yes",
                "-C",
                "relocation-model=pie",
                "-C",
                "codegen-units=1",
                "--emit=obj",
                "-o",
                str(obj_path),
                str(SRC_PATH),
            ],
            check=True,
        )
        compiled = []
        for syms, c_bytes, rels in object_functions(obj_path.read_bytes()):
            sym = syms[0] if syms else ""
            if ("AbciStateInfoHandler" in sym and "closure" in sym) or "resolve_block_number" in sym:
                rel_dicts = [
                    {"offset": r[0], "type": r[1], "addend": r[2], "width": 4}
                    for r in rels
                ]
                compiled.append((sym, c_bytes, rel_dicts))
        return compiled, ver


def _assert_first_party_symbol(sym: str) -> None:
    if "stream_f_async_rpc" not in sym:
        raise AssertionError(f"non-first-party symbol: {sym}")
    for forbidden in ("4core", "5alloc", "3std"):
        if sym.startswith(f"_ZN{forbidden}") or sym.startswith("_RNvNtC"):
            raise AssertionError(f"stdlib symbol not allowed: {sym}")


def _parse_int(val) -> int | None:
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        try:
            return int(val, 16) if val.startswith(("0x", "0X")) else int(val)
        except ValueError:
            return None
    return None


def check_disjointness(windows: list[tuple[int, int]]) -> None:
    ws_sorted = sorted(windows)
    for (s1, e1), (s2, e2) in zip(ws_sorted, ws_sorted[1:]):
        if e1 > s2:
            raise AssertionError(f"internal overlap: {hex(s1)}..{hex(e1)} vs {hex(s2)}..{hex(e2)}")

    # Wave-consolidation-safe check vs research/byte-windows.json
    if BYTE_WINDOWS_PATH.exists():
        bw = json.loads(BYTE_WINDOWS_PATH.read_text(encoding="utf-8"))
        for row in bw.get("windows", []):
            ws = _parse_int(row.get("start"))
            we = _parse_int(row.get("end"))
            if ws is None or we is None:
                continue
            is_dep = "dependency" in row
            for os_, oe_ in ws_sorted:
                if os_ < we and ws < oe_:
                    if is_dep or (os_, oe_) != (ws, we):
                        raise AssertionError(
                            f"overlap with byte-windows.json ({'dep' if is_dep else 'partial fp'}): "
                            f"{hex(os_)}..{hex(oe_)} vs {hex(ws)}..{hex(we)}"
                        )

    # Strictly disjoint from ALL sibling compiled-byte packets (both start/end and start_va/end_va)
    for p in sorted(WORK_ITEMS_DIR.glob("*/records.json")):
        if p.parent == PACKET_DIR:
            continue
        name = p.parent.name
        if not any(
            tag in name
            for tag in ("byte-matches", "thinlto", "gate-closure", "100pct", "census", "consolidation")
        ):
            continue
        doc = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(doc, dict):
            continue
        for key in ("windows", "records", "matches", "entries"):
            arr = doc.get(key)
            if not isinstance(arr, list):
                continue
            for row in arr:
                if not isinstance(row, dict):
                    continue
                ws = _parse_int(row.get("start") if "start" in row else row.get("start_va"))
                we = _parse_int(row.get("end") if "end" in row else row.get("end_va"))
                if ws is None or we is None:
                    continue
                for os_, oe_ in ws_sorted:
                    if os_ < we and ws < oe_:
                        raise AssertionError(
                            f"overlap with {name}: {hex(os_)}..{hex(oe_)} vs {hex(ws)}..{hex(we)}"
                        )


def build_records(data: bytes) -> dict:
    if len(data) != EXPECTED_BINARY_SIZE:
        raise AssertionError(f"size mismatch: {len(data)}")
    sha = hashlib.sha256(data).hexdigest()
    if sha != EXPECTED_BINARY_SHA256:
        raise AssertionError(f"sha256 mismatch: {sha}")

    va_to_off, _ = _make_va_to_off(data)
    fdes = load_fde_map()
    verified_locs = verify_locations(data)
    compiled, rustc_version = compile_harness()

    by_len: dict[int, list[tuple[str, bytes, list[dict]]]] = {}
    for sym, cb, rd in compiled:
        by_len.setdefault(len(cb), []).append((sym, cb, rd))

    rows = []
    tot_b = 0
    tot_raw = 0
    by_comp: dict[str, dict[str, int]] = {}

    for comp, s, e, label in TARGET_WINDOWS:
        if fdes and fdes.get(s) != e:
            raise AssertionError(f"FDE mismatch at {hex(s)}: expected {hex(e)}, got {fdes.get(s)}")
        t_bytes = data[va_to_off(s) : va_to_off(e)]
        matched = None
        for sym, c_bytes, rels in by_len.get(len(t_bytes), []):
            cmp_res = compare(c_bytes, t_bytes, rels)
            if cmp_res["relocation_qualified"] and not cmp_res["non_relocation_difference_offsets"]:
                matched = (sym, c_bytes, rels, cmp_res)
                break
        if matched is None:
            raise AssertionError(f"no compiled match for {hex(s)}..{hex(e)} ({e - s} B)")
        sym, c_bytes, rels, cmp_res = matched
        _assert_first_party_symbol(sym)
        sz = e - s
        tot_b += sz
        tot_raw += cmp_res["raw_equal_bytes"]
        bc = by_comp.setdefault(comp, {"windows": 0, "bytes": 0, "raw_equal_bytes": 0})
        bc["windows"] += 1
        bc["bytes"] += sz
        bc["raw_equal_bytes"] += cmp_res["raw_equal_bytes"]
        rows.append(
            {
                "component": comp,
                "attribution": "first_party_logic",
                "symbol": sym,
                "start": hex(s),
                "end": hex(e),
                "bytes": sz,
                "label": label,
                "target_body_sha256": hashlib.sha256(t_bytes).hexdigest(),
                "compiled_body_sha256": hashlib.sha256(c_bytes).hexdigest(),
                "raw_equal_bytes": cmp_res["raw_equal_bytes"],
                "relocation_bytes": cmp_res["relocation_bytes"],
                "relocation_qualified": True,
                "relocations": rels,
            }
        )

    check_disjointness([(int(r["start"], 16), int(r["end"], 16)) for r in rows])

    return {
        "work_item": "RE-015-node115-stream-f-async-and-rpc-logic-byte-matches",
        "target_path": "artifacts/node/115/hl-node",
        "target_sha256": sha,
        "rustc_version": rustc_version,
        "source_file": "main.rs",
        "source_sha256": hashlib.sha256(SRC_PATH.read_bytes()).hexdigest(),
        "flags": [
            "+1.95.0",
            "--edition=2021",
            "--crate-type=bin",
            "--crate-name=stream_f_async_rpc",
            "-C",
            "opt-level=3",
            "-C",
            "overflow-checks=yes",
            "-C",
            "relocation-model=pie",
            "-C",
            "codegen-units=1",
        ],
        "locations": verified_locs,
        "summary": {
            "windows": len(rows),
            "total_bytes": tot_b,
            "raw_equal_bytes": tot_raw,
            "relocation_qualified_windows": len(rows),
            "by_component": by_comp,
        },
        "windows": rows,
    }


def verify_records(records: dict, data: bytes) -> None:
    if records.get("target_sha256") != EXPECTED_BINARY_SHA256:
        raise AssertionError("target_sha256 mismatch")
    if len(data) != EXPECTED_BINARY_SIZE or hashlib.sha256(data).hexdigest() != EXPECTED_BINARY_SHA256:
        raise AssertionError("binary authentication failed")
    if hashlib.sha256(SRC_PATH.read_bytes()).hexdigest() != records.get("source_sha256"):
        raise AssertionError("main.rs sha256 mismatch")

    fresh = build_records(data)
    if fresh["summary"] != records["summary"]:
        raise AssertionError(f"summary mismatch: {fresh['summary']} != {records['summary']}")
    if fresh["locations"] != records["locations"]:
        raise AssertionError("locations mismatch")
    if len(fresh["windows"]) != len(records["windows"]):
        raise AssertionError("window count mismatch")

    for fw, cw in zip(fresh["windows"], records["windows"]):
        _assert_first_party_symbol(cw["symbol"])
        for k in (
            "component",
            "attribution",
            "start",
            "end",
            "bytes",
            "target_body_sha256",
            "compiled_body_sha256",
            "raw_equal_bytes",
            "relocation_bytes",
            "relocations",
        ):
            if fw[k] != cw[k]:
                raise AssertionError(f"mismatch at {cw['start']} field {k}")


def run_negative_controls(records: dict, data: bytes) -> int:
    rejected = 0

    # 1. Tampered target_sha256
    bad1 = copy.deepcopy(records)
    bad1["target_sha256"] = "0" * 64
    try:
        verify_records(bad1, data)
    except AssertionError:
        rejected += 1

    # 2. Tampered target_body_sha256 on evm_rpc resolve_block_number (0x232df90)
    bad2 = copy.deepcopy(records)
    bad2["windows"][0]["target_body_sha256"] = "f" * 64
    try:
        verify_records(bad2, data)
    except AssertionError:
        rejected += 1

    # 3. Dropped relocation entry on 0x29781a0
    bad3 = copy.deepcopy(records)
    bad3["windows"][1]["relocations"] = bad3["windows"][1]["relocations"][1:]
    try:
        verify_records(bad3, data)
    except AssertionError:
        rejected += 1

    # 4. Forbidden stdlib symbol attribution rejected
    bad4 = copy.deepcopy(records)
    bad4["windows"][1]["symbol"] = "_ZN4core3ptr13drop_in_place17h0000000000000000E"
    try:
        verify_records(bad4, data)
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
            f"{s['raw_equal_bytes']}/{s['total_bytes']} = "
            f"{100 * s['raw_equal_bytes'] / s['total_bytes']:.2f}% raw-equal; "
            f"by_component={s['by_component']})"
        )
        return 0

    recs = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))
    verify_records(recs, data)
    if args.self_test:
        rej = run_negative_controls(recs, data)
        if rej != 4:
            raise AssertionError(f"expected 4 negative controls rejected, got {rej}")
        s = recs["summary"]
        print(
            f"PASS: {s['windows']}/{s['windows']} first-party Stream F logic FDEs relocation-qualified "
            f"({s['total_bytes']} B, {s['raw_equal_bytes']}/{s['total_bytes']} = "
            f"{100 * s['raw_equal_bytes'] / s['total_bytes']:.2f}% raw-equal; "
            f"evm-rpc={s['by_component']['evm-rpc']['windows']}w/{s['by_component']['evm-rpc']['bytes']}B, "
            f"info-api={s['by_component']['info-api']['windows']}w/{s['by_component']['info-api']['bytes']}B; "
            f"3/3 Locations verified, 0 overlaps, 4/4 negative controls rejected)"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
