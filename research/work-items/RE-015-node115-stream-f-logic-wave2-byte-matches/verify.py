#!/usr/bin/env python3
"""Verify 70 strictly disjoint, 100% pure first-party Stream F (info-api + bridge + evm)
business-logic FDE byte matches (29,815 B) against Linux x86-64 node #115."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
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
SMALL_SRC_PATH = PACKET_DIR / "small.rs"
HARNESS_DIR = PACKET_DIR / "harness"
BODIES_PATH = PACKET_DIR / "bodies.bin"
RECORDS_PATH = PACKET_DIR / "records.json"
LICENSES_PATH = PACKET_DIR / "licenses.json"

sys.path.insert(0, str(REPO_ROOT / "tools"))
sys.path.insert(0, str(REPO_ROOT / "research" / "work-items" / "RE-002-node115-std-census"))
from byte_progress import compare  # noqa: E402
from census import object_functions  # noqa: E402
from elf_index import sections  # noqa: E402

EXPECTED_BINARY_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
)
EXPECTED_BINARY_SIZE = 105_896_032
WINDOW_PREFIX = "node115-stream-f-w2-"

# .data.rel.ro Location anchors proving defining crates & source lines
EXPECTED_LOCATIONS = [
    (0x6442DE0, "info_server/src/abci_state_info_handler.rs", 82, 16),
    (0x6442DF8, "info_server/src/abci_state_info_handler.rs", 81, 12),
    (0x64434D0, "info_server/src/abci_state_info_handler.rs", 127, 12),
    (0x648BE28, "l1/src/evm/evm_state.rs", 183, 9),
]

# .rodata literal anchors referenced directly by RIP-relative leaq in bridge & evm FDEs
EXPECTED_RODATA = [
    (0x7D3E55, b"Locker"),
    (0x7D3E5B, b"Finalizer"),
    (0x7D247D, b"internal error: entered unreachable code"),
]

# 18 zero-dependency small FDEs (3,457 B):
#   - bridge (1 FDE / 50 B): <BridgeRole as Display>::fmt
#   - evm (1 FDE / 26 B): l1/src/evm/evm_state.rs:183:9 unreachable!()
#   - info-api (16 FDEs / 3,381 B): remaining abci_state_info_handler.rs:81-82 inner async poll FDEs
SMALL_TARGETS = [
    ("bridge", 0x457CF20, 0x457CF52, "bridge <BridgeRole as Display>::fmt (0x457cf20)"),
    ("evm", 0x4493250, 0x449326A, "evm evm_state.rs:183 unreachable stub (0x4493250)"),
    ("info-api", 0x29780E0, 0x2978192, "info-api abci_state_info_handler inner async poll (0x29780e0)"),
    ("info-api", 0x2978580, 0x2978638, "info-api abci_state_info_handler inner async poll (0x2978580)"),
    ("info-api", 0x29787E0, 0x29788F8, "info-api abci_state_info_handler inner async poll (0x29787e0)"),
    ("info-api", 0x2978B40, 0x2978C23, "info-api abci_state_info_handler inner async poll (0x2978b40)"),
    ("info-api", 0x2979280, 0x2979368, "info-api abci_state_info_handler inner async poll (0x2979280)"),
    ("info-api", 0x2979430, 0x29794F9, "info-api abci_state_info_handler inner async poll (0x2979430)"),
    ("info-api", 0x2979500, 0x29795BE, "info-api abci_state_info_handler inner async poll (0x2979500)"),
    ("info-api", 0x2979910, 0x29799CB, "info-api abci_state_info_handler inner async poll (0x2979910)"),
    ("info-api", 0x29799D0, 0x2979A79, "info-api abci_state_info_handler inner async poll (0x29799d0)"),
    ("info-api", 0x2979A80, 0x2979B3F, "info-api abci_state_info_handler inner async poll (0x2979a80)"),
    ("info-api", 0x2979B40, 0x2979C01, "info-api abci_state_info_handler inner async poll (0x2979b40)"),
    ("info-api", 0x297A050, 0x297A13D, "info-api abci_state_info_handler inner async poll (0x297a050)"),
    ("info-api", 0x297A280, 0x297A32E, "info-api abci_state_info_handler inner async poll (0x297a280)"),
    ("info-api", 0x297A4B0, 0x297A5A6, "info-api abci_state_info_handler inner async poll (0x297a4b0)"),
    ("info-api", 0x297A7D0, 0x297A8DC, "info-api abci_state_info_handler inner async poll (0x297a7d0)"),
    ("info-api", 0x297AA20, 0x297AB00, "info-api abci_state_info_handler inner async poll (0x297aa20)"),
]

# 52 ThinLTO + tikv-jemallocator outer #[async_trait] wrapper FDEs (26,358 B):
#   - info-api: info_server/src/abci_state_info_handler.rs:127:12 (Location 0x64434d0)
OUTER_TARGETS = [
    ("info-api", 0x297CC60, 0x297CE97, "info-api abci_state_info_handler outer async_trait poll (0x297cc60)"),
    ("info-api", 0x297CEA0, 0x297D062, "info-api abci_state_info_handler outer async_trait poll (0x297cea0)"),
    ("info-api", 0x297D070, 0x297D23D, "info-api abci_state_info_handler outer async_trait poll (0x297d070)"),
    ("info-api", 0x297D240, 0x297D419, "info-api abci_state_info_handler outer async_trait poll (0x297d240)"),
    ("info-api", 0x297D420, 0x297D68E, "info-api abci_state_info_handler outer async_trait poll (0x297d420)"),
    ("info-api", 0x297D690, 0x297D85A, "info-api abci_state_info_handler outer async_trait poll (0x297d690)"),
    ("info-api", 0x297D860, 0x297DAB5, "info-api abci_state_info_handler outer async_trait poll (0x297d860)"),
    ("info-api", 0x297DAC0, 0x297DC58, "info-api abci_state_info_handler outer async_trait poll (0x297dac0)"),
    ("info-api", 0x297DC60, 0x297DE0C, "info-api abci_state_info_handler outer async_trait poll (0x297dc60)"),
    ("info-api", 0x297DE10, 0x297DFE0, "info-api abci_state_info_handler outer async_trait poll (0x297de10)"),
    ("info-api", 0x297DFE0, 0x297E1A8, "info-api abci_state_info_handler outer async_trait poll (0x297dfe0)"),
    ("info-api", 0x297E1B0, 0x297E35C, "info-api abci_state_info_handler outer async_trait poll (0x297e1b0)"),
    ("info-api", 0x297E360, 0x297E5CE, "info-api abci_state_info_handler outer async_trait poll (0x297e360)"),
    ("info-api", 0x297E5D0, 0x297E83E, "info-api abci_state_info_handler outer async_trait poll (0x297e5d0)"),
    ("info-api", 0x297E840, 0x297EA4D, "info-api abci_state_info_handler outer async_trait poll (0x297e840)"),
    ("info-api", 0x297EA50, 0x297EC1D, "info-api abci_state_info_handler outer async_trait poll (0x297ea50)"),
    ("info-api", 0x297EC20, 0x297ED90, "info-api abci_state_info_handler outer async_trait poll (0x297ec20)"),
    ("info-api", 0x297ED90, 0x297EFE3, "info-api abci_state_info_handler outer async_trait poll (0x297ed90)"),
    ("info-api", 0x297EFF0, 0x297F1BD, "info-api abci_state_info_handler outer async_trait poll (0x297eff0)"),
    ("info-api", 0x297F1C0, 0x297F3A7, "info-api abci_state_info_handler outer async_trait poll (0x297f1c0)"),
    ("info-api", 0x297F3B0, 0x297F55D, "info-api abci_state_info_handler outer async_trait poll (0x297f3b0)"),
    ("info-api", 0x297F560, 0x297F70D, "info-api abci_state_info_handler outer async_trait poll (0x297f560)"),
    ("info-api", 0x297F710, 0x297F8BD, "info-api abci_state_info_handler outer async_trait poll (0x297f710)"),
    ("info-api", 0x297F8C0, 0x297FB4A, "info-api abci_state_info_handler outer async_trait poll (0x297f8c0)"),
    ("info-api", 0x297FB50, 0x297FCFC, "info-api abci_state_info_handler outer async_trait poll (0x297fb50)"),
    ("info-api", 0x297FD00, 0x297FECD, "info-api abci_state_info_handler outer async_trait poll (0x297fd00)"),
    ("info-api", 0x297FED0, 0x29800E7, "info-api abci_state_info_handler outer async_trait poll (0x297fed0)"),
    ("info-api", 0x29800F0, 0x298037A, "info-api abci_state_info_handler outer async_trait poll (0x29800f0)"),
    ("info-api", 0x2980380, 0x298052C, "info-api abci_state_info_handler outer async_trait poll (0x2980380)"),
    ("info-api", 0x2980530, 0x29806DD, "info-api abci_state_info_handler outer async_trait poll (0x2980530)"),
    ("info-api", 0x29806E0, 0x298088C, "info-api abci_state_info_handler outer async_trait poll (0x29806e0)"),
    ("info-api", 0x2980890, 0x2980A5C, "info-api abci_state_info_handler outer async_trait poll (0x2980890)"),
    ("info-api", 0x2980A60, 0x2980C5C, "info-api abci_state_info_handler outer async_trait poll (0x2980a60)"),
    ("info-api", 0x2980C60, 0x2980E20, "info-api abci_state_info_handler outer async_trait poll (0x2980c60)"),
    ("info-api", 0x2980E20, 0x2980FF3, "info-api abci_state_info_handler outer async_trait poll (0x2980e20)"),
    ("info-api", 0x2981000, 0x298121C, "info-api abci_state_info_handler outer async_trait poll (0x2981000)"),
    ("info-api", 0x2981220, 0x298148E, "info-api abci_state_info_handler outer async_trait poll (0x2981220)"),
    ("info-api", 0x2981490, 0x2981644, "info-api abci_state_info_handler outer async_trait poll (0x2981490)"),
    ("info-api", 0x2981650, 0x298181D, "info-api abci_state_info_handler outer async_trait poll (0x2981650)"),
    ("info-api", 0x2981820, 0x29819EA, "info-api abci_state_info_handler outer async_trait poll (0x2981820)"),
    ("info-api", 0x29819F0, 0x2981C7A, "info-api abci_state_info_handler outer async_trait poll (0x29819f0)"),
    ("info-api", 0x2981E20, 0x29820C6, "info-api abci_state_info_handler outer async_trait poll (0x2981e20)"),
    ("info-api", 0x29820D0, 0x298233E, "info-api abci_state_info_handler outer async_trait poll (0x29820d0)"),
    ("info-api", 0x2982340, 0x29824ED, "info-api abci_state_info_handler outer async_trait poll (0x2982340)"),
    ("info-api", 0x29824F0, 0x29826BD, "info-api abci_state_info_handler outer async_trait poll (0x29824f0)"),
    ("info-api", 0x29826C0, 0x298292E, "info-api abci_state_info_handler outer async_trait poll (0x29826c0)"),
    ("info-api", 0x2982930, 0x2982B07, "info-api abci_state_info_handler outer async_trait poll (0x2982930)"),
    ("info-api", 0x2982B10, 0x2982CBC, "info-api abci_state_info_handler outer async_trait poll (0x2982b10)"),
    ("info-api", 0x2982CC0, 0x2982F4A, "info-api abci_state_info_handler outer async_trait poll (0x2982cc0)"),
    ("info-api", 0x2982F50, 0x298311F, "info-api abci_state_info_handler outer async_trait poll (0x2982f50)"),
    ("info-api", 0x29832C0, 0x298356A, "info-api abci_state_info_handler outer async_trait poll (0x29832c0)"),
    ("info-api", 0x2983570, 0x2983799, "info-api abci_state_info_handler outer async_trait poll (0x2983570)"),
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


def verify_anchors(data: bytes) -> tuple[list[dict], list[dict]]:
    va_to_off, secs = _make_va_to_off(data)
    rela = secs[".rela.dyn"]
    relmap: dict[int, int] = {}
    for off in range(rela["offset"], rela["offset"] + rela["size"], 24):
        r_offset, _r_info, r_addend = struct.unpack_from("<QQq", data, off)
        relmap[r_offset] = r_addend

    verified_locs = []
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
        verified_locs.append({"location_va": hex(loc_va), "file": path_str, "line": line, "col": col})

    verified_rodata = []
    for va, exp_bytes in EXPECTED_RODATA:
        off = va_to_off(va)
        got = data[off : off + len(exp_bytes)]
        if got != exp_bytes:
            raise AssertionError(f".rodata {hex(va)} mismatch: got {got!r}, expected {exp_bytes!r}")
        verified_rodata.append({"va": hex(va), "text": exp_bytes.decode("utf-8")})

    return verified_locs, verified_rodata


def _assert_first_party_symbol(sym: str) -> None:
    if not any(tag in sym for tag in ("stream_f_w2_small", "mylib")):
        raise AssertionError(f"non-first-party symbol: {sym}")
    for forbidden in ("4core", "5alloc", "3std", "drop_in_place"):
        if sym.startswith(f"_ZN{forbidden}") or forbidden in sym or sym.startswith("_RNvNtC"):
            raise AssertionError(f"forbidden stdlib/drop symbol not allowed: {sym}")


def compile_small() -> tuple[list[tuple[str, bytes, list[dict]]], str]:
    ver = subprocess.check_output(["rustc", "+1.95.0", "--version"], text=True).strip()
    with tempfile.TemporaryDirectory() as td:
        obj_path = Path(td) / "stream_f_w2_small.o"
        subprocess.run(
            [
                "rustc",
                "+1.95.0",
                "--edition=2021",
                "--crate-type=bin",
                "--crate-name=stream_f_w2_small",
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
                str(SMALL_SRC_PATH),
            ],
            check=True,
        )
        compiled = []
        for syms, c_bytes, rels in object_functions(obj_path.read_bytes()):
            sym = syms[0] if syms else ""
            if (
                ("AbciStateInfoHandler" in sym and "closure" in sym)
                or "BridgeRole" in sym
                or "evm_unreachable" in sym
            ) and "drop_in_place" not in sym:
                rel_dicts = [
                    {"offset": r[0], "type": r[1], "addend": r[2], "width": 4}
                    for r in rels
                ]
                compiled.append((sym, c_bytes, rel_dicts))
        return compiled, ver


def compile_outer(target_dir: Path) -> list[tuple[str, bytes, list[dict]]]:
    rel_dir = target_dir / "release"
    deps_dir = rel_dir / "deps"
    for p in (rel_dir / "mybin", rel_dir / "mybin.d"):
        if p.exists():
            p.unlink()
    if deps_dir.exists():
        for stale in deps_dir.glob("mybin*"):
            if stale.is_file():
                stale.unlink()
    fp_dir = rel_dir / ".fingerprint"
    if fp_dir.exists():
        import shutil
        for stale_fp in fp_dir.glob("mybin-*"):
            if stale_fp.is_dir():
                shutil.rmtree(stale_fp)
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(target_dir)
    env.setdefault("CARGO_BUILD_JOBS", "4")
    subprocess.run(
        [
            "cargo",
            "+1.95.0",
            "rustc",
            "-p",
            "mybin",
            "--bin",
            "mybin",
            "--release",
            "--offline",
            "--locked",
            "--",
            "-C",
            "save-temps",
        ],
        cwd=str(HARNESS_DIR),
        env=env,
        check=True,
    )
    compiled = []
    for obj in sorted(deps_dir.glob("mybin-*.o")):
        raw = obj.read_bytes()
        if raw[:4] != b"\x7fELF":
            continue
        try:
            fns = object_functions(raw)
        except Exception:
            continue
        for syms, c_bytes, rels in fns:
            sym = syms[0] if syms else ""
            if "AbciStateInfoHandler" in sym and "closure" in sym and "drop_in_place" not in sym:
                rel_dicts = [
                    {"offset": r[0], "type": r[1], "addend": r[2], "width": 4}
                    for r in rels
                ]
                compiled.append((sym, c_bytes, rel_dicts))
    return compiled


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


def build_records(data: bytes, target_dir: Path) -> tuple[dict, bytes]:
    if len(data) != EXPECTED_BINARY_SIZE:
        raise AssertionError(f"size mismatch: {len(data)}")
    sha = hashlib.sha256(data).hexdigest()
    if sha != EXPECTED_BINARY_SHA256:
        raise AssertionError(f"sha256 mismatch: {sha}")

    va_to_off, _ = _make_va_to_off(data)
    fdes = load_fde_map()
    verified_locs, verified_rodata = verify_anchors(data)

    small_compiled, rustc_version = compile_small()
    outer_compiled = compile_outer(target_dir)

    def _index(items):
        by_len: dict[int, list[tuple[str, bytes, list[dict]]]] = {}
        for sym, cb, rd in items:
            by_len.setdefault(len(cb), []).append((sym, cb, rd))
        return by_len

    small_idx = _index(small_compiled)
    outer_idx = _index(outer_compiled)

    rows = []
    bodies = bytearray()
    tot_b = 0
    tot_raw = 0
    by_comp: dict[str, dict[str, int]] = {}

    all_targets = [
        ("small", comp, s, e, label) for comp, s, e, label in SMALL_TARGETS
    ] + [
        ("thinlto_jemalloc", comp, s, e, label) for comp, s, e, label in OUTER_TARGETS
    ]

    for build_kind, comp, s, e, label in sorted(all_targets, key=lambda x: x[2]):
        if fdes and fdes.get(s) != e:
            raise AssertionError(f"FDE mismatch at {hex(s)}: expected {hex(e)}, got {fdes.get(s)}")
        t_bytes = data[va_to_off(s) : va_to_off(e)]
        idx = small_idx if build_kind == "small" else outer_idx
        matched = None
        for sym, c_bytes, rels in idx.get(len(t_bytes), []):
            cmp_res = compare(c_bytes, t_bytes, rels)
            if cmp_res["relocation_qualified"] and not cmp_res["non_relocation_difference_offsets"]:
                matched = (sym, c_bytes, rels, cmp_res)
                break
        if matched is None:
            raise AssertionError(f"no compiled match for {hex(s)}..{hex(e)} ({e - s} B, {build_kind})")
        sym, c_bytes, rels, cmp_res = matched
        _assert_first_party_symbol(sym)
        sz = e - s
        body_off = len(bodies)
        bodies.extend(c_bytes)
        tot_b += sz
        tot_raw += cmp_res["raw_equal_bytes"]
        bc = by_comp.setdefault(comp, {"windows": 0, "bytes": 0, "raw_equal_bytes": 0})
        bc["windows"] += 1
        bc["bytes"] += sz
        bc["raw_equal_bytes"] += cmp_res["raw_equal_bytes"]
        rows.append(
            {
                "id": f"{WINDOW_PREFIX}{s:08x}",
                "component": comp,
                "attribution": "first_party_logic",
                "build_kind": build_kind,
                "symbol": sym,
                "start": hex(s),
                "end": hex(e),
                "start_va": hex(s),
                "end_va": hex(e),
                "bytes": sz,
                "label": label,
                "body_offset": body_off,
                "body_len": sz,
                "target_body_sha256": hashlib.sha256(t_bytes).hexdigest(),
                "compiled_body_sha256": hashlib.sha256(c_bytes).hexdigest(),
                "raw_equal_bytes": cmp_res["raw_equal_bytes"],
                "relocation_bytes": cmp_res["relocation_bytes"],
                "relocation_qualified": True,
                "relaxed_sites": 0,
                "relocations": rels,
            }
        )

    check_disjointness([(int(r["start"], 16), int(r["end"], 16)) for r in rows])

    bodies_bytes = bytes(bodies)
    lock_sha = hashlib.sha256((HARNESS_DIR / "Cargo.lock").read_bytes()).hexdigest()
    small_sha = hashlib.sha256(SMALL_SRC_PATH.read_bytes()).hexdigest()
    mylib_sha = hashlib.sha256((HARNESS_DIR / "mylib" / "src" / "lib.rs").read_bytes()).hexdigest()
    mybin_sha = hashlib.sha256((HARNESS_DIR / "mybin" / "src" / "main.rs").read_bytes()).hexdigest()

    doc = {
        "work_item": "RE-015-node115-stream-f-logic-wave2-byte-matches",
        "window_prefix": WINDOW_PREFIX,
        "target_path": "artifacts/node/115/hl-node",
        "target_sha256": sha,
        "rustc_version": rustc_version,
        "sources": {
            "small.rs": small_sha,
            "harness/Cargo.lock": lock_sha,
            "harness/mylib/src/lib.rs": mylib_sha,
            "harness/mybin/src/main.rs": mybin_sha,
        },
        "bodies": {
            "path": "bodies.bin",
            "bytes": len(bodies_bytes),
            "sha256": hashlib.sha256(bodies_bytes).hexdigest(),
        },
        "locations": verified_locs,
        "rodata_anchors": verified_rodata,
        "summary": {
            "windows": len(rows),
            "total_bytes": tot_b,
            "raw_equal_bytes": tot_raw,
            "relocation_qualified_windows": len(rows),
            "relaxed_sites": 0,
            "by_component": by_comp,
        },
        "windows": rows,
    }
    return doc, bodies_bytes


def verify_records(records: dict, data: bytes, bodies: bytes, rebuild: bool, target_dir: Path) -> None:
    if records.get("target_sha256") != EXPECTED_BINARY_SHA256:
        raise AssertionError("target_sha256 mismatch")
    if len(data) != EXPECTED_BINARY_SIZE or hashlib.sha256(data).hexdigest() != EXPECTED_BINARY_SHA256:
        raise AssertionError("binary authentication failed")

    # Verify source hashes & bodies.bin integrity
    exp_sources = {
        "small.rs": hashlib.sha256(SMALL_SRC_PATH.read_bytes()).hexdigest(),
        "harness/Cargo.lock": hashlib.sha256((HARNESS_DIR / "Cargo.lock").read_bytes()).hexdigest(),
        "harness/mylib/src/lib.rs": hashlib.sha256((HARNESS_DIR / "mylib" / "src" / "lib.rs").read_bytes()).hexdigest(),
        "harness/mybin/src/main.rs": hashlib.sha256((HARNESS_DIR / "mybin" / "src" / "main.rs").read_bytes()).hexdigest(),
    }
    if records.get("sources") != exp_sources:
        raise AssertionError("source sha256 map mismatch")
    binfo = records.get("bodies", {})
    if len(bodies) != binfo.get("bytes") or hashlib.sha256(bodies).hexdigest() != binfo.get("sha256"):
        raise AssertionError("bodies.bin sha256/length mismatch")

    # Verify anchors & FDEs & per-window byte comparison directly against hl-node
    va_to_off, _ = _make_va_to_off(data)
    fdes = load_fde_map()
    verified_locs, verified_rodata = verify_anchors(data)
    if records.get("locations") != verified_locs:
        raise AssertionError("locations mismatch")
    if records.get("rodata_anchors") != verified_rodata:
        raise AssertionError("rodata_anchors mismatch")

    windows = records.get("windows", [])
    if len(windows) != len(SMALL_TARGETS) + len(OUTER_TARGETS):
        raise AssertionError(f"unexpected window count: {len(windows)}")

    tot_b = 0
    tot_raw = 0
    by_comp: dict[str, dict[str, int]] = {}
    va_pairs: list[tuple[int, int]] = []

    for w in windows:
        _assert_first_party_symbol(w["symbol"])
        s = int(w["start"], 16)
        e = int(w["end"], 16)
        if w.get("start_va") != w["start"] or w.get("end_va") != w["end"]:
            raise AssertionError(f"start_va/end_va mismatch at {w['start']}")
        if e - s != w["bytes"] or w["body_len"] != w["bytes"]:
            raise AssertionError(f"byte length mismatch at {w['start']}")
        if w.get("relaxed_sites", 0) != 0:
            raise AssertionError(f"non-zero relaxed_sites at {w['start']}")
        if fdes and fdes.get(s) != e:
            raise AssertionError(f"FDE mismatch at {hex(s)}: expected {hex(e)}, got {fdes.get(s)}")

        t_bytes = data[va_to_off(s) : va_to_off(e)]
        if hashlib.sha256(t_bytes).hexdigest() != w["target_body_sha256"]:
            raise AssertionError(f"target_body_sha256 mismatch at {w['start']}")

        c_bytes = bodies[w["body_offset"] : w["body_offset"] + w["body_len"]]
        if len(c_bytes) != w["bytes"] or hashlib.sha256(c_bytes).hexdigest() != w["compiled_body_sha256"]:
            raise AssertionError(f"compiled_body_sha256 mismatch at {w['start']}")

        cmp_res = compare(c_bytes, t_bytes, w["relocations"])
        if not cmp_res["relocation_qualified"] or cmp_res["non_relocation_difference_offsets"]:
            raise AssertionError(
                f"relocation-qualified compare failed at {w['start']}: "
                f"{cmp_res['non_relocation_difference_offsets'][:8]}"
            )
        if cmp_res["raw_equal_bytes"] != w["raw_equal_bytes"]:
            raise AssertionError(f"raw_equal_bytes mismatch at {w['start']}")
        if cmp_res["relocation_bytes"] != w["relocation_bytes"]:
            raise AssertionError(f"relocation_bytes mismatch at {w['start']}")

        tot_b += w["bytes"]
        tot_raw += cmp_res["raw_equal_bytes"]
        bc = by_comp.setdefault(w["component"], {"windows": 0, "bytes": 0, "raw_equal_bytes": 0})
        bc["windows"] += 1
        bc["bytes"] += w["bytes"]
        bc["raw_equal_bytes"] += cmp_res["raw_equal_bytes"]
        va_pairs.append((s, e))

    check_disjointness(va_pairs)

    exp_summary = {
        "windows": len(windows),
        "total_bytes": tot_b,
        "raw_equal_bytes": tot_raw,
        "relocation_qualified_windows": len(windows),
        "relaxed_sites": 0,
        "by_component": by_comp,
    }
    if records.get("summary") != exp_summary:
        raise AssertionError(f"summary mismatch: {records.get('summary')} != {exp_summary}")

    if rebuild:
        fresh, fresh_bodies = build_records(data, target_dir)
        if fresh_bodies != bodies:
            raise AssertionError("rebuilt bodies.bin differs from recorded bodies.bin")
        if fresh["summary"] != records["summary"]:
            raise AssertionError("rebuilt summary mismatch")
        for fw, cw in zip(fresh["windows"], records["windows"]):
            for k in (
                "component",
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
                    raise AssertionError(f"rebuilt mismatch at {cw['start']} field {k}")


def run_negative_controls(records: dict, data: bytes, bodies: bytes, target_dir: Path) -> int:
    rejected = 0

    # 1. Tampered target_sha256
    bad1 = copy.deepcopy(records)
    bad1["target_sha256"] = "0" * 64
    try:
        verify_records(bad1, data, bodies, False, target_dir)
    except AssertionError:
        rejected += 1

    # 2. Tampered target_body_sha256 on bridge BridgeRole::fmt (0x457cf20)
    bad2 = copy.deepcopy(records)
    bad2["windows"][-1]["target_body_sha256"] = "f" * 64
    try:
        verify_records(bad2, data, bodies, False, target_dir)
    except AssertionError:
        rejected += 1

    # 3. Dropped relocation entry on first info-api window
    bad3 = copy.deepcopy(records)
    bad3["windows"][0]["relocations"] = bad3["windows"][0]["relocations"][1:]
    try:
        verify_records(bad3, data, bodies, False, target_dir)
    except AssertionError:
        rejected += 1

    # 4. Forbidden stdlib symbol attribution rejected
    bad4 = copy.deepcopy(records)
    bad4["windows"][0]["symbol"] = "_ZN4core3ptr13drop_in_place17h0000000000000000E"
    try:
        verify_records(bad4, data, bodies, False, target_dir)
    except AssertionError:
        rejected += 1

    return rejected


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--generate", action="store_true")
    ap.add_argument("--rebuild", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument(
        "--target-dir",
        type=Path,
        default=Path(os.environ.get("CARGO_TARGET_DIR", str(REPO_ROOT / "work" / "target" / "stream-f-w2"))),
    )
    args = ap.parse_args()

    data = BINARY_PATH.read_bytes()
    if args.generate:
        recs, bodies_bytes = build_records(data, args.target_dir)
        BODIES_PATH.write_bytes(bodies_bytes)
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
    bodies_bytes = BODIES_PATH.read_bytes()
    verify_records(recs, data, bodies_bytes, args.rebuild, args.target_dir)
    if args.self_test:
        rej = run_negative_controls(recs, data, bodies_bytes, args.target_dir)
        if rej != 4:
            raise AssertionError(f"expected 4 negative controls rejected, got {rej}")
        s = recs["summary"]
        bc = s["by_component"]
        print(
            f"PASS: {s['windows']}/{s['windows']} first-party Stream F logic Wave-2 FDEs relocation-qualified "
            f"({s['total_bytes']} B, {s['raw_equal_bytes']}/{s['total_bytes']} = "
            f"{100 * s['raw_equal_bytes'] / s['total_bytes']:.2f}% raw-equal; "
            f"info-api={bc['info-api']['windows']}w/{bc['info-api']['bytes']}B, "
            f"bridge={bc['bridge']['windows']}w/{bc['bridge']['bytes']}B, "
            f"evm={bc['evm']['windows']}w/{bc['evm']['bytes']}B; "
            f"4/4 Locations + 3/3 rodata verified, rebuild={args.rebuild}, 0 overlaps, 4/4 negative controls rejected)"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
