#!/usr/bin/env python3
"""Compile main.rs & logic.rs with rustc +1.95.0 (-C lto=thin) and verify 13 non-visitor Stream E1 FDE byte matches against node #115."""

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
BYTE_WINDOWS_JSON = REPO_ROOT / "research" / "byte-windows.json"
WORK_ITEMS_DIR = REPO_ROOT / "research" / "work-items"
MAIN_SOURCE = PACKET_DIR / "main.rs"
LOGIC_SOURCE = PACKET_DIR / "logic.rs"
RECORDS_PATH = PACKET_DIR / "records.json"

EXPECTED_BINARY_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
)
EXPECTED_BINARY_SIZE = 105_896_032
TEXT_VA = 0x1419300
TEXT_OFF = 0x1418300
RODATA_VA = 0x430400
RODATA_OFF = 0x430400
RODATA_SZ = 0x76E640
DATA_REL_RO_VA = 0x63F2BA0
DATA_REL_RO_OFF = 0x63F0BA0
DATA_REL_RO_SZ = 0xFC000

SIBLING_PACKET_TAGS = (
    "byte-match",
    "thinlto",
    "census",
    "consolidation",
    "100pct",
    "gate-closure",
    "identity",
    "compiled",
)

# 13 strictly disjoint non-visitor first-party Stream E1 FDEs (4,246 B):
# (component, pool_kind, label, start_va, size, anchor_kind, anchor_value)
TARGET_WINDOWS: list[tuple[str, str, str, int, int, str, str]] = [
    # assets: pure business logic (11 FDEs = 2,974 B)
    ("assets", "logic_lib", "SpotMeta::set_deployer_trading_fee_share_a", 0x2C58880, 199, "rodata", "deployer trading fee share cannot be more than 100%"),
    ("assets", "logic_lib", "SpotMeta::set_deployer_trading_fee_share_a", 0x55CEC80, 199, "rodata", "deployer trading fee share cannot be more than 100%"),
    ("assets", "logic_lib", "SpotMeta::set_deployer_trading_fee_share_b", 0x55CED50, 199, "rodata", "deployer trading fee share cannot be more than 100%"),
    ("assets", "logic_bin", "SpotMeta::px_from_wire", 0x29AE8C0, 312, "location", "l1/src/spot_meta.rs:1055:9"),
    ("assets", "logic_bin", "SpotMeta::px_from_wire", 0x593D7E0, 312, "location", "l1/src/spot_meta.rs:1055:9"),
    ("assets", "logic_bin", "SpotMeta::dual_px_to_f64", 0x22F5DE0, 360, "location", "l1/src/spot_meta.rs:1055:9"),
    ("assets", "logic_bin", "SpotMeta::dual_px_to_f64", 0x50E9D40, 360, "location", "l1/src/spot_meta.rs:1055:9"),
    ("assets", "logic_bin", "SpotMeta::px_to_f64", 0x50BE9E0, 165, "location", "l1/src/spot_meta.rs:1055:9"),
    ("assets", "logic_lib", "PerpMeta::dual_px_to_f64", 0x22F5C80, 349, "location", "l1/src/perp_meta.rs:287:28"),
    ("assets", "logic_lib", "PerpMeta::dual_px_to_f64", 0x50E9BE0, 349, "location", "l1/src/perp_meta.rs:287:28"),
    ("assets", "logic_lib", "qtys::scale_nonneg_i64", 0x46A6AA0, 170, "location", "l1/src/qtys/mod.rs:847:1"),
    # orderbook: ThinLTO DebugStruct::fmt (2 FDEs = 1,272 B)
    ("orderbook", "debug_bin", "OrderCore::fmt", 0x5AA99E0, 636, "rodata", "OrderCore"),
    ("orderbook", "debug_bin", "OrderCore::fmt", 0x5AA9C60, 636, "rodata", "OrderCore"),
]


def parse_elf_sections(obj: bytes) -> list[tuple[int, str, int, int, int, int, int, int]]:
    e_shoff = struct.unpack_from("<Q", obj, 40)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", obj, 58)
    shstr_off = struct.unpack_from("<Q", obj, e_shoff + e_shstrndx * e_shentsize + 24)[0]
    out = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, _, _ = (
            struct.unpack_from("<IIQQQQIIQQ", obj, off)
        )
        end = obj.index(b"\x00", shstr_off + sh_name)
        name = obj[shstr_off + sh_name : end].decode("utf-8", "replace")
        out.append((i, name, sh_type, sh_addr, sh_offset, sh_size, sh_link, sh_info))
    return out


def extract_obj_functions(obj: bytes, filter_fn) -> list[tuple[str, bytes, list[int]]]:
    secs = parse_elf_sections(obj)
    relas_by_sec: dict[int, list[int]] = {}
    for s in secs:
        if s[2] == 4:  # SHT_RELA
            relas_by_sec[s[7]] = sorted(
                struct.unpack_from("<Q", obj, o)[0]
                for o in range(s[4], s[4] + s[5], 24)
            )
    out = []
    for idx, name, _sh_type, _sh_addr, sh_offset, sh_size, _sh_link, _sh_info in secs:
        if not name.startswith(".text.") or sh_size == 0 or not filter_fn(name):
            continue
        body = obj[sh_offset : sh_offset + sh_size]
        rels = [r for r in relas_by_sec.get(idx, []) if 0 <= r < sh_size]
        out.append((name, body, rels))
    return out


def compile_sources() -> tuple[dict[str, list[tuple[str, bytes, list[int]]]], str]:
    ver = subprocess.check_output(["rustc", "+1.95.0", "--version"], text=True).strip()
    pools: dict[str, list[tuple[str, bytes, list[int]]]] = {
        "debug_bin": [],
        "logic_bin": [],
        "logic_lib": [],
    }
    with tempfile.TemporaryDirectory(prefix="e1_thinlto_w4_") as td:
        tmp = Path(td)
        subprocess.check_call(
            [
                "rustc", "+1.95.0", "--edition=2021", "--crate-name", "e1_w4_main",
                "-C", "opt-level=3", "-C", "overflow-checks=yes", "-C", "lto=thin",
                "-C", "save-temps", str(MAIN_SOURCE), "-o", str(tmp / "e1_w4_main"),
            ],
            cwd=tmp,
        )
        for obj_path in sorted(tmp.glob("*.rcgu.o")):
            raw = obj_path.read_bytes()
            pools["debug_bin"].extend(extract_obj_functions(raw, lambda n: "Debug" in n))
            pools["logic_bin"].extend(extract_obj_functions(raw, lambda n: "e1_" in n))

        logic_obj = tmp / "e1_w4_logic.o"
        subprocess.check_call(
            [
                "rustc", "+1.95.0", "--edition=2021", "--crate-name", "e1_w4_logic",
                "--crate-type=lib", "-C", "opt-level=3", "-C", "overflow-checks=yes",
                "-C", "lto=thin", "--emit=obj", str(LOGIC_SOURCE), "-o", str(logic_obj),
            ],
            cwd=tmp,
        )
        pools["logic_lib"].extend(
            extract_obj_functions(logic_obj.read_bytes(), lambda n: "e1_" in n)
        )
    return pools, ver


def load_rela_dyn_map(binary: bytes) -> dict[int, int]:
    secs = parse_elf_sections(binary)
    rela_map: dict[int, int] = {}
    for _idx, name, _st, _addr, sh_offset, sh_size, _l, _i in secs:
        if name == ".rela.dyn":
            for o in range(sh_offset, sh_offset + sh_size, 24):
                r_offset, r_info, r_addend = struct.unpack_from("<QQq", binary, o)
                if (r_info & 0xFFFFFFFF) == 8:  # R_X86_64_RELATIVE
                    rela_map[r_offset] = r_addend
            break
    return rela_map


def verify_anchor(
    binary: bytes, rela_map: dict[int, int], start: int, size: int, anchor_kind: str, anchor_value: str
) -> None:
    tbytes = binary[TEXT_OFF + (start - TEXT_VA) : TEXT_OFF + (start - TEXT_VA) + size]
    for i in range(len(tbytes) - 7):
        if tbytes[i] in (0x48, 0x4C) and tbytes[i + 1] == 0x8D and (tbytes[i + 2] & 0xC7) == 0x05:
            disp = struct.unpack_from("<i", tbytes, i + 3)[0]
            tgt = (start + i + 7) + disp
            if anchor_kind == "rodata" and RODATA_VA <= tgt < RODATA_VA + RODATA_SZ:
                needle = anchor_value.encode("ascii")
                ro_off = RODATA_OFF + (tgt - RODATA_VA)
                if binary[ro_off : ro_off + len(needle)] == needle:
                    return
            elif anchor_kind == "location" and DATA_REL_RO_VA <= tgt < DATA_REL_RO_VA + DATA_REL_RO_SZ:
                file_va = rela_map.get(tgt)
                if file_va is not None and RODATA_VA <= file_va < RODATA_VA + RODATA_SZ:
                    slot_off = DATA_REL_RO_OFF + (tgt - DATA_REL_RO_VA)
                    _fp, flen, line, col = struct.unpack_from("<QQII", binary, slot_off)
                    if 0 < flen < 256:
                        ro_off = RODATA_OFF + (file_va - RODATA_VA)
                        loc_str = f"{binary[ro_off : ro_off + flen].decode('ascii', 'replace')}:{line}:{col}"
                        if loc_str == anchor_value:
                            return
    raise RuntimeError(f"{anchor_kind} anchor {anchor_value!r} not found in 0x{start:x}")


def load_fde_map() -> dict[int, int]:
    fdes: dict[int, int] = {}
    with FDE_TSV.open("r", encoding="utf-8") as fh:
        for line in fh:
            parts = line.strip().split("\t")
            if len(parts) >= 2 and parts[0].startswith("0x"):
                fdes[int(parts[0], 16)] = int(parts[1], 16)
    return fdes


def _to_int(val: object) -> int | None:
    if isinstance(val, int) and not isinstance(val, bool):
        return val
    if isinstance(val, str):
        s = val.strip()
        if s.startswith(("0x", "0X")):
            try:
                return int(s, 16)
            except ValueError:
                return None
        if s.isdigit():
            return int(s)
    return None


def _collect_json_intervals(obj: object, out: list[tuple[int, int]]) -> None:
    if isinstance(obj, dict):
        s: int | None = None
        e: int | None = None
        for sk, ek in (
            ("start", "end"),
            ("start_va", "end_va"),
            ("start_addr", "end_addr"),
            ("va_start", "va_end"),
            ("fde_start", "fde_end"),
        ):
            if sk in obj and ek in obj:
                s, e = _to_int(obj[sk]), _to_int(obj[ek])
                break
        if s is None:
            for sk, lk in (
                ("start", "size"),
                ("start_va", "size"),
                ("va", "size"),
                ("va", "len"),
                ("start", "length"),
                ("start_va", "bytes"),
                ("fde_start", "fde_size"),
            ):
                if sk in obj and lk in obj:
                    sv, lv = _to_int(obj[sk]), _to_int(obj[lk])
                    if sv is not None and lv is not None and sv >= TEXT_VA and 0 < lv < 0x1000000:
                        s, e = sv, sv + lv
                        break
        if s is not None and e is not None and s >= TEXT_VA and e > s and (e - s) < 0x1000000:
            out.append((s, e))
        for v in obj.values():
            _collect_json_intervals(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _collect_json_intervals(v, out)


def verify_non_overlap(records_windows: list[dict]) -> None:
    # 1. Internal strict disjointness
    intervals = sorted((int(w["start"], 16), int(w["end"], 16)) for w in records_windows)
    for (s1, e1), (s2, e2) in zip(intervals, intervals[1:]):
        if s2 < e1:
            raise RuntimeError(f"internal overlap: 0x{s1:x}..0x{e1:x} and 0x{s2:x}..0x{e2:x}")

    # 2. Wave-4 consolidation-safe check against research/byte-windows.json
    bw = json.loads(BYTE_WINDOWS_JSON.read_text(encoding="utf-8"))
    for w in bw.get("windows", []):
        bs = int(w["start"], 16) if isinstance(w["start"], str) else int(w["start"])
        be = int(w["end"], 16) if isinstance(w["end"], str) else int(w["end"])
        for s, e in intervals:
            if s < be and bs < e:
                if s == bs and e == be and "dependency" not in w and str(w.get("id", w.get("unit", ""))).startswith("node115-fp-w"):
                    continue
                raise RuntimeError(
                    f"overlap with research/byte-windows.json: 0x{s:x}..0x{e:x} vs 0x{bs:x}..0x{be:x} ({w.get('unit')})"
                )

    # 3. Exhaustive sibling compiled-byte packet check (start/end AND start_va/end_va AND va/size)
    own_name = PACKET_DIR.name
    for jpath in sorted(WORK_ITEMS_DIR.glob("*/*.json")):
        pkt = jpath.parent.name
        if pkt == own_name or not any(tag in pkt for tag in SIBLING_PACKET_TAGS):
            continue
        sib_intervals: list[tuple[int, int]] = []
        _collect_json_intervals(json.loads(jpath.read_text(encoding="utf-8")), sib_intervals)
        for bs, be in sib_intervals:
            for s, e in intervals:
                if s < be and bs < e:
                    if pkt == "RE-001-node115-first-party-wave5-consolidation" and (s, e) == (bs, be):
                        continue
                    raise RuntimeError(
                        f"overlap with sibling packet {pkt}: 0x{s:x}..0x{e:x} vs 0x{bs:x}..0x{be:x}"
                    )


def build_records() -> dict:
    binary = BINARY_PATH.read_bytes()
    actual_sha = hashlib.sha256(binary).hexdigest()
    if actual_sha != EXPECTED_BINARY_SHA256 or len(binary) != EXPECTED_BINARY_SIZE:
        raise RuntimeError("target binary sha256/size mismatch")
    fdes = load_fde_map()
    rela_map = load_rela_dyn_map(binary)
    pools, rustc_ver = compile_sources()

    windows: list[dict] = []
    for comp, pool_kind, label, start, size, anchor_kind, anchor_val in TARGET_WINDOWS:
        end = start + size
        if fdes.get(start) != end:
            raise RuntimeError(f"FDE mismatch for {label} at 0x{start:x}..0x{end:x}")
        verify_anchor(binary, rela_map, start, size, anchor_kind, anchor_val)
        target_bytes = binary[TEXT_OFF + (start - TEXT_VA) : TEXT_OFF + (end - TEXT_VA)]
        pool = pools[pool_kind]

        best = None
        for sym, cbytes, rels in pool:
            if len(cbytes) != size:
                continue
            rel_mask = bytearray(size)
            for r in rels:
                for k in range(r, min(size, r + 4)):
                    rel_mask[k] = 1
            non_reloc = [i for i in range(size) if cbytes[i] != target_bytes[i] and rel_mask[i] == 0]
            if not non_reloc:
                raw_eq = sum(1 for i in range(size) if cbytes[i] == target_bytes[i])
                if best is None or raw_eq > best[1]:
                    best = (sym, raw_eq, rels)
        if best is None:
            raise RuntimeError(f"no 0-diff compiled match for {label} @0x{start:x} ({size} B)")
        sym, raw_eq, rels = best
        windows.append(
            {
                "component": comp,
                "kind": "logic" if pool_kind.startswith("logic") else "debug",
                "pool": pool_kind,
                "label": label,
                "start": hex(start),
                "end": hex(end),
                "size": size,
                "raw_equal_bytes": raw_eq,
                "relocation_offsets": rels,
                "non_reloc_diffs": 0,
                "compiled_symbol": sym,
                "anchor_kind": anchor_kind,
                "anchor": anchor_val,
            }
        )

    verify_non_overlap(windows)
    total_bytes = sum(w["size"] for w in windows)
    total_raw = sum(w["raw_equal_bytes"] for w in windows)
    by_comp: dict[str, dict[str, int]] = {}
    for w in windows:
        c = by_comp.setdefault(w["component"], {"windows": 0, "bytes": 0, "raw_equal_bytes": 0})
        c["windows"] += 1
        c["bytes"] += w["size"]
        c["raw_equal_bytes"] += w["raw_equal_bytes"]

    return {
        "schema_version": 1,
        "work_item": "RE-004-node115-stream-e1-thinlto-logic-and-debug-byte-matches",
        "target_binary": {
            "path": "artifacts/node/115/hl-node",
            "size": EXPECTED_BINARY_SIZE,
            "sha256": EXPECTED_BINARY_SHA256,
        },
        "compiler": {
            "rustc_version": rustc_ver,
            "flags": ["--edition=2021", "-C", "opt-level=3", "-C", "overflow-checks=yes", "-C", "lto=thin"],
        },
        "summary": {
            "windows": len(windows),
            "total_bytes": total_bytes,
            "raw_equal_bytes": total_raw,
            "relocation_qualified_windows": len(windows),
            "by_component": by_comp,
        },
        "windows": windows,
    }


def verify_records_against_live(recorded: dict, live: dict) -> None:
    if recorded["target_binary"] != live["target_binary"]:
        raise AssertionError("target_binary mismatch")
    if recorded["summary"] != live["summary"]:
        raise AssertionError(f"summary mismatch: {recorded['summary']} != {live['summary']}")
    if len(recorded["windows"]) != len(live["windows"]):
        raise AssertionError("window count mismatch")
    for rw, lw in zip(recorded["windows"], live["windows"]):
        for key in (
            "component",
            "kind",
            "pool",
            "label",
            "start",
            "end",
            "size",
            "raw_equal_bytes",
            "relocation_offsets",
            "non_reloc_diffs",
            "anchor_kind",
            "anchor",
        ):
            if rw[key] != lw[key]:
                raise AssertionError(f"window field {key} mismatch at {rw['start']}: {rw[key]} != {lw[key]}")


def run_negative_controls(recorded: dict, live: dict) -> int:
    mutations = [
        ("bad_window_count", lambda r: r["summary"].update({"windows": 14})),
        ("bad_fde_size", lambda r: r["windows"][0].update({"size": 200, "end": "0x2c58948"})),
        ("bad_non_reloc_diff", lambda r: r["windows"][0].update({"non_reloc_diffs": 1})),
        ("bad_anchor", lambda r: r["windows"][0].update({"anchor": "corrupted anchor"})),
    ]
    rejected = 0
    for name, mutate in mutations:
        bad = copy.deepcopy(recorded)
        mutate(bad)
        try:
            verify_records_against_live(bad, live)
        except AssertionError:
            rejected += 1
        else:
            raise AssertionError(f"negative control {name} unexpectedly passed")
    return rejected


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    live = build_records()
    if args.write:
        RECORDS_PATH.write_text(json.dumps(live, indent=2) + "\n", encoding="utf-8")
        print(f"WROTE {RECORDS_PATH}: {live['summary']}")
        return 0

    recorded = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))
    verify_records_against_live(recorded, live)
    neg = run_negative_controls(recorded, live) if args.self_test else 0
    sm = live["summary"]
    print(
        f"PASS: {sm['windows']}/{sm['windows']} relocation-qualified, "
        f"{sm['total_bytes']} B ({sm['raw_equal_bytes']} raw-equal, "
        f"assets={sm['by_component']['assets']['windows']}w/{sm['by_component']['assets']['bytes']}B, "
        f"orderbook={sm['by_component']['orderbook']['windows']}w/{sm['by_component']['orderbook']['bytes']}B), "
        f"{neg}/4 negative controls rejected"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
