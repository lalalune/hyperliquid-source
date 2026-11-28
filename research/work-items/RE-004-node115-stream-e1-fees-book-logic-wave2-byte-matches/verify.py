#!/usr/bin/env python3
"""Compile stubs.rs + lib_pic.rs + lib_pie.rs (100% pure std, zero external deps) with rustc +1.95.0 and verify 9 pure first-party business-logic Stream E1 FDE byte matches across fees, orderbook, and assets against node #115."""

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
sys.path.insert(0, str(REPO_ROOT / "tools"))
import byte_progress  # noqa: E402

BINARY_PATH = REPO_ROOT / "artifacts" / "node" / "115" / "hl-node"
FDE_TSV = REPO_ROOT / "work" / "index" / "node-115-fde.tsv"
BYTE_WINDOWS_JSON = REPO_ROOT / "research" / "byte-windows.json"
WORK_ITEMS_DIR = REPO_ROOT / "research" / "work-items"
STUBS_SOURCE = PACKET_DIR / "stubs.rs"
PIC_SOURCE = PACKET_DIR / "lib_pic.rs"
PIE_SOURCE = PACKET_DIR / "lib_pie.rs"
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

# 9 strictly disjoint pure first-party business-logic Stream E1 FDEs (2,483 B):
# (component, pool_kind, label, start_va, size, anchor_kind, anchor_value)
TARGET_WINDOWS: list[tuple[str, str, str, int, int, str, str]] = [
    # fees: pure business logic (1 FDE = 163 B)
    ("fees", "pic_lib", "FeeTracker::subaccounts_vlm_sum", 0x294BCD0, 163, "location", "l1/src/qtys/impl_ntl.rs:682:1"),
    # orderbook: pure business logic (2 FDEs = 958 B)
    ("orderbook", "pie_lib", "Level::modify_order_sz (spot)", 0x5192060, 479, "location", "l1/src/book/level.rs:32:54"),
    ("orderbook", "pie_lib", "Level::modify_order_sz (perp)", 0x5192240, 479, "location", "l1/src/book/level.rs:32:54"),
    # assets: pure business logic (5 FDEs = 1,162 B)
    ("assets", "pic_lib", "SpotMeta::mid_px_to_f64", 0x2CAC7D0, 239, "location", "l1/src/spot_meta.rs:1055:9"),
    ("assets", "pic_lib", "SpotMeta::mid_px_to_f64", 0x56449A0, 239, "location", "l1/src/spot_meta.rs:1055:9"),
    ("assets", "pic_lib", "SpotMeta::mid_px_to_f64", 0x5644A90, 239, "location", "l1/src/spot_meta.rs:1055:9"),
    ("assets", "pic_lib", "SpotMeta::is_user_frozen", 0x3C49440, 255, "location", "l1/src/spot_meta.rs:119:33"),
    ("assets", "pic_lib", "qtys::net_balance", 0x4215880, 190, "location", "l1/src/qtys/mod.rs:847:1"),
    # risk: pure business logic (1 FDE = 200 B; l1/src/spot_clearinghouse/)
    ("risk", "pic_lib", "SpotClearinghouse::capped_usdc_ntl", 0x3BFA270, 200, "location", "l1/src/spot_meta.rs:119:33"),
]


def parse_elf_sections(obj: bytes) -> list[tuple[int, str, int, int, int, int, int, int]]:
    if len(obj) < 64 or obj[:4] != b"\x7fELF":
        return []
    e_shoff = struct.unpack_from("<Q", obj, 40)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", obj, 58)
    if e_shoff == 0 or e_shnum == 0 or e_shstrndx >= e_shnum:
        return []
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


def extract_obj_functions(obj: bytes, filter_fn) -> list[tuple[str, bytes, list[dict]]]:
    secs = parse_elf_sections(obj)
    if not secs:
        return []
    relas_by_sec: dict[int, list[dict]] = {}
    for s in secs:
        if s[2] == 4:  # SHT_RELA
            rows = []
            for o in range(s[4], s[4] + s[5], 24):
                r_off, r_info, r_addend = struct.unpack_from("<QQq", obj, o)
                rows.append(
                    {
                        "offset": int(r_off),
                        "width": 4,
                        "kind": int(r_info & 0xFFFFFFFF),
                        "addend": int(r_addend),
                    }
                )
            rows.sort(key=lambda r: r["offset"])
            relas_by_sec[s[7]] = rows
    out = []
    for idx, name, _sh_type, _sh_addr, sh_offset, sh_size, _sh_link, _sh_info in secs:
        if not name.startswith(".text.") or sh_size == 0 or not filter_fn(name):
            continue
        body = obj[sh_offset : sh_offset + sh_size]
        rels = [r for r in relas_by_sec.get(idx, []) if 0 <= r["offset"] < sh_size]
        out.append((name, body, rels))
    return out


def compile_sources() -> tuple[dict[str, list[tuple[str, bytes, list[dict]]]], str]:
    ver = subprocess.check_output(["rustc", "+1.95.0", "--version"], text=True).strip()
    pools: dict[str, list[tuple[str, bytes, list[dict]]]] = {
        "pic_lib": [],
        "pie_lib": [],
    }
    with tempfile.TemporaryDirectory(prefix="e1_s19_") as td:
        tmp = Path(td)
        stubs_rlib = tmp / "libe1_stubs.rlib"
        pic_obj = tmp / "s19_pic.o"
        pie_obj = tmp / "s19_pie.o"
        subprocess.check_call(
            [
                "rustc", "+1.95.0", "--edition=2021", "--crate-name", "e1_stubs",
                "--crate-type=rlib", "-C", "opt-level=3",
                str(STUBS_SOURCE), "-o", str(stubs_rlib),
            ],
            cwd=tmp,
        )
        subprocess.check_call(
            [
                "rustc", "+1.95.0", "--edition=2021", "--crate-name", "e1_s19_pic",
                "--crate-type=lib", "-C", "opt-level=3", "-C", "overflow-checks=yes",
                "-C", "lto=thin", "--emit=obj",
                "--extern", f"e1_stubs={stubs_rlib}", "-L", f"dependency={tmp}",
                str(PIC_SOURCE), "-o", str(pic_obj),
            ],
            cwd=tmp,
        )
        subprocess.check_call(
            [
                "rustc", "+1.95.0", "--edition=2021", "--crate-name", "e1_s19_pie",
                "--crate-type=lib", "-C", "relocation-model=pie", "-C", "opt-level=3",
                "-C", "overflow-checks=yes", "-C", "lto=thin", "--emit=obj",
                "--extern", f"e1_stubs={stubs_rlib}", "-L", f"dependency={tmp}",
                str(PIE_SOURCE), "-o", str(pie_obj),
            ],
            cwd=tmp,
        )
        pools["pic_lib"].extend(
            extract_obj_functions(pic_obj.read_bytes(), lambda n: "e1_" in n)
        )
        pools["pie_lib"].extend(
            extract_obj_functions(pie_obj.read_bytes(), lambda n: "e1_" in n)
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
                ("start_va", "size_bytes"),
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

    # 2. Consolidation-safe check against research/byte-windows.json
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

    # 3. Exhaustive sibling compiled-byte packet check across all VA key spellings
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
                    if pkt.startswith("RE-001-node115-first-party-wave") and pkt.endswith("-consolidation") and (s, e) == (bs, be):
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
            try:
                cmp_res = byte_progress.compare(cbytes, target_bytes, rels)
            except ValueError:
                continue
            if cmp_res["relocation_qualified"]:
                raw_eq = cmp_res["raw_equal_bytes"]
                if best is None or raw_eq > best[1]:
                    best = (sym, raw_eq, rels)
        if best is None:
            raise RuntimeError(f"no 0-diff compiled match for {label} @0x{start:x} ({size} B)")
        sym, raw_eq, rels = best
        windows.append(
            {
                "component": comp,
                "kind": "logic",
                "pool": pool_kind,
                "label": label,
                "start": hex(start),
                "end": hex(end),
                "size": size,
                "raw_equal_bytes": raw_eq,
                "relocations": rels,
                "relocation_offsets": [r["offset"] for r in rels],
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
        "work_item": "RE-004-node115-stream-e1-fees-book-logic-wave2-byte-matches",
        "target_binary": {
            "path": "artifacts/node/115/hl-node",
            "size": EXPECTED_BINARY_SIZE,
            "sha256": EXPECTED_BINARY_SHA256,
        },
        "compiler": {
            "rustc_version": rustc_ver,
            "flags": [
                "--edition=2021",
                "-C",
                "opt-level=3",
                "-C",
                "overflow-checks=yes",
                "-C",
                "lto=thin",
            ],
            "external_dependencies": [],
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
            "relocations",
            "relocation_offsets",
            "non_reloc_diffs",
            "anchor_kind",
            "anchor",
        ):
            if rw[key] != lw[key]:
                raise AssertionError(
                    f"window field {key} mismatch at {rw['start']}: {rw[key]} != {lw[key]}"
                )


def run_negative_controls(recorded: dict, live: dict) -> int:
    mutations = [
        ("bad_window_count", lambda r: r["summary"].update({"windows": 10})),
        ("bad_fde_size", lambda r: r["windows"][0].update({"size": 164, "end": "0x294bd74"})),
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
    bc = sm["by_component"]
    print(
        f"PASS: {sm['windows']}/{sm['windows']} relocation-qualified, "
        f"{sm['total_bytes']} B ({sm['raw_equal_bytes']} raw-equal, "
        f"fees={bc['fees']['windows']}w/{bc['fees']['bytes']}B, "
        f"orderbook={bc['orderbook']['windows']}w/{bc['orderbook']['bytes']}B, "
        f"assets={bc['assets']['windows']}w/{bc['assets']['bytes']}B, "
        f"risk={bc['risk']['windows']}w/{bc['risk']['bytes']}B), "
        f"{neg}/4 negative controls rejected"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
