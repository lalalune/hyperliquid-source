#!/usr/bin/env python3
"""Live-compile main.rs with rustc 1.95.0 and verify 31 strictly disjoint dex-registry business-logic FDE byte matches against node #115."""

from __future__ import annotations

import argparse
import copy
import glob
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
SOURCE_PATH = PACKET_DIR / "main.rs"
RECORDS_PATH = PACKET_DIR / "records.json"

sys.path.insert(0, str(REPO_ROOT / "tools"))
import byte_progress as bp  # noqa: E402

EXPECTED_BINARY_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
EXPECTED_BINARY_SIZE = 105896032

WINDOWS = [
    ("dex-registry", "dex_perp_dexes_get_113", 0x4201750, 0x42017C1, "PerpDexes::get checked Pdi indexer (l1/src/dex_registry/perp_dex.rs:29)"),
    ("dex-registry", "dex_perp_dexes_get_113", 0x42017D0, 0x4201841, "PerpDexes::get_mut checked Pdi indexer (l1/src/dex_registry/perp_dex.rs:34)"),
    ("dex-registry", "dex_clearinghouses_get_113", 0x446B2F0, 0x446B361, "Clearinghouses::get checked Pdi indexer (l1/src/dex_registry/clearinghouses.rs:11)"),
    ("dex-registry", "dex_clearinghouses_get_113", 0x446B370, 0x446B3E1, "Clearinghouses::get checked Pdi clone (l1/src/dex_registry/clearinghouses.rs:11)"),
    ("dex-registry", "dex_clearinghouses_get_113", 0x446B3F0, 0x446B461, "Clearinghouses::get_mut checked Pdi indexer (l1/src/dex_registry/clearinghouses.rs:17)"),
    ("dex-registry", "dex_clearinghouses_by_asset_133", 0x276D060, 0x276D0E5, "Clearinghouses::get_mut by asset / 10_000 (l1/src/dex_registry/clearinghouses.rs:17)"),
    ("dex-registry", "dex_clearinghouses_by_asset_133", 0x5B00E50, 0x5B00ED5, "Clearinghouses::get by asset / 10_000 (l1/src/dex_registry/clearinghouses.rs:11)"),
    ("dex-registry", "dex_clearinghouses_by_asset_133", 0x5B00EE0, 0x5B00F65, "Clearinghouses::get_mut by asset / 10_000 clone (l1/src/dex_registry/clearinghouses.rs:17)"),
    ("dex-registry", "dex_ex_ch7c0_asset_139", 0x2753A70, 0x2753AFB, "Exchange(+0x7c8) Clearinghouses::get by asset / 10_000 (clearinghouses.rs:11)"),
    ("dex-registry", "dex_ex_ch7c0_asset_139", 0x5AED6D0, 0x5AED75B, "Exchange(+0x7c8) Clearinghouses::get by asset / 10_000 clone (clearinghouses.rs:11)"),
    ("dex-registry", "dex_ex_ch7c0_rev_139", 0x2A8B2E0, 0x2A8B36B, "Exchange(+0x7c8)::clearinghouse_by_asset (clearinghouses.rs:11)"),
    ("dex-registry", "dex_ex_ch7c0_rev_139", 0x2A8B370, 0x2A8B3FB, "Exchange(+0x7c8)::clearinghouse_mut_by_asset (clearinghouses.rs:17)"),
    ("dex-registry", "dex_ex_ch7c0_rev_139", 0x55E93A0, 0x55E942B, "Exchange(+0x7c8)::clearinghouse_by_asset clone (clearinghouses.rs:11)"),
    ("dex-registry", "dex_ex_ch1330_asset_139", 0x5AED760, 0x5AED7EB, "Exchange(+0x1338) Clearinghouses::get by asset / 10_000 (clearinghouses.rs:11)"),
    ("dex-registry", "dex_ex_ch1330_rev_139", 0x55E9310, 0x55E939B, "Exchange(+0x1338)::clearinghouse_by_asset (clearinghouses.rs:11)"),
    ("dex-registry", "dex_ex_perp4630_asset_139", 0x5AED7F0, 0x5AED87B, "Exchange(+0x4638) PerpDexes::get by asset / 10_000 (perp_dex.rs:29)"),
    ("dex-registry", "dex_ex_perp3ac0_asset_139", 0x2753B00, 0x2753B8B, "Exchange(+0x3ac8) PerpDexes::get by asset / 10_000 (perp_dex.rs:29)"),
    ("dex-registry", "dex_ex_perp3ac0_asset_139", 0x5AED880, 0x5AED90B, "Exchange(+0x3ac8) PerpDexes::get by asset / 10_000 clone (perp_dex.rs:29)"),
    ("dex-registry", "dex_ex_perp3ac0_book_get_192", 0x2753ED0, 0x2753F90, "Exchange(+0x3ac8) PerpDex::book_mut get(local).unwrap() (perp_dex.rs:34)"),
    ("dex-registry", "dex_ex_perp3ac0_book_get_192", 0x5AEDF90, 0x5AEE050, "Exchange(+0x3ac8) PerpDex::book_mut get(local).unwrap() clone (perp_dex.rs:34)"),
    ("dex-registry", "dex_ex_perp4630_book_get_192", 0x5AEE050, 0x5AEE110, "Exchange(+0x4638) PerpDex::book_mut get(local).unwrap() (perp_dex.rs:34)"),
    ("dex-registry", "dex_ex_perp3ac0_book_idx_198", 0x276E000, 0x276E0C6, "Exchange(+0x3ac8) PerpDex::books[local] (perp_dex.rs:29)"),
    ("dex-registry", "dex_ex_perp3ac0_book_idx_198", 0x5B03AE0, 0x5B03BA6, "Exchange(+0x3ac8) PerpDex::books[local] clone (perp_dex.rs:29)"),
    ("dex-registry", "dex_ex_perp4630_book_idx_198", 0x276E0D0, 0x276E196, "Exchange(+0x4638) PerpDex::books[local] (perp_dex.rs:29)"),
    ("dex-registry", "dex_ex_perp4630_book_idx_198", 0x5B03A10, 0x5B03AD6, "Exchange(+0x4638) PerpDex::books[local] clone (perp_dex.rs:29)"),
    ("dex-registry", "dex_ex_perp1fa0_book_idx_198", 0x276E1A0, 0x276E266, "Exchange(+0x1fa8) PerpDex::books[local] (perp_dex.rs:29)"),
    ("dex-registry", "dex_ex_perp3ac0_book_summary_232", 0x2753750, 0x2753838, "Exchange(+0x3ac8) PerpDex::book_summary (perp_dex.rs:29)"),
    ("dex-registry", "dex_ex_perp3ac0_book_summary_232", 0x5AED180, 0x5AED268, "Exchange(+0x3ac8) PerpDex::book_summary clone (perp_dex.rs:29)"),
    ("dex-registry", "dex_ex_perp4630_book_summary_232", 0x5AED090, 0x5AED178, "Exchange(+0x4638) PerpDex::book_summary (perp_dex.rs:29)"),
    ("dex-registry", "dex_clearinghouses_get_by_name_254", 0x446AF70, 0x446B06E, "Clearinghouses::get_by_name (l1/src/dex_registry/clearinghouses.rs:11)"),
    ("dex-registry", "dex_clearinghouses_get_by_name_254", 0x446B070, 0x446B16E, "Clearinghouses::get_mut_by_name (l1/src/dex_registry/clearinghouses.rs:17)"),
]


def parse_elf_sections(blob: bytes) -> list[tuple[int, str, int, int, int, int, int, int]]:
    e_shoff = struct.unpack_from("<Q", blob, 0x28)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", blob, 0x3A)
    shstr_off = struct.unpack_from("<Q", blob, e_shoff + e_shstrndx * e_shentsize + 24)[0]
    out = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name, sh_type, _sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info = (
            struct.unpack_from("<IIQQQQII", blob, off)
        )
        end = blob.find(b"\0", shstr_off + sh_name)
        name = blob[shstr_off + sh_name : end].decode("latin1")
        out.append((i, name, sh_type, sh_addr, sh_offset, sh_size, sh_link, sh_info))
    return out


def load_fde_map() -> dict[int, int]:
    fdes: dict[int, int] = {}
    with FDE_TSV.open("r", encoding="utf-8") as fh:
        for line in fh:
            parts = line.strip().split("\t")
            if len(parts) >= 2 and parts[0].startswith("0x"):
                fdes[int(parts[0], 16)] = int(parts[1], 16)
    return fdes


def collect_existing_ranges() -> list[tuple[int, int, str, bool]]:
    ranges: list[tuple[int, int, str, bool]] = []
    bw = json.loads(BYTE_WINDOWS_JSON.read_text(encoding="utf-8"))
    for w in bw.get("windows", []):
        s = int(w["start"], 16) if isinstance(w["start"], str) else int(w["start"])
        e = int(w["end"], 16) if isinstance(w["end"], str) else int(w["end"])
        ranges.append((s, e, "research/byte-windows.json", "dependency" not in w))

    patterns = [
        "research/work-items/*byte-matches*/records.json",
        "research/work-items/*thinlto*/records.json",
        "research/work-items/*thinlto*/census.json",
        "research/work-items/*gate-closure*/records.json",
        "research/work-items/*100pct*/records.json",
    ]
    seen_files: set[Path] = set()
    for pat in patterns:
        for p_str in glob.glob(str(REPO_ROOT / pat)):
            p = Path(p_str).resolve()
            if p == RECORDS_PATH.resolve() or p in seen_files:
                continue
            seen_files.add(p)
            try:
                doc = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                continue
            for key in ("windows", "matches", "entries", "fdes"):
                items = doc.get(key)
                if not isinstance(items, list):
                    continue
                for w in items:
                    if not isinstance(w, dict):
                        continue
                    s_raw = w.get("start") if "start" in w else w.get("start_va")
                    e_raw = w.get("end") if "end" in w else w.get("end_va")
                    if s_raw is None:
                        continue
                    s = int(s_raw, 16) if isinstance(s_raw, str) else int(s_raw)
                    if e_raw is not None:
                        e = int(e_raw, 16) if isinstance(e_raw, str) else int(e_raw)
                    elif isinstance(w.get("size"), int):
                        e = s + w["size"]
                    elif isinstance(w.get("bytes"), int):
                        e = s + w["bytes"]
                    else:
                        continue
                    ranges.append((s, e, str(p.relative_to(REPO_ROOT)), False))
    return ranges


def compile_object() -> tuple[bytes, str]:
    rustc_ver = subprocess.check_output(["rustc", "+1.95.0", "--version"], text=True).strip()
    with tempfile.TemporaryDirectory() as td:
        obj_path = Path(td) / "main.o"
        subprocess.check_call(
            [
                "rustc",
                "+1.95.0",
                "--edition=2021",
                "--crate-type=bin",
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
                str(SOURCE_PATH),
            ]
        )
        return obj_path.read_bytes(), rustc_ver


def extract_compiled_functions(obj: bytes) -> dict[str, tuple[bytes, list[dict]]]:
    secs = parse_elf_sections(obj)
    by_name = {s[1]: s for s in secs}
    sym_sec = by_name[".symtab"]
    str_sec = secs[sym_sec[6]]
    strtab = obj[str_sec[4] : str_sec[4] + str_sec[5]]

    relas: dict[int, list[tuple[int, int, int]]] = {}
    for s in secs:
        if s[2] == 4:
            rels = []
            for p in range(s[4], s[4] + s[5], 24):
                r_off, r_info, r_add = struct.unpack_from("<QQq", obj, p)
                rels.append((r_off, r_info & 0xFFFFFFFF, r_add))
            relas[s[7]] = rels

    funcs: dict[str, tuple[bytes, list[dict]]] = {}
    for p in range(sym_sec[4], sym_sec[4] + sym_sec[5], 24):
        st_name, st_info, _st_other, st_shndx, st_val, st_size = struct.unpack_from("<IBBHQQ", obj, p)
        if (st_info & 0xF) == 2 and st_size > 0 and st_shndx < len(secs):
            end = strtab.index(b"\0", st_name)
            sym_name = strtab[st_name:end].decode("ascii", errors="replace")
            sec = secs[st_shndx]
            body = obj[sec[4] + st_val : sec[4] + st_val + st_size]
            rel_rows = [
                {"offset": r_off - st_val, "width": 4, "type": r_type, "addend": r_add}
                for r_off, r_type, r_add in relas.get(st_shndx, [])
                if st_val <= r_off < st_val + st_size
            ]
            funcs[sym_name] = (body, rel_rows)
    return funcs


def build_and_verify(
    records: dict,
    bin_data: bytes,
    text_va: int,
    text_off: int,
    fdes: dict[int, int],
    funcs: dict[str, tuple[bytes, list[dict]]],
    other_ranges: list[tuple[int, int, str]],
) -> dict:
    tb = records["target_binary"]
    if len(bin_data) != tb["size"] or len(bin_data) != EXPECTED_BINARY_SIZE:
        raise AssertionError("binary size mismatch")
    if hashlib.sha256(bin_data).hexdigest() != tb["sha256"] or tb["sha256"] != EXPECTED_BINARY_SHA256:
        raise AssertionError("binary sha256 mismatch")

    seen: list[tuple[int, int]] = []
    total_bytes = 0
    total_raw_eq = 0
    for w in records["windows"]:
        s = int(w["start"], 16)
        e = int(w["end"], 16)
        sz = int(w["size"])
        if e - s != sz or fdes.get(s) != e:
            raise AssertionError(f"FDE mismatch for {w['symbol']} at 0x{s:x}")
        for os_, oe_ in seen:
            if not (e <= os_ or s >= oe_):
                raise AssertionError(f"internal overlap at 0x{s:x}")
        for os_, oe_, src, allow_exact_fp in other_ranges:
            if not (e <= os_ or s >= oe_):
                if allow_exact_fp and (s, e) == (os_, oe_):
                    continue
                raise AssertionError(f"overlap with {src} at 0x{s:x}..0x{e:x}")
        seen.append((s, e))

        cands = [k for k in funcs if w["symbol"] in k]
        if len(cands) != 1:
            raise AssertionError(f"compiled symbol lookup failed for {w['symbol']}: {cands}")
        cand_bytes, rel_rows = funcs[cands[0]]
        tgt_bytes = bin_data[text_off + (s - text_va) : text_off + (e - text_va)]
        if len(cand_bytes) != len(tgt_bytes):
            raise AssertionError(f"length mismatch for {w['symbol']} at 0x{s:x}: {len(cand_bytes)} != {len(tgt_bytes)}")
        res = bp.compare(tgt_bytes, cand_bytes, rel_rows)
        if not res["relocation_qualified"]:
            raise AssertionError(f"non-relocation diff for {w['symbol']} at 0x{s:x}: {res}")
        raw_eq = sum(1 for a, b in zip(tgt_bytes, cand_bytes) if a == b)
        if w["raw_equal_bytes"] != raw_eq or w["relocation_slots"] != len(rel_rows):
            raise AssertionError(f"recorded stats mismatch for {w['symbol']} at 0x{s:x}")
        total_bytes += sz
        total_raw_eq += raw_eq

    sm = records["summary"]
    if (
        sm["window_count"] != len(records["windows"])
        or sm["total_bytes"] != total_bytes
        or sm["raw_equal_bytes"] != total_raw_eq
    ):
        raise AssertionError("summary totals mismatch")
    return {"windows": len(records["windows"]), "bytes": total_bytes, "raw_equal": total_raw_eq}


def generate_records(
    bin_data: bytes,
    text_va: int,
    text_off: int,
    fdes: dict[int, int],
    funcs: dict[str, tuple[bytes, list[dict]]],
    rustc_ver: str,
) -> dict:
    windows = []
    total_bytes = 0
    total_raw_eq = 0
    for comp, sym, s, e, desc in WINDOWS:
        assert fdes.get(s) == e, f"FDE mismatch for 0x{s:x}..0x{e:x}"
        cands = [k for k in funcs if sym in k]
        assert len(cands) == 1, f"symbol {sym}: {cands}"
        cand_bytes, rel_rows = funcs[cands[0]]
        tgt_bytes = bin_data[text_off + (s - text_va) : text_off + (e - text_va)]
        res = bp.compare(tgt_bytes, cand_bytes, rel_rows)
        assert res["relocation_qualified"], f"failed {sym} @ 0x{s:x}: {res}"
        raw_eq = sum(1 for a, b in zip(tgt_bytes, cand_bytes) if a == b)
        windows.append(
            {
                "component": comp,
                "symbol": sym,
                "start": f"0x{s:x}",
                "end": f"0x{e:x}",
                "size": e - s,
                "raw_equal_bytes": raw_eq,
                "relocation_slots": len(rel_rows),
                "description": desc,
            }
        )
        total_bytes += e - s
        total_raw_eq += raw_eq
    return {
        "work_item": "RE-007-node115-dex-registry-logic-byte-matches",
        "component": "dex-registry",
        "compiler": rustc_ver,
        "flags": [
            "--edition=2021",
            "--crate-type=bin",
            "-C",
            "opt-level=3",
            "-C",
            "overflow-checks=yes",
            "-C",
            "relocation-model=pie",
            "-C",
            "codegen-units=1",
        ],
        "target_binary": {
            "path": "artifacts/node/115/hl-node",
            "size": len(bin_data),
            "sha256": EXPECTED_BINARY_SHA256,
        },
        "windows": windows,
        "summary": {
            "window_count": len(windows),
            "total_bytes": total_bytes,
            "raw_equal_bytes": total_raw_eq,
            "raw_equal_pct": round(100.0 * total_raw_eq / total_bytes, 2),
        },
    }


def run_negative_controls(
    records: dict,
    bin_data: bytes,
    text_va: int,
    text_off: int,
    fdes: dict[int, int],
    funcs: dict[str, tuple[bytes, list[dict]]],
    other_ranges: list[tuple[int, int, str]],
) -> int:
    mutations = [
        ("bad_sha", lambda r: r["target_binary"].update({"sha256": "0" * 64})),
        ("bad_fde_end", lambda r: r["windows"][0].update({"end": "0x42017c2", "size": 114})),
        ("dup_overlap", lambda r: r["windows"].append(copy.deepcopy(r["windows"][0]))),
        ("bad_raw_eq", lambda r: r["windows"][0].update({"raw_equal_bytes": 1})),
    ]
    rejected = 0
    for name, mutate in mutations:
        bad = copy.deepcopy(records)
        mutate(bad)
        try:
            build_and_verify(bad, bin_data, text_va, text_off, fdes, funcs, other_ranges)
        except AssertionError:
            rejected += 1
        else:
            raise AssertionError(f"negative control {name} unexpectedly passed")
    return rejected


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write-records", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    bin_data = BINARY_PATH.read_bytes()
    secs = parse_elf_sections(bin_data)
    text_sec = {s[1]: s for s in secs}[".text"]
    text_va, text_off = text_sec[3], text_sec[4]
    fdes = load_fde_map()
    obj, rustc_ver = compile_object()
    funcs = extract_compiled_functions(obj)

    if args.write_records:
        rec = generate_records(bin_data, text_va, text_off, fdes, funcs, rustc_ver)
        RECORDS_PATH.write_text(json.dumps(rec, indent=2) + "\n", encoding="utf-8")

    records = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))
    other_ranges = collect_existing_ranges()
    stats = build_and_verify(records, bin_data, text_va, text_off, fdes, funcs, other_ranges)
    neg = 0
    if args.self_test:
        neg = run_negative_controls(records, bin_data, text_va, text_off, fdes, funcs, other_ranges)
    pct = 100.0 * stats["raw_equal"] / stats["bytes"]
    print(
        f"PASS: {stats['windows']}/31 dex-registry business-logic FDEs relocation-qualified "
        f"({stats['bytes']} B, {stats['raw_equal']}/{stats['bytes']} = {pct:.2f}% raw-equal, "
        f"0 overlaps, {neg}/4 negative controls rejected)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
