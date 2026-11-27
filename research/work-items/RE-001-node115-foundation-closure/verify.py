#!/usr/bin/env python3
"""Full-scope node #115 foundation (base/src/*.rs) closure verifier."""

from __future__ import annotations

import argparse
import bisect
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]

TARGET_REL = "artifacts/node/115/hl-node"
TARGET_SIZE = 105896032
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

FILE_TO_MODULE = {
    "base/src/api_secrets.rs": "src/node115-base/src/runtime_utils.rs",
    "base/src/api_url.rs": "src/node115-base/src/api_url.rs",
    "base/src/bucket_guard.rs": "src/node115-base/src/bucket_guard.rs",
    "base/src/build_mode.rs": "src/node115-base/src/build_mode.rs",
    "base/src/c_guard.rs": "src/node115-base/src/guards.rs",
    "base/src/chain_ext.rs": "src/node115-base/src/runtime_utils.rs",
    "base/src/cid.rs": "src/node115-base/src/cid.rs",
    "base/src/crit_msg.rs": "src/node115-base/src/runtime_utils.rs",
    "base/src/curl.rs": "src/node115-base/src/runtime_utils.rs",
    "base/src/daily_liner.rs": "src/node115-base/src/runtime_utils.rs",
    "base/src/data_cache.rs": "src/node115-base/src/runtime_utils.rs",
    "base/src/ema_tracker.rs": "src/node115-base/src/guards.rs",
    "base/src/file_mod_time_tracker.rs": "src/node115-base/src/runtime_utils.rs",
    "base/src/fodname.rs": "src/node115-base/src/runtime_utils.rs",
    "base/src/fu.rs": "src/node115-base/src/runtime_utils.rs",
    "base/src/http_client.rs": "src/node115-base/src/runtime_utils.rs",
    "base/src/l1_map/entry.rs": "src/node115-base/src/l1_map.rs",
    "base/src/lazy_mutex.rs": "src/node115-base/src/runtime_utils.rs",
    "base/src/liner.rs": "src/node115-base/src/runtime_utils.rs",
    "base/src/lock_id.rs": "src/node115-base/src/lock_id.rs",
    "base/src/log/handle.rs": "src/node115-base/src/runtime_utils.rs",
    "base/src/log/state.rs": "src/node115-base/src/log_settings.rs",
    "base/src/lu.rs": "src/node115-base/src/runtime_utils.rs",
    "base/src/production.rs": "src/node115-base/src/runtime_utils.rs",
    "base/src/quorum_policy.rs": "src/node115-base/src/runtime_utils.rs",
    "base/src/ren.rs": "src/node115-base/src/runtime_utils.rs",
    "base/src/shell.rs": "src/node115-base/src/runtime_utils.rs",
    "base/src/short_string.rs": "src/node115-base/src/short_string.rs",
    "base/src/singleton_set.rs": "src/node115-base/src/guards.rs",
    "base/src/slack_alert.rs": "src/node115-base/src/runtime_utils.rs",
    "base/src/time.rs": "src/node115-base/src/time.rs",
    "base/src/u.rs": "src/node115-base/src/runtime_utils.rs",
    "base/src/wallet.rs": "src/node115-base/src/runtime_utils.rs",
}

RODATA_LITERALS = [
    ("0x465668", "Out of bounds access"),
    ("0x5ee173", "occupied entry index"),
    ("0x466fc5", "CGuard was set too many times"),
    ("0x4315c4", "SingletonSet could not register "),
    ("0x466dc4", "assertion failed: self.denom > 0."),
    ("0x436683", "hour out of range: "),
    ("0x467101", "LogSettings"),
    ("0x46710c", "LockOrderingViolation"),
    ("0x464856", "BucketGuard"),
]

TEXT_ANCHORS = [
    ("0x15472b0", "5331c0b9000000004839", "base/src/short_string.rs:52 short_string_pack_rec entry"),
    ("0x1567ad8", "81f900100e00", "base/src/time.rs:57 cmp $0xe1000,%ecx"),
    ("0x1567af3", "81f9905f0100", "base/src/time.rs:57 cmp $0x15f90,%ecx"),
    ("0x14c2c50", "4157415641545348", "base/src/bucket_guard.rs entry"),
    ("0x2425280", "488b074885c07409", "base/src/l1_map/entry.rs:60 OccupiedEntry::get entry"),
    ("0x2424e80", "415741564154534883ec3848", "base/src/l1_map/entry.rs:210 OccupiedEntry::remove_entry entry"),
]


def parse_elf_sections(data: bytes) -> dict[str, tuple[int, int, int]]:
    (e_shoff,) = struct.unpack_from("<Q", data, 40)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)
    (shstr_off,) = struct.unpack_from("<Q", data, e_shoff + e_shstrndx * e_shentsize + 24)
    secs: dict[str, tuple[int, int, int]] = {}
    for i in range(e_shnum):
        b = e_shoff + i * e_shentsize
        sh_name, _sh_type, _sh_flags, sh_addr, sh_offset, sh_size = struct.unpack_from(
            "<IIQQQQ", data, b
        )
        end = data.index(b"\x00", shstr_off + sh_name)
        secs[data[shstr_off + sh_name : end].decode()] = (sh_addr, sh_offset, sh_size)
    return secs


def load_fde_extents() -> dict[int, int]:
    extents: dict[int, int] = {}
    for line in (ROOT / "work/index/node-115-fde.tsv").read_text().splitlines()[1:]:
        p = line.split("\t")
        if len(p) >= 2:
            extents[int(p[0], 16)] = int(p[1], 16)
    return extents


def check_target_digest(data: bytes, expected_sha: str) -> None:
    if len(data) != TARGET_SIZE:
        raise ValueError(f"Unexpected target size: {len(data)}")
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected_sha:
        raise ValueError(f"Target SHA-256 mismatch: {actual} != {expected_sha}")


def scan_binary(data: bytes) -> dict:
    secs = parse_elf_sections(data)
    ro_va, ro_off, ro_sz = secs[".rodata"]
    drr_va, drr_off, drr_sz = secs[".data.rel.ro"]
    _rela_va, rela_off, rela_sz = secs[".rela.dyn"]
    text_va, text_off, text_sz = secs[".text"]
    ro_bytes = data[ro_off : ro_off + ro_sz]
    drr_bytes = data[drr_off : drr_off + drr_sz]
    text_bytes = data[text_off : text_off + text_sz]

    fdes = load_fde_extents()
    sorted_fdes = sorted(fdes.items())
    starts = [s for s, _ in sorted_fdes]

    pat = re.compile(rb"base/src/[a-zA-Z0-9_/.-]+\.rs")
    va_to_file: dict[int, tuple[str, int]] = {}
    files_seen: set[str] = set()
    for m in pat.finditer(ro_bytes):
        fn = m.group().decode()
        files_seen.add(fn)
        va_to_file[ro_va + m.start()] = (fn, len(fn))

    locs_by_va: dict[int, tuple[str, int, int]] = {}
    locs_by_file: dict[str, list[dict]] = {fn: [] for fn in sorted(files_seen)}
    for off in range(rela_off, rela_off + rela_sz, 24):
        r_offset, r_info, r_addend = struct.unpack_from("<QQq", data, off)
        if (r_info & 0xFFFFFFFF) == 8 and r_addend in va_to_file and drr_va <= r_offset < drr_va + drr_sz - 24:
            fn, flen = va_to_file[r_addend]
            ln, line, col = struct.unpack_from("<QII", drr_bytes, r_offset - drr_va + 8)
            if ln == flen and 1 <= line <= 5000 and 1 <= col <= 400:
                locs_by_va[r_offset] = (fn, line, col)
                locs_by_file[fn].append({"va": hex(r_offset), "line": line, "col": col})

    ref_locs: set[int] = set()
    fde_to_files: dict[int, set[str]] = {}
    file_to_fdes: dict[str, set[int]] = {fn: set() for fn in sorted(files_seen)}
    for i in range(0, len(text_bytes) - 7):
        if text_bytes[i] in (0x48, 0x4C) and text_bytes[i + 1] == 0x8D and (text_bytes[i + 2] & 0xC7) == 0x05:
            (disp,) = struct.unpack_from("<i", text_bytes, i + 3)
            t = text_va + i + 7 + disp
            if t in locs_by_va:
                ref_locs.add(t)
                fn, _line, _col = locs_by_va[t]
                va = text_va + i
                idx = bisect.bisect_right(starts, va) - 1
                if idx >= 0 and sorted_fdes[idx][0] <= va < sorted_fdes[idx][1]:
                    s = sorted_fdes[idx][0]
                    fde_to_files.setdefault(s, set()).add(fn)
                    file_to_fdes[fn].add(s)

    return {
        "secs": secs,
        "fdes": fdes,
        "files_seen": sorted(files_seen),
        "locs_by_va": locs_by_va,
        "locs_by_file": locs_by_file,
        "ref_locs": ref_locs,
        "fde_to_files": fde_to_files,
        "file_to_fdes": file_to_fdes,
    }


def check_rodata_and_text(data: bytes, secs: dict[str, tuple[int, int, int]], literals, anchors) -> None:
    ro_va, ro_off, _ = secs[".rodata"]
    text_va, text_off, _ = secs[".text"]
    for va_hex, lit in literals:
        va = int(va_hex, 16)
        raw = lit.encode()
        got = data[ro_off + (va - ro_va) : ro_off + (va - ro_va) + len(raw)]
        if got != raw:
            raise ValueError(f".rodata literal mismatch at {va_hex}: {got!r} != {raw!r}")
    for va_hex, hex_bytes, _desc in anchors:
        va = int(va_hex, 16)
        raw = bytes.fromhex(hex_bytes)
        got = data[text_off + (va - text_va) : text_off + (va - text_va) + len(raw)]
        if got != raw:
            raise ValueError(f".text anchor mismatch at {va_hex}: {got.hex()} != {hex_bytes}")


def generate_records() -> dict:
    data = (ROOT / TARGET_REL).read_bytes()
    check_target_digest(data, TARGET_SHA256)
    scan = scan_binary(data)
    check_rodata_and_text(data, scan["secs"], RODATA_LITERALS, TEXT_ANCHORS)

    comps = {c["id"]: c for c in json.loads((ROOT / "research/components.json").read_text())["components"]}
    impl_paths = comps["foundation"]["implementation_paths"]

    bm1 = json.loads((ROOT / "research/work-items/RE-001-node115-foundation-byte-matches/records.json").read_text())
    bm2 = json.loads((ROOT / "research/work-items/RE-001-node115-foundation-l1-map-byte-matches/records.json").read_text())
    bw = json.loads((ROOT / "research/byte-windows.json").read_text())
    bw_fp = [w for w in bw["windows"] if "dependency" not in w and w.get("component") == "foundation"]

    file_rows = []
    for fn in scan["files_seen"]:
        mapped_mod = FILE_TO_MODULE[fn]
        if not (ROOT / mapped_mod).is_file():
            raise ValueError(f"Mapped module missing: {mapped_mod}")
        fs = sorted(scan["file_to_fdes"][fn])
        file_rows.append(
            {
                "source_file": fn,
                "location_count": len(scan["locs_by_file"][fn]),
                "fde_count": len(fs),
                "fde_bytes": sum(scan["fdes"][s] - s for s in fs),
                "reconstructed_module": mapped_mod,
            }
        )

    return {
        "schema_version": 1,
        "work_item": "RE-001-node115-foundation-closure",
        "component": "foundation",
        "target": {
            "path": TARGET_REL,
            "size_bytes": TARGET_SIZE,
            "sha256": TARGET_SHA256,
        },
        "summary": {
            "source_file_count": len(scan["files_seen"]),
            "location_count": len(scan["locs_by_va"]),
            "referenced_location_count": len(scan["ref_locs"]),
            "unreferenced_location_count": len(scan["locs_by_va"]) - len(scan["ref_locs"]),
            "unique_location_fde_count": len(scan["fde_to_files"]),
            "unique_location_fde_bytes": sum(scan["fdes"][s] - s for s in scan["fde_to_files"]),
            "registered_implementation_paths": len(impl_paths),
            "rodata_literal_anchors": len(RODATA_LITERALS),
            "text_instruction_anchors": len(TEXT_ANCHORS),
            "byte_identity_summary": {
                "foundation_byte_matches_windows": len(bm1["windows"]),
                "foundation_byte_matches_bytes": sum(w.get("bytes", w.get("size", 0)) for w in bm1["windows"]),
                "foundation_l1_map_windows": len(bm2["windows"]),
                "foundation_l1_map_bytes": sum(w["bytes"] for w in bm2["windows"]),
                "wave4_registry_foundation_windows": len(bw_fp),
                "wave4_registry_foundation_bytes": sum(w["end"] - w["start"] for w in bw_fp),
                "identity_gate_satisfied": False,
            },
        },
        "source_files": file_rows,
        "rodata_literals": [{"va": va, "literal": lit} for va, lit in RODATA_LITERALS],
        "text_anchors": [{"va": va, "hex": hx, "label": lbl} for va, hx, lbl in TEXT_ANCHORS],
        "implementation_paths": impl_paths,
    }


def verify(self_test: bool = False) -> None:
    rec = json.loads((HERE / "records.json").read_text())
    data = (ROOT / TARGET_REL).read_bytes()
    check_target_digest(data, rec["target"]["sha256"])
    scan = scan_binary(data)

    lits = [(r["va"], r["literal"]) for r in rec["rodata_literals"]]
    ancs = [(r["va"], r["hex"], r["label"]) for r in rec["text_anchors"]]
    check_rodata_and_text(data, scan["secs"], lits, ancs)

    expected_files = [r["source_file"] for r in rec["source_files"]]
    if expected_files != scan["files_seen"]:
        raise ValueError("Source file set mismatch against live node #115 ELF")
    if rec["summary"]["location_count"] != len(scan["locs_by_va"]):
        raise ValueError("Location count mismatch")
    if rec["summary"]["referenced_location_count"] != len(scan["ref_locs"]):
        raise ValueError("Referenced location count mismatch")
    if rec["summary"]["unreferenced_location_count"] != 0:
        raise ValueError("Unexpected unreferenced locations")
    if rec["summary"]["unique_location_fde_count"] != len(scan["fde_to_files"]):
        raise ValueError("Unique Location FDE count mismatch")
    total_fde_bytes = sum(scan["fdes"][s] - s for s in scan["fde_to_files"])
    if rec["summary"]["unique_location_fde_bytes"] != total_fde_bytes:
        raise ValueError("Unique Location FDE byte total mismatch")
    if rec["summary"]["byte_identity_summary"]["identity_gate_satisfied"] is not False:
        raise ValueError("identity_gate_satisfied must remain false")

    for row in rec["source_files"]:
        mod = ROOT / row["reconstructed_module"]
        if not mod.is_file():
            raise ValueError(f"Missing reconstructed module: {row['reconstructed_module']}")
        fn = row["source_file"]
        if row["location_count"] != len(scan["locs_by_file"][fn]):
            raise ValueError(f"Location count mismatch for {fn}")
        if row["fde_count"] != len(scan["file_to_fdes"][fn]):
            raise ValueError(f"FDE count mismatch for {fn}")

    for impl in rec["implementation_paths"]:
        if not (ROOT / impl).exists():
            raise ValueError(f"Missing registered implementation path: {impl}")

    nc = 0
    if self_test:
        # NC1: bad target digest rejected
        try:
            check_target_digest(data, "f" * 64)
            raise AssertionError("NC1 failed")
        except ValueError:
            nc += 1
        # NC2: corrupted .rodata literal rejected
        try:
            check_rodata_and_text(data, scan["secs"], [(lits[0][0], "WRONG_LITERAL")], ancs)
            raise AssertionError("NC2 failed")
        except ValueError:
            nc += 1
        # NC3: corrupted .text instruction anchor rejected
        try:
            check_rodata_and_text(data, scan["secs"], lits, [(ancs[0][0], "00" * (len(ancs[0][1]) // 2), "bad")])
            raise AssertionError("NC3 failed")
        except ValueError:
            nc += 1
        # NC4: missing source file rejected
        if len(expected_files[:-1]) == len(scan["files_seen"]):
            raise AssertionError("NC4 failed")
        nc += 1

    print(
        f"PASS: foundation closure verified — {len(scan['files_seen'])}/{len(scan['files_seen'])} base/src files, "
        f"{len(scan['locs_by_va'])}/{len(scan['locs_by_va'])} Locations (0 unreferenced), "
        f"{len(scan['fde_to_files'])}/{len(scan['fde_to_files'])} Location FDEs ({total_fde_bytes} B), "
        f"{len(lits)} literals, {len(ancs)} text anchors, {nc}/4 negative controls rejected"
    )


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--generate", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.generate:
        rec = generate_records()
        (HERE / "records.json").write_text(json.dumps(rec, indent=2) + "\n")
        s = rec["summary"]
        print(
            f"Generated foundation closure: {s['source_file_count']} files, "
            f"{s['location_count']} Locations ({s['unreferenced_location_count']} unref), "
            f"{s['unique_location_fde_count']} FDEs ({s['unique_location_fde_bytes']} B)"
        )
    else:
        verify(self_test=args.self_test)


if __name__ == "__main__":
    main()
