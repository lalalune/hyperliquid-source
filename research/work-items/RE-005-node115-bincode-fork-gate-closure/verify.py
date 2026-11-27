#!/usr/bin/env python3
"""Verify node #115 serialization (z_forks/bincode-fork) gate-closure evidence and 8 FDE byte matches."""

from __future__ import annotations

import argparse
import bisect
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

# Complete 19-FDE classification of the z_forks/bincode-fork CGU (0x1607c70..0x1609aaa, 7,684 B)
CGU_INVENTORY = [
    (0x1607c70, 0x1607e03, "inlined_core_fmt", "<&u8 as Debug>::fmt (core::fmt::num inlined, vtable 0x6403300)"),
    (0x1607e10, 0x1607fb5, "inlined_core_fmt", "<&usize as Debug>::fmt (core::fmt::num inlined, vtable 0x6403160/0x64032c0)"),
    (0x1607fc0, 0x1608165, "inlined_core_fmt", "<&u64 as Debug>::fmt (core::fmt::num inlined, vtable 0x64031e0)"),
    (0x1608170, 0x1608313, "inlined_core_fmt", "<&u32 as Debug>::fmt (core::fmt::num inlined, vtable 0x64031c0)"),
    (0x1608320, 0x1608333, "matched_here", "<&&str as Debug>::fmt forwarder (vtable 0x64032a0 -> GOT 0x64df700 -> 0x1689750)"),
    (0x1608340, 0x1608666, "inlined_core_fmt", "<[u8; 4] as Debug>::fmt (core::fmt::builders inlined)"),
    (0x1608670, 0x16087a0, "inlined_core_fmt", "<u8 as Debug>::fmt (core::fmt::num inlined)"),
    (0x16087a0, 0x16090ed, "inlined_core_fmt", "<DecodeError as Debug>::fmt (18-variant jump table 0x46a86c, core::fmt::builders inlined)"),
    (0x16090f0, 0x16090f9, "matched_here", "<&std::io::Error as Debug>::fmt forwarder (vtable 0x64031a0 -> GOT 0x64e1598 -> 0x16892a0)"),
    (0x1609100, 0x1609301, "inlined_core_fmt", "<AllowedEnumVariants as Debug>::fmt (vtable 0x6403260, core::fmt::builders inlined)"),
    (0x1609310, 0x1609323, "matched_here", "<&str as Debug>::fmt forwarder (vtable 0x6403240 -> GOT 0x64df700 -> 0x1689750)"),
    (0x1609330, 0x160948a, "inlined_core_fmt", "<Option<u8> as Debug>::fmt (vtable 0x6403180, core::fmt::builders inlined)"),
    (0x1609490, 0x1609635, "inlined_core_fmt", "<&i64 as Debug>::fmt (core::fmt::num inlined)"),
    (0x1609640, 0x1609842, "inlined_core_fmt", "<&[u32] as Debug>::fmt (core::fmt::builders inlined)"),
    (0x1609850, 0x160992d, "inlined_core_fmt", "<core::str::Utf8Error as Debug>::fmt (vtable 0x6403280, core::fmt::builders inlined)"),
    (0x1609930, 0x160995f, "matched_existing_stream_c", "<&IntegerType as Debug>::fmt (already in RE-012-node115-stream-c-byte-matches)"),
    (0x1609960, 0x1609a31, "sdallocx_drop_glue", "drop_in_place::<std::io::Error> (vtable 0x64032c8, jemalloc sdallocx 0x64df4a0 -> 0x635de30)"),
    (0x1609a40, 0x1609a6c, "matched_existing_stream_c", "<IntegerType as Debug>::fmt (already in RE-012-node115-stream-c-byte-matches)"),
    (0x1609a70, 0x1609aaa, "matched_here", "<DecodeError as Display>::fmt (vtable 0x64e1940, write!(f, \"{self:?}\") -> 0x16087a0)"),
]


def load_fde_map() -> tuple[dict[int, int], list[tuple[int, int]]]:
    fdes: dict[int, int] = {}
    ordered: list[tuple[int, int]] = []
    if not FDE_TSV.exists():
        raise AssertionError(f"Missing FDE index: {FDE_TSV}")
    with FDE_TSV.open("r", encoding="utf-8") as fh:
        fh.readline()
        for line in fh:
            parts = line.strip().split("\t")
            if len(parts) >= 2:
                s = int(parts[0], 16) if parts[0].startswith("0x") else int(parts[0])
                e = int(parts[1], 16) if parts[1].startswith("0x") else int(parts[1])
                fdes[s] = e
                ordered.append((s, e))
    ordered.sort()
    return fdes, ordered


def compile_object() -> tuple[bytes, str]:
    ver = subprocess.check_output(["rustc", "+1.95.0", "--version"], text=True).strip()
    with tempfile.TemporaryDirectory() as td:
        obj = Path(td) / "bincode_fork_gate_closure.o"
        subprocess.run(
            [
                "rustc",
                "+1.95.0",
                "--edition=2021",
                "--crate-type=rlib",
                "--crate-name=node115_bincode_fork_gate_closure",
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


def verify_static_anchors(data: bytes, rec: dict, fdes: dict[int, int], ordered_fdes: list[tuple[int, int]]) -> dict:
    secs, va_to_off = _make_va_to_off(data)
    rel_map = _read_rela_relative_map(data, secs)

    # 1. Verify all 19 CGU FDE extents and total byte count
    cgu_bytes = 0
    for s, e, kind, _ in CGU_INVENTORY:
        if fdes.get(s) != e:
            raise AssertionError(f"CGU FDE mismatch at {hex(s)}: expected {hex(e)}, got {hex(fdes.get(s, 0))}")
        cgu_bytes += e - s
    if len(CGU_INVENTORY) != rec["cgu_summary"]["total_fdes"] or cgu_bytes != rec["cgu_summary"]["total_bytes"]:
        raise AssertionError("CGU summary count/bytes mismatch")

    # Verify vtable entries in .data.rel.ro 0x6403160..0x6403308 and 0x64e1940
    expected_vtables = {
        0x6403160: 0x1607e10,
        0x6403180: 0x1609330,
        0x64031a0: 0x16090f0,
        0x64031c0: 0x1608170,
        0x64031e0: 0x1607fc0,
        0x6403200: 0x1609a40,
        0x6403220: 0x1609930,
        0x6403240: 0x1609310,
        0x6403260: 0x1609100,
        0x6403280: 0x1609850,
        0x64032a0: 0x1608320,
        0x64032c0: 0x1607e10,
        0x64032c8: 0x1609960,
        0x6403300: 0x1607c70,
        0x64e1940: 0x1609a70,
    }
    for vt_va, fn_va in expected_vtables.items():
        if rel_map.get(vt_va) != fn_va:
            raise AssertionError(f"Vtable {hex(vt_va)} expected {hex(fn_va)}, got {hex(rel_map.get(vt_va, 0))}")

    # Verify GOT entries referenced by matched windows & sdallocx classification
    expected_gots = {
        0x64e7f78: 0x5822700,  # cold_invalid_int
        0x64df6f0: 0x1680500,  # core::fmt::write
        0x64df700: 0x1689750,  # <str as Debug>::fmt
        0x64e1598: 0x16892a0,  # <String as Debug>::fmt
        0x64df4a0: 0x635de30,  # jemalloc sdallocx
    }
    for got_va, tgt_va in expected_gots.items():
        if rel_map.get(got_va) != tgt_va:
            raise AssertionError(f"GOT {hex(got_va)} expected {hex(tgt_va)}, got {hex(rel_map.get(got_va, 0))}")

    # 2. Verify all 4 z_forks/bincode-fork .rodata paths and all 13 Location structs in .data.rel.ro
    drr = secs[".data.rel.ro"]
    loc_to_path: dict[int, str] = {}
    for sp in rec["location_audit"]["source_paths"]:
        p_va = int(sp["va"], 16)
        p_bytes = sp["path"].encode("ascii")
        off = va_to_off(p_va)
        if data[off : off + len(p_bytes)] != p_bytes:
            raise AssertionError(f"Path string mismatch at {sp['va']}: expected {sp['path']}")
        for loc_hex in sp["location_vas"]:
            l_va = int(loc_hex, 16)
            if rel_map.get(l_va) != p_va:
                raise AssertionError(f"Location {loc_hex} does not point to {sp['va']}")
            l_off = drr["offset"] + (l_va - drr["address"])
            length, line, col = struct.unpack_from("<QII", data, l_off + 8)
            if (length, line, col) != (len(p_bytes), sp["line"], sp["col"]):
                raise AssertionError(f"Location {loc_hex} metadata mismatch: {(length, line, col)}")
            loc_to_path[l_va] = sp["path"]

    # 3. Verify all 100 unique .text FDE call sites referencing those 13 Location structs
    text_sec = secs[".text"]
    text_va = text_sec["address"]
    text_bytes = data[text_sec["offset"] : text_sec["offset"] + text_sec["size"]]
    fde_starts = [s for s, _ in ordered_fdes]
    hits_by_path: dict[str, set[int]] = {}
    all_unique_fdes: set[int] = set()
    loc_set = set(loc_to_path.keys())
    for i in range(len(text_bytes) - 7):
        b0 = text_bytes[i]
        if (b0 == 0x48 or b0 == 0x4C) and text_bytes[i + 1] == 0x8D and (text_bytes[i + 2] & 0xC7) == 0x05:
            disp = struct.unpack_from("<i", text_bytes, i + 3)[0]
            va = text_va + i
            tgt = va + 7 + disp
            if tgt in loc_set:
                idx = bisect.bisect_right(fde_starts, va) - 1
                if idx >= 0:
                    fs, fe = ordered_fdes[idx]
                    if fs <= va < fe:
                        hits_by_path.setdefault(loc_to_path[tgt], set()).add(fs)
                        all_unique_fdes.add(fs)

    for sp in rec["location_audit"]["source_paths"]:
        got_cnt = len(hits_by_path.get(sp["path"], set()))
        if got_cnt != sp["call_site_fdes"]:
            raise AssertionError(f"Call-site FDE count mismatch for {sp['path']}: got {got_cnt}, expected {sp['call_site_fdes']}")
    if len(all_unique_fdes) != rec["location_audit"]["total_unique_call_site_fdes"]:
        raise AssertionError(
            f"Total unique call-site FDE count mismatch: got {len(all_unique_fdes)}, expected {rec['location_audit']['total_unique_call_site_fdes']}"
        )

    return {
        "cgu_fdes": len(CGU_INVENTORY),
        "cgu_bytes": cgu_bytes,
        "location_structs": len(loc_to_path),
        "unique_call_site_fdes": len(all_unique_fdes),
    }


def check_disjointness(
    windows: list[dict],
    byte_windows_data: dict | None = None,
    peer_records: list[tuple[str, int, int]] | None = None,
) -> None:
    seen: list[tuple[int, int, str]] = []
    for w in windows:
        s = int(w["start_va"], 16)
        e = int(w["end_va"], 16)
        if e - s != w["size_bytes"]:
            raise AssertionError(f"Window {w['id']} size mismatch")
        for ps, pe, pid in seen:
            if s < pe and ps < e:
                raise AssertionError(f"Internal overlap between {w['id']} and {pid}")
        seen.append((s, e, w["id"]))

    if byte_windows_data is None:
        bw_path = REPO_ROOT / "research" / "byte-windows.json"
        if bw_path.exists():
            byte_windows_data = json.loads(bw_path.read_text(encoding="utf-8"))

    if byte_windows_data is not None:
        for bw in byte_windows_data.get("windows", []):
            es = bw["start"] if isinstance(bw["start"], int) else int(bw["start"], 16)
            ee = bw["end"] if isinstance(bw["end"], int) else int(bw["end"], 16)
            is_dep = bool(bw.get("dependency"))
            for s, e, wid in seen:
                if s < ee and es < e:
                    if is_dep:
                        raise AssertionError(f"Window {wid} overlaps dependency window {bw.get('id')}")
                    if (s, e) != (es, ee):
                        raise AssertionError(f"Window {wid} partially overlaps first-party window {bw.get('id')}")

    if peer_records is None:
        peer_records = []
        wi_root = REPO_ROOT / "research" / "work-items"
        for rp in sorted(wi_root.glob("*-byte-matches*/records.json")) + sorted(wi_root.glob("*-gate-closure*/records.json")):
            if rp.resolve() == RECORDS_PATH.resolve():
                continue
            pr = json.loads(rp.read_text(encoding="utf-8"))
            for pw in pr.get("windows", []):
                raw_s = pw.get("start_va", pw.get("start"))
                if raw_s is None:
                    continue
                ps = raw_s if isinstance(raw_s, int) else int(raw_s, 16)
                raw_e = pw.get("end_va", pw.get("end"))
                if raw_e is not None:
                    pe = raw_e if isinstance(raw_e, int) else int(raw_e, 16)
                else:
                    pe = ps + pw.get("size_bytes", pw.get("size", 0))
                peer_records.append((rp.parent.name, ps, pe))

    for pname, ps, pe in peer_records:
        for s, e, wid in seen:
            if s < pe and ps < e:
                raise AssertionError(f"Window {wid} overlaps peer packet {pname} ({hex(ps)}..{hex(pe)})")


def verify_compiled_windows(data: bytes, rec: dict, fdes: dict[int, int], obj_bytes: bytes) -> dict:
    secs = {s["name"]: s for s in sections(data)}
    text_sec = secs[".text"]
    compiled = list(object_functions(obj_bytes))

    def find_symbol(tokens: list[str]):
        matches = [
            (syms, body, rels)
            for syms, body, rels in compiled
            if all(tok in syms[0] for tok in tokens)
        ]
        if len(matches) != 1:
            raise AssertionError(f"Expected 1 compiled symbol for {tokens}, found {len(matches)}: {[m[0][0] for m in matches]}")
        return matches[0]

    total_bytes = 0
    total_raw = 0
    results = []
    for w in rec["windows"]:
        s = int(w["start_va"], 16)
        e = int(w["end_va"], 16)
        if fdes.get(s) != e:
            raise AssertionError(f"Window {w['id']} FDE mismatch: expected {hex(e)}, got {hex(fdes.get(s, 0))}")
        syms, body, rels = find_symbol(w["symbol_tokens"])
        target = data[text_sec["offset"] + (s - text_sec["address"]) : text_sec["offset"] + (e - text_sec["address"])]
        if len(body) != len(target):
            raise AssertionError(f"Window {w['id']} size mismatch: built={len(body)} vs target={len(target)}")
        rel_rows = [{"offset": r[0], "width": 4, "kind": r[1], "addend": r[2]} for r in rels]
        cmp = compare(body, target, rel_rows)
        if not cmp["relocation_qualified"]:
            raise AssertionError(f"Window {w['id']} failed rel-qual match: diffs={cmp['non_relocation_difference_offsets']}")
        total_bytes += cmp["bytes"]
        total_raw += cmp["raw_equal_bytes"]
        results.append({
            "id": w["id"],
            "symbol": syms[0],
            "bytes": cmp["bytes"],
            "raw_equal_bytes": cmp["raw_equal_bytes"],
            "relocations": len(rel_rows),
        })

    return {
        "matched_windows": len(results),
        "total_bytes": total_bytes,
        "total_raw_equal_bytes": total_raw,
        "windows": results,
    }


def run_negative_controls(data: bytes, rec: dict, fdes: dict[int, int], obj_bytes: bytes) -> int:
    # 1. Single-byte mutation in target window must be rejected
    bad_data = bytearray(data)
    secs = {s["name"]: s for s in sections(data)}
    t_off = secs[".text"]["offset"] + (0x5822490 - secs[".text"]["address"])
    bad_data[t_off] ^= 0xFF
    try:
        verify_compiled_windows(bytes(bad_data), rec, fdes, obj_bytes)
        raise AssertionError("Negative control 1 failed: mutated byte was not rejected")
    except AssertionError as exc:
        if "Negative control 1 failed" in str(exc):
            raise

    # 2. Wrong FDE end must be rejected
    bad_rec = copy.deepcopy(rec)
    bad_rec["windows"][0]["end_va"] = hex(int(bad_rec["windows"][0]["end_va"], 16) - 1)
    try:
        verify_compiled_windows(data, bad_rec, fdes, obj_bytes)
        raise AssertionError("Negative control 2 failed: wrong FDE extent was not rejected")
    except AssertionError as exc:
        if "Negative control 2 failed" in str(exc):
            raise

    # 3. Dependency overlap must be rejected
    dep_bw = {"windows": [{"id": "fake-dep", "start": 0x5822490, "end": 0x58225b5, "dependency": "fake"}]}
    try:
        check_disjointness(rec["windows"], byte_windows_data=dep_bw, peer_records=[])
        raise AssertionError("Negative control 3 failed: dependency overlap was not rejected")
    except AssertionError as exc:
        if "Negative control 3 failed" in str(exc):
            raise

    # 4. Partial overlap with first-party window must be rejected
    partial_bw = {"windows": [{"id": "fake-partial", "start": 0x5822490, "end": 0x58224a0, "dependency": None}]}
    try:
        check_disjointness(rec["windows"], byte_windows_data=partial_bw, peer_records=[])
        raise AssertionError("Negative control 4 failed: partial overlap was not rejected")
    except AssertionError as exc:
        if "Negative control 4 failed" in str(exc):
            raise

    return 4


def verify_all(self_test: bool = False) -> dict:
    data = BINARY_PATH.read_bytes()
    if len(data) != EXPECTED_BINARY_SIZE:
        raise AssertionError(f"Binary size mismatch: {len(data)}")
    sha = hashlib.sha256(data).hexdigest()
    if sha != EXPECTED_BINARY_SHA256:
        raise AssertionError(f"Binary SHA-256 mismatch: {sha}")

    rec = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))
    fdes, ordered_fdes = load_fde_map()
    static_res = verify_static_anchors(data, rec, fdes, ordered_fdes)
    check_disjointness(rec["windows"])
    obj_bytes, rustc_ver = compile_object()
    compiled_res = verify_compiled_windows(data, rec, fdes, obj_bytes)
    neg_controls = run_negative_controls(data, rec, fdes, obj_bytes) if self_test else 0
    return {
        "rustc_version": rustc_ver,
        "static": static_res,
        "compiled": compiled_res,
        "negative_controls_rejected": neg_controls,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    summary = verify_all(self_test=args.self_test)
    c = summary["compiled"]
    s = summary["static"]
    print(
        f"PASS: {c['matched_windows']}/8 rel-qual bincode-fork windows "
        f"({c['total_bytes']} B, {c['total_raw_equal_bytes']}/{c['total_bytes']} raw-equal), "
        f"{s['cgu_fdes']} CGU FDEs ({s['cgu_bytes']} B) classified, "
        f"{s['location_structs']} Locations / {s['unique_call_site_fdes']} call-site FDEs verified, "
        f"{summary['negative_controls_rejected']}/4 negative controls rejected "
        f"[{summary['rustc_version']}]"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
