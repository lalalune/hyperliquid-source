#!/usr/bin/env python3
"""Compile lib.rs with rustc 1.95.0 and verify 16 non-visitor business-logic Stream E2 FDE byte matches against node #115."""

from __future__ import annotations

import argparse
import copy
import glob
import hashlib
import json
import struct
import subprocess
import tempfile
from pathlib import Path

PACKET_DIR = Path(__file__).resolve().parent
REPO_ROOT = PACKET_DIR.parents[2]
BINARY_PATH = REPO_ROOT / "artifacts" / "node" / "115" / "hl-node"
FDE_TSV = REPO_ROOT / "work" / "index" / "node-115-fde.tsv"
BYTE_WINDOWS_JSON = REPO_ROOT / "research" / "byte-windows.json"
SOURCE_PATH = PACKET_DIR / "lib.rs"
RECORDS_PATH = PACKET_DIR / "records.json"

EXPECTED_BINARY_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
EXPECTED_BINARY_SIZE = 105896032

WINDOWS = [
    ("exchange", "exchange_bole_reserve_utilization_bps", 0x36A08B0, 0x36A09E8, "exchange BoleReserve::utilization_bps fixed-point u128 (0x36a08b0)"),
    ("exchange", "exchange_bole_reserve_utilization_f64", 0x36A09F0, 0x36A0B25, "exchange BoleReserve::utilization_f64 fixed-point u128 (0x36a09f0)"),
    ("action-wire", "action_wire_order_kind_22_visit_str", 0x25D03A0, 0x25D05EB, "action-wire OrderKind 22-alias JSON visit_str (0x25d03a0)"),
    ("action-wire", "action_wire_order_kind_22_visit_str", 0x4450A20, 0x4450C6B, "action-wire OrderKind 22-alias JSON visit_str (0x4450a20)"),
    ("exchange", "exchange_compact_18_visit_str", 0x286D0C0, 0x286D2A0, "exchange 18-variant compact state/ADL/PM JSON visit_str (0x286d0c0)"),
    ("exchange", "exchange_compact_18_visit_str", 0x4682FD0, 0x46831B0, "exchange 18-variant compact state/ADL/PM JSON visit_str (0x4682fd0)"),
    ("exchange", "exchange_user_abstraction_11_visit_str", 0x23C5330, 0x23C544D, "exchange UserAbstraction 11-alias JSON visit_str (0x23c5330)"),
    ("exchange", "exchange_user_abstraction_11_visit_str", 0x3BDD050, 0x3BDD16D, "exchange UserAbstraction 11-alias JSON visit_str (0x3bdd050)"),
    ("l1-shared", "l1_shared_node_role_4_visit_str", 0x1543CE0, 0x1543DCA, "l1-shared NodeRole 4-variant JSON visit_str (0x1543ce0)"),
    ("l1-shared", "l1_shared_node_role_4_visit_str", 0x57C3C90, 0x57C3D7A, "l1-shared NodeRole 4-variant JSON visit_str (0x57c3c90)"),
    ("l1-shared", "l1_shared_node_role_fmt_display", 0x1553730, 0x155379A, "l1-shared NodeRole::fmt Display (0x1553730)"),
    ("exchange", "exchange_bole_reserve_9_visit_str", 0x288F7F0, 0x288F8B5, "exchange BoleReserve 9-field compact JSON visit_str (0x288f7f0)"),
    ("exchange", "exchange_bole_reserve_9_visit_str", 0x4699090, 0x4699155, "exchange BoleReserve 9-field compact JSON visit_str (0x4699090)"),
    ("risk", "risk_compact_9_visit_str", 0x2886380, 0x2886409, "risk Clearinghouse/Bole 9-tag compact JSON visit_str (0x2886380)"),
    ("risk", "risk_compact_9_visit_str", 0x4693600, 0x4693689, "risk Clearinghouse/Bole 9-tag compact JSON visit_str (0x4693600)"),
    ("risk", "risk_oracle_kind_fmt_display", 0x3D66320, 0x3D6636E, "risk OracleKind::fmt Display (0x3d66320)"),
]


def parse_elf_sections(blob: bytes) -> list[tuple[int, str, int, int, int, int, int, int]]:
    e_shoff = struct.unpack_from("<Q", blob, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", blob, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", blob, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", blob, 0x3E)[0]
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
        fh.readline()
        for line in fh:
            parts = line.strip().split("\t")
            if len(parts) >= 2:
                s = int(parts[0], 16) if parts[0].startswith("0x") else int(parts[0])
                e = int(parts[1], 16) if parts[1].startswith("0x") else int(parts[1])
                fdes[s] = e
    return fdes


def compile_object() -> tuple[bytes, str]:
    rustc_ver = subprocess.check_output(["rustc", "+1.95.0", "--version"], text=True).strip()
    with tempfile.TemporaryDirectory() as td:
        obj_path = Path(td) / "stream_e2_logic_byte_matches.o"
        subprocess.check_call(
            [
                "rustc",
                "+1.95.0",
                "--edition=2021",
                "--crate-type=rlib",
                "--crate-name=node115_stream_e2_logic_byte_matches",
                "-C",
                "opt-level=3",
                "-C",
                "overflow-checks=yes",
                "--emit=obj",
                "-o",
                str(obj_path),
                str(SOURCE_PATH),
            ]
        )
        return obj_path.read_bytes(), rustc_ver


def extract_compiled_funcs(obj_bytes: bytes) -> dict[str, tuple[bytes, list[int]]]:
    secs = parse_elf_sections(obj_bytes)
    rel_by_sec: dict[int, list[int]] = {}
    for _i, _name, st, _addr, soff, ssz, _link, sinfo in secs:
        if st == 4:
            offs = []
            for j in range(0, ssz, 24):
                r_off = struct.unpack_from("<Q", obj_bytes, soff + j)[0]
                offs.append(r_off)
            rel_by_sec[sinfo] = offs
    funcs: dict[str, tuple[bytes, list[int]]] = {}
    for i, name, st, _addr, soff, ssz, _link, _sinfo in secs:
        if st == 1 and name.startswith(".text."):
            funcs[name] = (obj_bytes[soff : soff + ssz], rel_by_sec.get(i, []))
    return funcs


def check_disjointness(rows: list[dict]) -> None:
    # 1. Internal disjointness
    intervals = sorted((int(r["start_va"], 16), int(r["end_va"], 16), r["symbol"]) for r in rows)
    for (s1, e1, n1), (s2, e2, n2) in zip(intervals, intervals[1:]):
        if s2 < e1:
            raise AssertionError(f"Internal overlap: {n1} {hex(s1)}..{hex(e1)} vs {n2} {hex(s2)}..{hex(e2)}")

    # 2. research/byte-windows.json: forbid ANY dependency overlap and ANY partial first-party overlap;
    # allow exact (s, e) == (es, ee) non-dependency first-party consolidation.
    if BYTE_WINDOWS_JSON.exists():
        bw = json.loads(BYTE_WINDOWS_JSON.read_text(encoding="utf-8"))
        for s, e, sym in intervals:
            for w in bw.get("windows", []):
                es, ee = int(w["start"]), int(w["end"])
                if max(s, es) < min(e, ee):
                    if w.get("dependency") is not None or (s, e) != (es, ee):
                        raise AssertionError(
                            f"Window {sym} ({hex(s)}..{hex(e)}) overlaps byte-windows.json {hex(es)}..{hex(ee)}"
                        )

    # 3. Sibling *-byte-matches* and constants-gate-closure packets: forbid ANY overlap
    checked_peers = 0
    peer_globs = [
        str(REPO_ROOT / "research" / "work-items" / "*byte-matches*" / "records.json"),
        str(REPO_ROOT / "research" / "work-items" / "*constants-gate-closure*" / "records.json"),
    ]
    for pattern in peer_globs:
        for pstr in sorted(glob.glob(pattern)):
            pp = Path(pstr).resolve()
            if pp == RECORDS_PATH.resolve():
                continue
            checked_peers += 1
            d = json.loads(pp.read_text(encoding="utf-8"))
            recs = d.get("windows", d.get("records", d.get("matches", [])))
            for r in recs:
                es = r.get("start_va", r.get("start", r.get("va")))
                if isinstance(es, str):
                    es = int(es, 16)
                ee = r.get("end_va", r.get("end"))
                if isinstance(ee, str):
                    ee = int(ee, 16)
                if ee is None:
                    ee = es + int(r.get("size_bytes", r.get("size", 0)))
                for s, e, sym in intervals:
                    if max(s, es) < min(e, ee):
                        raise AssertionError(
                            f"Window {sym} ({hex(s)}..{hex(e)}) overlaps sibling {pp.parent.name} {hex(es)}..{hex(ee)}"
                        )
    if checked_peers == 0:
        raise AssertionError("Expected at least 1 sibling byte-match packet during disjointness check")


def build_records(binary_bytes: bytes, obj_bytes: bytes, rustc_ver: str) -> dict:
    secs = {name: (sa, so, sz) for _i, name, _st, sa, so, sz, _l, _in in parse_elf_sections(binary_bytes)}
    text_sa, text_so, _text_sz = secs[".text"]
    fdes = load_fde_map()
    compiled = extract_compiled_funcs(obj_bytes)

    by_comp: dict[str, dict[str, int]] = {}
    rows = []
    total_bytes = 0
    total_raw_equal = 0
    for comp, sym, start_va, end_va, label in WINDOWS:
        if fdes.get(start_va) != end_va:
            raise AssertionError(f"FDE mismatch for {hex(start_va)}: expected {hex(end_va)}, got {fdes.get(start_va)}")
        matches = [k for k in compiled if f"{len(sym)}{sym}" in k]
        if len(matches) != 1:
            raise AssertionError(f"Expected 1 compiled section for {sym}, got {matches}")
        got_bytes, rel_offs = compiled[matches[0]]
        size = end_va - start_va
        if len(got_bytes) != size:
            raise AssertionError(f"Size mismatch for {sym}: compiled {len(got_bytes)} vs target {size}")
        off = text_so + (start_va - text_sa)
        want_bytes = binary_bytes[off : off + size]
        mask = bytearray([1] * size)
        for roff in rel_offs:
            for b in range(roff, min(roff + 4, size)):
                mask[b] = 0
        mismatches = [idx for idx, (a, b, m) in enumerate(zip(got_bytes, want_bytes, mask)) if m and a != b]
        if mismatches:
            raise AssertionError(f"Non-relocation mismatch in {sym} @ {hex(start_va)}: {mismatches[:12]}")
        raw_eq = sum(1 for a, b in zip(got_bytes, want_bytes) if a == b)
        total_bytes += size
        total_raw_equal += raw_eq
        by_comp.setdefault(comp, {"windows": 0, "bytes": 0, "raw_equal": 0})
        by_comp[comp]["windows"] += 1
        by_comp[comp]["bytes"] += size
        by_comp[comp]["raw_equal"] += raw_eq
        rows.append(
            {
                "component": comp,
                "symbol": sym,
                "start_va": hex(start_va),
                "end_va": hex(end_va),
                "size": size,
                "raw_equal": raw_eq,
                "relocations": rel_offs,
                "target_sha256": hashlib.sha256(want_bytes).hexdigest(),
                "label": label,
            }
        )
    check_disjointness(rows)
    return {
        "work_item": "RE-007-node115-stream-e2-logic-byte-matches",
        "target_release": "node-115",
        "target_path": "artifacts/node/115/hl-node",
        "target_sha256": hashlib.sha256(binary_bytes).hexdigest(),
        "target_size": len(binary_bytes),
        "rustc_version": rustc_ver,
        "summary": {
            "total_windows": len(rows),
            "total_bytes": total_bytes,
            "total_raw_equal": total_raw_equal,
            "by_component": by_comp,
        },
        "windows": rows,
    }


def verify_records(records: dict, binary_bytes: bytes, obj_bytes: bytes, rustc_ver: str) -> None:
    if records["target_sha256"] != EXPECTED_BINARY_SHA256:
        raise AssertionError("target_sha256 mismatch")
    if records["target_size"] != EXPECTED_BINARY_SIZE:
        raise AssertionError("target_size mismatch")
    rebuilt = build_records(binary_bytes, obj_bytes, rustc_ver)
    if records["windows"] != rebuilt["windows"] or records["summary"] != rebuilt["summary"]:
        raise AssertionError("rebuilt windows/summary mismatch against records.json")


def run_negative_controls(records: dict, binary_bytes: bytes, obj_bytes: bytes, rustc_ver: str) -> int:
    caught = 0
    r1 = copy.deepcopy(records)
    r1["target_sha256"] = "0" * 64
    try:
        verify_records(r1, binary_bytes, obj_bytes, rustc_ver)
        raise RuntimeError("failed to reject bad target_sha256")
    except AssertionError:
        caught += 1

    r2 = copy.deepcopy(records)
    r2["windows"][0]["target_sha256"] = "f" * 64
    try:
        verify_records(r2, binary_bytes, obj_bytes, rustc_ver)
        raise RuntimeError("failed to reject bad window hash")
    except AssertionError:
        caught += 1

    r3 = copy.deepcopy(records)
    r3["windows"][-1]["size"] += 1
    try:
        verify_records(r3, binary_bytes, obj_bytes, rustc_ver)
        raise RuntimeError("failed to reject bad window size")
    except AssertionError:
        caught += 1

    secs = {name: (sa, so, sz) for _i, name, _st, sa, so, sz, _l, _in in parse_elf_sections(binary_bytes)}
    text_sa, text_so, _ = secs[".text"]
    va0 = int(records["windows"][0]["start_va"], 16)
    mut_bin = bytearray(binary_bytes)
    mut_bin[text_so + (va0 - text_sa)] ^= 0xFF
    try:
        build_records(bytes(mut_bin), obj_bytes, rustc_ver)
        raise RuntimeError("failed to reject mutated target opcode")
    except AssertionError:
        caught += 1
    return caught


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--generate", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    binary_bytes = BINARY_PATH.read_bytes()
    if hashlib.sha256(binary_bytes).hexdigest() != EXPECTED_BINARY_SHA256:
        raise SystemExit("Pinned node #115 binary SHA-256 mismatch")
    obj_bytes, rustc_ver = compile_object()
    if args.generate:
        recs = build_records(binary_bytes, obj_bytes, rustc_ver)
        RECORDS_PATH.write_text(json.dumps(recs, indent=2) + "\n", encoding="utf-8")
        print(f"Generated {RECORDS_PATH}: {recs['summary']}")
    else:
        recs = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))
        verify_records(recs, binary_bytes, obj_bytes, rustc_ver)
        print(f"Verified {recs['summary']}")
    if args.self_test:
        caught = run_negative_controls(recs, binary_bytes, obj_bytes, rustc_ver)
        print(f"Negative controls rejected: {caught}/4")


if __name__ == "__main__":
    main()
