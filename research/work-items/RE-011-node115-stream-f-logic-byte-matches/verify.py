#!/usr/bin/env python3
"""Live-compile and verify 23 strictly disjoint Stream F first-party FDE byte matches
across `bridge` (13 FDEs / 11,526 B), `evm` (8 FDEs / 8,689 B), and `evm-rpc`
(2 FDEs / 618 B) — totaling 20,833 B in Linux x86-64 node #115.
"""

from __future__ import annotations

import argparse
import glob
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
sys.path.insert(0, str(REPO_ROOT / "tools"))
import byte_progress as bp  # noqa: E402

TARGET_BIN = REPO_ROOT / "artifacts/node/115/hl-node"
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
FDE_TSV = REPO_ROOT / "work/index/node-115-fde.tsv"
BYTE_WINDOWS_JSON = REPO_ROOT / "research/byte-windows.json"
LIB_RS = PACKET_DIR / "lib.rs"
RECORDS_JSON = PACKET_DIR / "records.json"

TARGETS = [
    # bridge: Bridge2::FieldVisitor::visit_bytes (RMP tag 0x9, 15 fields + __Ignore)
    ("bridge", "Bridge2::FieldVisitor::visit_bytes (RMP #1)", "bridge2_visit_bytes_tag9", 0x28618E0, 0x28621E3),
    ("bridge", "Bridge2::FieldVisitor::visit_bytes (RMP #2)", "bridge2_visit_bytes_tag9", 0x4442E00, 0x4443703),
    ("bridge", "Bridge2::FieldVisitor::visit_bytes (RMP #3)", "bridge2_visit_bytes_tag9", 0x5AE3260, 0x5AE3B63),
    # bridge: Bridge2::FieldVisitor::visit_str (tag 0x0 x2, RMP tag 0x9 x3)
    ("bridge", "Bridge2::FieldVisitor::visit_str (tag0 #1)", "bridge2_visit_str_tag0", 0x28621F0, 0x286248E),
    ("bridge", "Bridge2::FieldVisitor::visit_str (RMP #1)", "bridge2_visit_str_tag9", 0x2862490, 0x286272E),
    ("bridge", "Bridge2::FieldVisitor::visit_str (RMP #2)", "bridge2_visit_str_tag9", 0x4443710, 0x44439AE),
    ("bridge", "Bridge2::FieldVisitor::visit_str (tag0 #2)", "bridge2_visit_str_tag0", 0x44439B0, 0x4443C4E),
    ("bridge", "Bridge2::FieldVisitor::visit_str (RMP #3)", "bridge2_visit_str_tag9", 0x5AE3B70, 0x5AE3E0E),
    # bridge: EthEventId::FieldVisitor::visit_str (5 fields + 1-char renames + __Ignore)
    ("bridge", "EthEventId::FieldVisitor::visit_str (tag0 #1)", "eth_event_id_visit_str_tag0", 0x28657C0, 0x28658BB),
    ("bridge", "EthEventId::FieldVisitor::visit_str (RMP #1)", "eth_event_id_visit_str_tag9", 0x28658C0, 0x28659BB),
    ("bridge", "EthEventId::FieldVisitor::visit_str (RMP #2)", "eth_event_id_visit_str_tag9", 0x4446940, 0x4446A3B),
    ("bridge", "EthEventId::FieldVisitor::visit_str (tag0 #2)", "eth_event_id_visit_str_tag0", 0x4446A40, 0x4446B3B),
    ("bridge", "EthEventId::FieldVisitor::visit_str (RMP #3)", "eth_event_id_visit_str_tag9", 0x5AE4780, 0x5AE487B),
    # evm: HyperEvm::FieldVisitor::visit_bytes (RMP tag 0x9, 15 fields + __Ignore)
    ("evm", "HyperEvm::FieldVisitor::visit_bytes (RMP #1)", "hyperevm_visit_bytes_tag9", 0x299C930, 0x299D068),
    ("evm", "HyperEvm::FieldVisitor::visit_bytes (RMP #2)", "hyperevm_visit_bytes_tag9", 0x4339E20, 0x433A558),
    ("evm", "HyperEvm::FieldVisitor::visit_bytes (RMP #3)", "hyperevm_visit_bytes_tag9", 0x5472610, 0x5472D48),
    # evm: HyperEvm::FieldVisitor::visit_str (tag 0x0 x2, RMP tag 0x9 x3)
    ("evm", "HyperEvm::FieldVisitor::visit_str (tag0 #1)", "hyperevm_visit_str_tag0", 0x299D070, 0x299D2E5),
    ("evm", "HyperEvm::FieldVisitor::visit_str (RMP #1)", "hyperevm_visit_str_tag9", 0x299D2F0, 0x299D565),
    ("evm", "HyperEvm::FieldVisitor::visit_str (tag0 #2)", "hyperevm_visit_str_tag0", 0x433A560, 0x433A7D5),
    ("evm", "HyperEvm::FieldVisitor::visit_str (RMP #2)", "hyperevm_visit_str_tag9", 0x433A7E0, 0x433AA55),
    ("evm", "HyperEvm::FieldVisitor::visit_str (RMP #3)", "hyperevm_visit_str_tag9", 0x5472D50, 0x5472FC5),
    # evm-rpc: EthCallOverrides::FieldVisitor::visit_str (4 fields + camelCase/snake_case aliases)
    ("evm-rpc", "EthCallOverrides::FieldVisitor::visit_str (tag0)", "eth_call_ovr_tag0", 0x29AEE50, 0x29AEF58),
    # evm-rpc: AccountOverride::FieldVisitor::visit_str (6 fields + HyperEVM MovePrecompileToAddress)
    ("evm-rpc", "AccountOverride::FieldVisitor::visit_str (JSON)", "account_override_visit_str", 0x2745310, 0x2745472),
]


def parse_int(v: int | str) -> int:
    return int(v, 16) if isinstance(v, str) else int(v)


def read_text_section(elf_path: Path) -> tuple[int, bytes, str]:
    raw = elf_path.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    e_shoff = struct.unpack_from("<Q", raw, 40)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", raw, 58)
    shstr_off = struct.unpack_from("<Q", raw, e_shoff + e_shstrndx * e_shentsize + 24)[0]
    shstr_sz = struct.unpack_from("<Q", raw, e_shoff + e_shstrndx * e_shentsize + 32)[0]
    shstr = raw[shstr_off : shstr_off + shstr_sz]
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name, _sh_type, _sh_flags, sh_addr, sh_offset, sh_size = struct.unpack_from("<IIQQQQ", raw, off)
        name = shstr[sh_name : shstr.index(b"\x00", sh_name)].decode("ascii", "ignore")
        if name == ".text":
            return sh_addr, raw[sh_offset : sh_offset + sh_size], sha
    raise RuntimeError(".text section not found")


def compile_object() -> tuple[dict[str, tuple[str, bytes, list[dict]]], str]:
    rustc_ver = subprocess.check_output(["rustc", "+1.95.0", "--version"], text=True).strip()
    with tempfile.TemporaryDirectory(prefix="stream_f_logic_115_") as tmpdir:
        obj_path = Path(tmpdir) / "stream_f_logic.o"
        cmd = [
            "rustc",
            "+1.95.0",
            "--edition=2021",
            "--crate-name=stream_f_logic_115",
            "--crate-type=rlib",
            "-C",
            "opt-level=3",
            "-C",
            "overflow-checks=yes",
            "-C",
            "codegen-units=1",
            "--emit=obj",
            "-o",
            str(obj_path),
            str(LIB_RS),
        ]
        subprocess.check_call(cmd)
        data = obj_path.read_bytes()

    e_shoff = struct.unpack_from("<Q", data, 40)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)
    shstr_off = struct.unpack_from("<Q", data, e_shoff + e_shstrndx * e_shentsize + 24)[0]
    shstr_sz = struct.unpack_from("<Q", data, e_shoff + e_shstrndx * e_shentsize + 32)[0]
    shstr = data[shstr_off : shstr_off + shstr_sz]
    secs = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        flds = struct.unpack_from("<IIQQQQIIQQ", data, off)
        name = shstr[flds[0] : shstr.index(b"\x00", flds[0])].decode("ascii", "ignore")
        sdata = data[flds[4] : flds[4] + flds[5]] if flds[1] != 8 else b""
        secs.append((name, flds, sdata))

    symtab = b""
    strtab = b""
    rela_by_sec: dict[int, bytes] = {}
    for _name, flds, sdata in secs:
        if flds[1] == 2:
            symtab = sdata
            strtab = secs[flds[6]][2]
        elif flds[1] == 4:
            rela_by_sec[flds[7]] = sdata

    syms: dict[str, tuple[str, bytes, list[dict]]] = {}
    for off in range(0, len(symtab), 24):
        st_name, st_info, _st_other, st_shndx, st_value, st_size = struct.unpack_from("<IBBHQQ", symtab, off)
        if st_size == 0 or st_shndx == 0 or st_shndx >= len(secs):
            continue
        if (st_info & 0xF) != 2:
            continue
        sname = strtab[st_name : strtab.index(b"\x00", st_name)].decode("ascii", "ignore")
        sec_data = secs[st_shndx][2]
        body = sec_data[st_value : st_value + st_size]
        rels = []
        rdata = rela_by_sec.get(st_shndx, b"")
        for roff in range(0, len(rdata), 24):
            r_offset, r_info, r_addend = struct.unpack_from("<QQq", rdata, roff)
            if st_value <= r_offset < st_value + st_size:
                rels.append(
                    {
                        "offset": r_offset - st_value,
                        "width": 4,
                        "type": r_info & 0xFFFFFFFF,
                        "addend": r_addend,
                    }
                )
        rels.sort(key=lambda r: r["offset"])
        syms[sname] = (sname, body, rels)
    return syms, rustc_ver


def find_sym(syms: dict[str, tuple[str, bytes, list[dict]]], key: str) -> tuple[str, bytes, list[dict]]:
    token = f"{len(key)}{key}"
    hits = [v for k, v in syms.items() if token in k]
    if len(hits) != 1:
        raise RuntimeError(f"Expected 1 compiled symbol matching {key!r}, got {len(hits)}")
    return hits[0]


def load_fde_set() -> set[tuple[int, int]]:
    out: set[tuple[int, int]] = set()
    with FDE_TSV.open() as f:
        f.readline()
        for line in f:
            parts = line.strip().split("\t")
            if len(parts) >= 2:
                out.add((int(parts[0], 16), int(parts[1], 16)))
    return out


def check_disjointness(records: list[dict]) -> None:
    # 1. Self-disjointness
    intervals = sorted((parse_int(r["start"]), parse_int(r["end"]), r["id"]) for r in records)
    for i in range(len(intervals) - 1):
        if intervals[i][1] > intervals[i + 1][0]:
            raise AssertionError(f"Self-overlap: {intervals[i]} vs {intervals[i + 1]}")

    # 2. Wave-4 consolidation-safe check against research/byte-windows.json:
    #    - ZERO overlap with any dependency window
    #    - ZERO partial overlap with any first-party window (exact (s, e) match allowed after Wave-4 fold)
    bw = json.loads(BYTE_WINDOWS_JSON.read_text())
    for s, e, rid in intervals:
        for w in bw.get("windows", []):
            ws, we = parse_int(w["start"]), parse_int(w["end"])
            if ws < e and s < we:
                if "dependency" in w:
                    raise AssertionError(f"Overlap with dependency window {w.get('id')}: {rid}")
                if (s, e) != (ws, we):
                    raise AssertionError(f"Partial overlap with first-party window {w.get('id')}: {rid}")

    # 3. Zero overlap with all sibling byte-matches / gate-closure / thinlto / 100pct packets
    patterns = [
        "research/work-items/*byte-matches*/records.json",
        "research/work-items/*gate-closure*/records.json",
        "research/work-items/*thinlto*/records.json",
        "research/work-items/*100pct*/records.json",
    ]
    seen_paths: set[Path] = set()
    for pat in patterns:
        for p_str in glob.glob(str(REPO_ROOT / pat)):
            p = Path(p_str).resolve()
            if p == RECORDS_JSON.resolve() or p in seen_paths:
                continue
            seen_paths.add(p)
            data = json.loads(p.read_text())
            recs = data if isinstance(data, list) else data.get("records", [])
            for r in recs:
                s_v = r.get("start") or r.get("fde_start") or r.get("va_start") or r.get("target_va_start")
                e_v = r.get("end") or r.get("fde_end") or r.get("va_end") or r.get("target_va_end")
                if s_v is None or e_v is None:
                    continue
                rs, re_ = parse_int(s_v), parse_int(e_v)
                for s, e, rid in intervals:
                    if rs < e and s < re_:
                        raise AssertionError(f"Overlap with sibling packet {p.parent.name}: {rid}")


def run_negative_controls(text_va: int, text_data: bytes, syms: dict) -> list[str]:
    results = []
    # NC1: 1-byte non-relocation corruption must fail compare
    _sname, cbody, rels = find_sym(syms, "bridge2_visit_bytes_tag9")
    tbody = text_data[0x28618E0 - text_va : 0x28621E3 - text_va]
    bad = bytearray(cbody)
    bad[0] ^= 0xFF
    res1 = bp.compare(bytes(bad), tbody, rels)
    assert not res1["relocation_qualified"], "NC1 failed: corrupted byte passed!"
    results.append("NC1_corrupt_non_reloc_byte_rejected")

    # NC2: Wrong target FDE (Bridge2 vs HyperEvm) must fail
    _sn2, cb2, rels2 = find_sym(syms, "bridge2_visit_str_tag0")
    tb2 = text_data[0x299D070 - text_va : 0x299D2E5 - text_va]
    try:
        res2 = bp.compare(cb2, tb2, rels2)
        assert not res2["relocation_qualified"], "NC2 failed: wrong target passed!"
    except ValueError:
        pass
    results.append("NC2_wrong_target_fde_rejected")

    # NC3: Empty relocation mask on function containing RIP-relative jump table must fail raw equality
    res3 = bp.compare(cbody, tbody, [])
    assert not res3["relocation_qualified"], "NC3 failed: unmasked relocation passed!"
    results.append("NC3_missing_reloc_mask_rejected")

    # NC4: Truncated target window must fail
    try:
        bp.compare(cbody, tbody[:-1], rels)
        raise AssertionError("NC4 failed: truncated target passed!")
    except ValueError:
        pass
    results.append("NC4_truncated_window_rejected")
    return results


def build_payload() -> dict:
    text_va, text_data, sha = read_text_section(TARGET_BIN)
    assert sha == TARGET_SHA256, f"Target SHA-256 mismatch: {sha}"
    fdes = load_fde_set()
    syms, rustc_ver = compile_object()

    records = []
    by_comp: dict[str, dict[str, int]] = {}
    total_bytes = 0
    total_raw = 0

    for comp, label, sym_key, s, e in TARGETS:
        assert (s, e) in fdes, f"Not an exact FDE: 0x{s:x}..0x{e:x}"
        mangled, cbody, rels = find_sym(syms, sym_key)
        tbody = text_data[s - text_va : e - text_va]
        assert len(cbody) == len(tbody), f"Length mismatch for {sym_key}: {len(cbody)} vs {len(tbody)}"
        res = bp.compare(cbody, tbody, rels)
        assert res["relocation_qualified"], f"Relocation-qualified mismatch for {sym_key} @ 0x{s:x}"
        assert res["non_reloc_diff_bytes"] == 0 if "non_reloc_diff_bytes" in res else True

        rec = {
            "id": f"node115-fp-stream-f-logic-{comp}-{s:x}",
            "component": comp,
            "label": label,
            "source_symbol": sym_key,
            "mangled_symbol": mangled,
            "start": f"0x{s:x}",
            "end": f"0x{e:x}",
            "size": e - s,
            "raw_equal_bytes": res["raw_equal_bytes"],
            "relocation_count": len(rels),
            "relocations": rels,
            "compiled_body_sha256": hashlib.sha256(cbody).hexdigest(),
            "target_body_sha256": hashlib.sha256(tbody).hexdigest(),
            "relocation_qualified": True,
        }
        records.append(rec)
        total_bytes += e - s
        total_raw += res["raw_equal_bytes"]
        st = by_comp.setdefault(comp, {"fdes": 0, "bytes": 0, "raw_equal_bytes": 0})
        st["fdes"] += 1
        st["bytes"] += e - s
        st["raw_equal_bytes"] += res["raw_equal_bytes"]

    check_disjointness(records)
    ncs = run_negative_controls(text_va, text_data, syms)

    return {
        "schema_version": 1,
        "packet": "RE-011-node115-stream-f-logic-byte-matches",
        "target": {
            "path": "artifacts/node/115/hl-node",
            "sha256": TARGET_SHA256,
        },
        "compiler": {
            "rustc": rustc_ver,
            "flags": [
                "--edition=2021",
                "--crate-name=stream_f_logic_115",
                "--crate-type=rlib",
                "-C",
                "opt-level=3",
                "-C",
                "overflow-checks=yes",
                "-C",
                "codegen-units=1",
                "--emit=obj",
            ],
            "unsafe_code": "forbid",
            "external_dependencies": 0,
        },
        "summary": {
            "total_fdes": len(records),
            "total_bytes": total_bytes,
            "raw_equal_bytes": total_raw,
            "raw_equal_pct": round(100.0 * total_raw / total_bytes, 2),
            "by_component": by_comp,
            "negative_controls": ncs,
        },
        "records": records,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write-records", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    payload = build_payload()
    if args.write_records:
        RECORDS_JSON.write_text(json.dumps(payload, indent=2) + "\n")
        print(f"Wrote {RECORDS_JSON} ({payload['summary']['total_fdes']} FDEs, {payload['summary']['total_bytes']} B)")
        return 0

    if args.self_test or not args.write_records:
        assert RECORDS_JSON.exists(), f"Missing {RECORDS_JSON}"
        recorded = json.loads(RECORDS_JSON.read_text())
        assert recorded["records"] == payload["records"], "Live rebuild drifted from records.json!"
        s = payload["summary"]
        print(
            f"PASS: {s['total_fdes']}/{s['total_fdes']} FDEs relocation-qualified, "
            f"{s['total_bytes']} B total, {s['raw_equal_bytes']}/{s['total_bytes']} ({s['raw_equal_pct']}%) raw-equal, "
            f"components={s['by_component']}, {len(s['negative_controls'])}/4 negative controls rejected"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
