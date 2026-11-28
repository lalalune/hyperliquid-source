#!/usr/bin/env python3
"""Live ThinLTO compiled-byte verifier for RE-007-node115-stream-e2-debug-byte-matches."""

from __future__ import annotations

import argparse
import copy
import glob
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
SRC_PATH = HERE / "main.rs"
RECORDS_PATH = HERE / "records.json"
BIN_PATH = REPO / "artifacts" / "node" / "115" / "hl-node"
FDE_TSV_PATH = REPO / "work" / "index" / "node-115-fde.tsv"
BYTE_WINDOWS_PATH = REPO / "research" / "byte-windows.json"

TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
COMPILE_FLAGS = [
    "+1.95.0",
    "--edition=2021",
    "--crate-name",
    "stream_e2_dbg",
    "-C",
    "opt-level=3",
    "-C",
    "overflow-checks=yes",
    "-C",
    "lto=thin",
    "-C",
    "save-temps",
]

# (component, label, kind, start_va, end_va, rodata_anchor_text)
SPECS: list[tuple[str, str, str, int, int, str]] = [
    # risk (8 FDEs / 2,050 B)
    ("risk", "margin_table_id_fmt_44eaf00", "MarginTableId::fmt(&self)", 0x44EAF00, 0x44EB025, "MarginTableId"),
    ("risk", "raw_leverage_fmt_44e87a0", "RawLeverage::fmt(&self)", 0x44E87A0, 0x44E88C5, "RawLeverage"),
    ("risk", "raw_leverage_ref_fmt_4228bf0", "<&RawLeverage as Debug>::fmt", 0x4228BF0, 0x4228D18, "RawLeverage"),
    ("risk", "adl_requirement_ref_fmt_44db9d0", "<&AdlRequirement as Debug>::fmt", 0x44DB9D0, 0x44DBAAD, "AdlRequirement"),
    ("risk", "liquidatable_ref2_fmt_42287a0", "<&&Liquidatable as Debug>::fmt", 0x42287A0, 0x42288A0, "Liquidatable"),
    ("risk", "position_index_fmt_4305a20", "PositionIndex::fmt(&self)", 0x4305A20, 0x4305AF6, "Isolated"),
    ("risk", "position_index_ref_fmt_3c4cda0", "<&PositionIndex as Debug>::fmt", 0x3C4CDA0, 0x3C4CE79, "Isolated"),
    ("risk", "cum_funding_fmt_44e85c0", "CumFunding::fmt(&self)", 0x44E85C0, 0x44E86C4, "CumFunding"),
    # vaults (2 FDEs / 386 B)
    ("vaults", "ownership_fmt_44e5c60", "Ownership::fmt(&self)", 0x44E5C60, 0x44E5D3D, "Ownership"),
    ("vaults", "vault_user_state_ref2_fmt_44dbab0", "<&&vaults::UserState as Debug>::fmt", 0x44DBAB0, 0x44DBB55, "UserState"),
    # l1-shared (12 FDEs / 3,413 B)
    ("l1-shared", "nonce_ref_fmt_2c7c910", "<&Nonce as Debug>::fmt", 0x2C7C910, 0x2C7CA38, "Nonce"),
    ("l1-shared", "decibps_fmt_2e21fb0", "Decibps::fmt(&self)", 0x2E21FB0, 0x2E220D5, "Decibps"),
    ("l1-shared", "decibps_fmt_5960b20", "Decibps::fmt(&self)", 0x5960B20, 0x5960C45, "Decibps"),
    ("l1-shared", "decibps_ref_fmt_2c7c7e0", "<&Decibps as Debug>::fmt", 0x2C7C7E0, 0x2C7C908, "Decibps"),
    ("l1-shared", "decibps_ref_fmt_53d4ce0", "<&Decibps as Debug>::fmt", 0x53D4CE0, 0x53D4E08, "Decibps"),
    ("l1-shared", "priority_rate_fmt_2453910", "PriorityRate::fmt(&self)", 0x2453910, 0x2453A35, "PriorityRate"),
    ("l1-shared", "priority_rate_ref_fmt_241ea90", "<&PriorityRate as Debug>::fmt", 0x241EA90, 0x241EBB8, "PriorityRate"),
    ("l1-shared", "priority_rate_ref_fmt_50d8a20", "<&PriorityRate as Debug>::fmt", 0x50D8A20, 0x50D8B48, "PriorityRate"),
    ("l1-shared", "priority_rate_limit_fmt_51f5840", "PriorityRateLimit::fmt(&self)", 0x51F5840, 0x51F5965, "PriorityRateLimit"),
    ("l1-shared", "float_ref_fmt_44db400", "<&Float as Debug>::fmt", 0x44DB400, 0x44DB528, "Float"),
    ("l1-shared", "order_builder_info_ref_fmt_5940be0", "<&OrderBuilderInfo as Debug>::fmt", 0x5940BE0, 0x5940CDD, "OrderBuilderInfo"),
    ("l1-shared", "sub_builder_ref_fmt_5941770", "<&SubBuilder as Debug>::fmt", 0x5941770, 0x594184D, "SubBuilder"),
    # action-wire (11 FDEs / 2,459 B)
    ("action-wire", "twap_id_ref_fmt_5a2e210", "<&TwapId as Debug>::fmt", 0x5A2E210, 0x5A2E338, "TwapId"),
    ("action-wire", "oid_ref_fmt_5941a80", "<&Oid as Debug>::fmt", 0x5941A80, 0x5941BA8, "Oid"),
    ("action-wire", "trailing_stop_order_ref_fmt_2d47e90", "<&TrailingStopOrder as Debug>::fmt", 0x2D47E90, 0x2D47F35, "TrailingStopOrder"),
    ("action-wire", "trailing_stop_order_ref_fmt_2d47f50", "<&TrailingStopOrder as Debug>::fmt", 0x2D47F50, 0x2D47FF5, "TrailingStopOrder"),
    ("action-wire", "trailing_stop_order_ref_fmt_5a2c0b0", "<&TrailingStopOrder as Debug>::fmt", 0x5A2C0B0, 0x5A2C155, "TrailingStopOrder"),
    ("action-wire", "trailing_stop_order_ref_fmt_5a2ea20", "<&TrailingStopOrder as Debug>::fmt", 0x5A2EA20, 0x5A2EAC5, "TrailingStopOrder"),
    ("action-wire", "trigger_order_ref_fmt_5a2c190", "<&TriggerOrder as Debug>::fmt", 0x5A2C190, 0x5A2C270, "TriggerOrder"),
    ("action-wire", "trigger_order_ref_fmt_5a2ece0", "<&TriggerOrder as Debug>::fmt", 0x5A2ECE0, 0x5A2EDC0, "TriggerOrder"),
    ("action-wire", "trigger_ref_fmt_5a2e0e0", "<&Trigger as Debug>::fmt", 0x5A2E0E0, 0x5A2E1DD, "Trigger"),
    ("action-wire", "trigger_ref_fmt_5a2e630", "<&Trigger as Debug>::fmt", 0x5A2E630, 0x5A2E72D, "Trigger"),
    ("action-wire", "relationships_fmt_5aa8480", "Relationships::fmt(&self)", 0x5AA8480, 0x5AA857D, "Relationships"),
    # exchange (3 FDEs / 584 B)
    ("exchange", "exchange_user_state_ref_fmt_5941020", "<&exchange::UserState as Debug>::fmt", 0x5941020, 0x594111D, "UserState"),
    ("exchange", "exchange_user_state_ref_fmt_5941850", "<&exchange::UserState as Debug>::fmt", 0x5941850, 0x594194D, "UserState"),
    ("exchange", "exchange_kind_display_fmt_1696db0", "<ExchangeKind as Display>::fmt", 0x1696DB0, 0x1696DFE, "Exchange"),
]


def parse_elf_sections(data: bytes) -> dict[str, tuple[int, int, int]]:
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    shstr_off = struct.unpack_from("<Q", data, e_shoff + e_shstrndx * e_shentsize + 24)[0]
    sections: dict[str, tuple[int, int, int]] = {}
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name, _t, _f, sh_addr, sh_offset, sh_size = struct.unpack_from("<IIQQQQ", data, off)
        end = data.index(b"\x00", shstr_off + sh_name)
        sections[data[shstr_off + sh_name : end].decode("ascii")] = (sh_addr, sh_offset, sh_size)
    return sections


def parse_obj_sections(obj: bytes) -> dict[str, tuple[bytes, list[int]]]:
    o_shoff = struct.unpack_from("<Q", obj, 0x28)[0]
    o_shentsize, o_shnum, o_shstrndx = struct.unpack_from("<HHH", obj, 0x3A)
    o_shstr = struct.unpack_from("<Q", obj, o_shoff + o_shstrndx * o_shentsize + 24)[0]
    o_secs = []
    for i in range(o_shnum):
        off = o_shoff + i * o_shentsize
        sh_name, sh_type, _f, _a, sh_offset, sh_size, _l, sh_info = struct.unpack_from("<IIQQQQII", obj, off)
        end = obj.index(b"\x00", o_shstr + sh_name)
        o_secs.append((i, obj[o_shstr + sh_name : end].decode("utf-8", "replace"), sh_type, sh_offset, sh_size, sh_info))

    relocs: dict[int, list[int]] = {}
    for _idx, _name, stype, soff, ssz, sinfo in o_secs:
        if stype == 4:
            offs: set[int] = set()
            for p in range(soff, soff + ssz, 24):
                r_offset, r_info, _r_addend = struct.unpack_from("<QQq", obj, p)
                width = 8 if (r_info & 0xFFFFFFFF) == 1 else 4
                for k in range(width):
                    offs.add(r_offset + k)
            relocs[sinfo] = sorted(offs)

    by_name: dict[str, tuple[bytes, list[int]]] = {}
    for idx, name, stype, soff, ssz, _sinfo in o_secs:
        if stype == 1 and name.startswith(".text."):
            by_name[name] = (obj[soff : soff + ssz], relocs.get(idx, []))
    return by_name


def load_fde_map() -> dict[int, int]:
    fdes: dict[int, int] = {}
    with FDE_TSV_PATH.open("r", encoding="utf-8") as fh:
        for line in fh:
            parts = line.strip().split("\t")
            if len(parts) >= 2 and parts[0].startswith("0x"):
                fdes[int(parts[0], 16)] = int(parts[1], 16)
    return fdes


def compile_source(src_path: Path, flags: list[str]) -> dict[str, tuple[bytes, list[int]]]:
    with tempfile.TemporaryDirectory(prefix="node115-e2-dbg-") as td:
        out_bin = Path(td) / "stream_e2_dbg"
        subprocess.run(
            ["rustc", *flags, str(src_path), "-o", str(out_bin)],
            cwd=td,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        objs = sorted(glob.glob(os.path.join(td, "stream_e2_dbg.stream_e2_dbg.*.rcgu.o")))
        if not objs:
            raise AssertionError("ThinLTO compile produced no rcgu.o object")
        by_name: dict[str, tuple[bytes, list[int]]] = {}
        for op in objs:
            by_name.update(parse_obj_sections(Path(op).read_bytes()))
        return by_name


def extract_interval(w: dict, fdes: dict[int, int]) -> tuple[int, int] | None:
    s = None
    for k in ("start", "start_va", "va_start", "fde_start", "node115_start", "va"):
        if w.get(k) is not None:
            s = w[k]
            break
    if s is None:
        return None
    si = int(s, 16) if isinstance(s, str) else int(s)
    for k in ("end", "end_va", "va_end", "fde_end", "node115_end"):
        if w.get(k) is not None:
            return (si, int(w[k], 16) if isinstance(w[k], str) else int(w[k]))
    for k in ("size", "len", "byte_len", "bytes"):
        if isinstance(w.get(k), int):
            return (si, si + int(w[k]))
    return (si, fdes[si]) if si in fdes else None


def check_disjointness(windows: list[dict], fdes: dict[int, int]) -> None:
    own: list[tuple[int, int, str]] = []
    for w in windows:
        s = int(w["start_va"], 16)
        e = int(w["end_va"], 16)
        assert s < e, f"invalid window {w['label']}"
        own.append((s, e, w["label"]))
    own.sort()
    for i in range(len(own) - 1):
        assert own[i][1] <= own[i + 1][0], f"internal overlap: {own[i]} vs {own[i + 1]}"

    other: list[tuple[int, int, str, bool]] = []
    if BYTE_WINDOWS_PATH.exists():
        bw = json.loads(BYTE_WINDOWS_PATH.read_text(encoding="utf-8"))
        for w in bw.get("windows", []):
            iv = extract_interval(w, fdes)
            if iv:
                other.append((iv[0], iv[1], "research/byte-windows.json", "dependency" not in w))

    for p in sorted((REPO / "research" / "work-items").glob("*/records.json")):
        if p.resolve() == RECORDS_PATH.resolve():
            continue
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        items = d if isinstance(d, list) else d.get("windows", d.get("records", []))
        for w in items:
            if not isinstance(w, dict):
                continue
            iv = extract_interval(w, fdes)
            if iv:
                other.append((iv[0], iv[1], p.parent.name, False))

    for s, e, lbl in own:
        for os_, oe_, src_lbl, allow_exact_fp in other:
            if max(s, os_) < min(e, oe_):
                if allow_exact_fp and (s, e) == (os_, oe_):
                    continue
                raise AssertionError(
                    f"overlap for {lbl} ({hex(s)}..{hex(e)}) with {src_lbl} ({hex(os_)}..{hex(oe_)})"
                )


def verify_rodata_anchor(elf: bytes, secs: dict[str, tuple[int, int, int]], start_va: int, end_va: int, anchor: str) -> None:
    text_va, text_off, _ = secs[".text"]
    ro_va, ro_off, ro_sz = secs[".rodata"]
    buf = elf[text_off + (start_va - text_va) : text_off + (end_va - text_va)]
    ro = elf[ro_off : ro_off + ro_sz]
    needle = anchor.encode("utf-8")
    for i in range(len(buf) - 7):
        if buf[i] in (0x48, 0x4C) and buf[i + 1] == 0x8D and (buf[i + 2] & 0xC7) == 0x05:
            disp = struct.unpack_from("<i", buf, i + 3)[0]
            dest = start_va + i + 7 + disp
            if ro_va <= dest < ro_va + ro_sz - len(needle):
                o = dest - ro_va
                if ro[o : o + len(needle)] == needle:
                    return
    raise AssertionError(f"RIP-relative .rodata anchor {anchor!r} not found in {hex(start_va)}..{hex(end_va)}")


def generate_records() -> dict:
    elf = BIN_PATH.read_bytes()
    actual_sha = hashlib.sha256(elf).hexdigest()
    assert actual_sha == TARGET_SHA256, f"SHA-256 mismatch: {actual_sha}"
    secs = parse_elf_sections(elf)
    text_va, text_off, _ = secs[".text"]
    fdes = load_fde_map()
    by_name = compile_source(SRC_PATH, COMPILE_FLAGS)
    rustc_ver = subprocess.check_output(["rustc", "+1.95.0", "--version"], text=True).strip()

    windows = []
    by_comp: dict[str, dict[str, int]] = {}
    total_bytes = 0
    total_raw_equal = 0

    for comp, label, kind, s, e, anchor in SPECS:
        assert s in fdes and fdes[s] == e, f"FDE extent mismatch for {label}: {hex(s)}..{hex(e)}"
        verify_rodata_anchor(elf, secs, s, e, anchor)
        tbytes = elf[text_off + (s - text_va) : text_off + (e - text_va)]
        best = None
        for sec_name, (cbytes, roffs) in sorted(by_name.items()):
            if len(cbytes) != len(tbytes):
                continue
            rset = set(roffs)
            diffs = [i for i in range(len(tbytes)) if cbytes[i] != tbytes[i] and i not in rset]
            if not diffs:
                raw_eq = sum(cbytes[i] == tbytes[i] for i in range(len(tbytes)))
                if best is None or raw_eq > best[0]:
                    best = (raw_eq, sec_name, cbytes, roffs)
        assert best is not None, f"no 0-diff compiled section for {label} ({hex(s)}..{hex(e)}, {e - s} B)"
        raw_eq, sec_name, cbytes, roffs = best
        total_bytes += len(tbytes)
        total_raw_equal += raw_eq
        st = by_comp.setdefault(comp, {"windows": 0, "bytes": 0, "raw_equal_bytes": 0})
        st["windows"] += 1
        st["bytes"] += len(tbytes)
        st["raw_equal_bytes"] += raw_eq
        windows.append(
            {
                "component": comp,
                "label": label,
                "kind": kind,
                "rodata_anchor": anchor,
                "compiled_section": sec_name,
                "start_va": hex(s),
                "end_va": hex(e),
                "size": len(tbytes),
                "raw_equal_bytes": raw_eq,
                "relocation_offsets": roffs,
                "relocation_qualified": True,
                "target_sha256": hashlib.sha256(tbytes).hexdigest(),
                "compiled_sha256": hashlib.sha256(cbytes).hexdigest(),
            }
        )

    check_disjointness(windows, fdes)
    return {
        "schema_version": 1,
        "work_item": "RE-007-node115-stream-e2-debug-byte-matches",
        "target_binary": {
            "path": "artifacts/node/115/hl-node",
            "sha256": TARGET_SHA256,
        },
        "source_file": "main.rs",
        "source_sha256": hashlib.sha256(SRC_PATH.read_bytes()).hexdigest(),
        "rustc_version": rustc_ver,
        "compile_flags": COMPILE_FLAGS,
        "summary": {
            "window_count": len(windows),
            "total_bytes": total_bytes,
            "raw_equal_bytes": total_raw_equal,
            "raw_equal_pct": round(100.0 * total_raw_equal / total_bytes, 2),
            "by_component": by_comp,
        },
        "windows": windows,
    }


def verify_records(rec: dict, *, run_self_test: bool = False) -> None:
    elf = BIN_PATH.read_bytes()
    assert hashlib.sha256(elf).hexdigest() == rec["target_binary"]["sha256"] == TARGET_SHA256
    assert hashlib.sha256(SRC_PATH.read_bytes()).hexdigest() == rec["source_sha256"]
    secs = parse_elf_sections(elf)
    text_va, text_off, _ = secs[".text"]
    fdes = load_fde_map()
    by_name = compile_source(SRC_PATH, rec["compile_flags"])

    windows = rec["windows"]
    assert len(windows) == rec["summary"]["window_count"] == 36
    check_disjointness(windows, fdes)

    tot_b = 0
    tot_raw = 0
    for w in windows:
        s = int(w["start_va"], 16)
        e = int(w["end_va"], 16)
        assert s in fdes and fdes[s] == e, f"FDE extent mismatch {w['label']}"
        verify_rodata_anchor(elf, secs, s, e, w["rodata_anchor"])
        tbytes = elf[text_off + (s - text_va) : text_off + (e - text_va)]
        assert hashlib.sha256(tbytes).hexdigest() == w["target_sha256"]
        cbytes, roffs = by_name[w["compiled_section"]]
        assert len(cbytes) == len(tbytes) == w["size"]
        assert roffs == w["relocation_offsets"]
        rset = set(roffs)
        diffs = [i for i in range(len(tbytes)) if cbytes[i] != tbytes[i] and i not in rset]
        assert not diffs, f"non-reloc diffs in {w['label']}: {diffs[:10]}"
        raw_eq = sum(cbytes[i] == tbytes[i] for i in range(len(tbytes)))
        assert raw_eq == w["raw_equal_bytes"]
        tot_b += len(tbytes)
        tot_raw += raw_eq

    assert tot_b == rec["summary"]["total_bytes"] == 8901
    assert tot_raw == rec["summary"]["raw_equal_bytes"]

    if run_self_test:
        # 1. Corrupt non-relocation byte
        w0 = windows[0]
        s0, e0 = int(w0["start_va"], 16), int(w0["end_va"], 16)
        tb = bytearray(elf[text_off + (s0 - text_va) : text_off + (e0 - text_va)])
        cb, ro = by_name[w0["compiled_section"]]
        non_reloc = next(i for i in range(len(tb)) if i not in set(ro))
        tb[non_reloc] ^= 0xFF
        assert [i for i in range(len(tb)) if cb[i] != tb[i] and i not in set(ro)], "neg1 failed"

        # 2. Internal overlap rejected
        dup = copy.deepcopy(windows)
        dup.append(copy.deepcopy(windows[0]))
        try:
            check_disjointness(dup, fdes)
            raise AssertionError("neg2 failed")
        except AssertionError as exc:
            assert "internal overlap" in str(exc)

        # 3. External overlap with byte-windows.json rejected
        bw = json.loads(BYTE_WINDOWS_PATH.read_text(encoding="utf-8"))
        ext0 = bw["windows"][0]
        ext_s = ext0["start"] if isinstance(ext0["start"], int) else int(ext0["start"], 16)
        ext_e = ext0["end"] if isinstance(ext0["end"], int) else int(ext0["end"], 16)
        bad_ext = copy.deepcopy(windows)
        bad_ext[0]["start_va"] = hex(ext_s)
        bad_ext[0]["end_va"] = hex(ext_e)
        try:
            check_disjointness(bad_ext, fdes)
            raise AssertionError("neg3 failed")
        except AssertionError as exc:
            assert "overlap" in str(exc)

        # 4. Bogus .rodata anchor rejected
        try:
            verify_rodata_anchor(elf, secs, s0, e0, "DefinitelyNotInRodataXYZ999")
            raise AssertionError("neg4 failed")
        except AssertionError as exc:
            assert "not found" in str(exc)

        print(
            f"PASS: {len(windows)}/{len(windows)} relocation-qualified Stream E2 ThinLTO Debug/Display "
            f"windows, {tot_b} B ({tot_raw}/{tot_b} = {100.0 * tot_raw / tot_b:.2f}% raw-equal), "
            f"4/4 negative controls rejected."
        )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--generate", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.generate:
        rec = generate_records()
        RECORDS_PATH.write_text(json.dumps(rec, indent=2) + "\n", encoding="utf-8")
    rec = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))
    verify_records(rec, run_self_test=args.self_test)
    if not args.self_test:
        s = rec["summary"]
        print(f"PASS: {s['window_count']} windows, {s['total_bytes']} B ({s['raw_equal_bytes']} raw-equal)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
