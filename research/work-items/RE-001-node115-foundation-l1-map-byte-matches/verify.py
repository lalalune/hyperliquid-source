#!/usr/bin/env python3
"""Live-compiled byte-match verifier for node #115 base/src/l1_map/entry.rs FDEs."""

from __future__ import annotations

import argparse
import bisect
import hashlib
import json
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import byte_progress  # noqa: E402

TARGET_REL = "artifacts/node/115/hl-node"
TARGET_SIZE = 105896032
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
RUSTC_FLAGS = [
    "rustc",
    "+1.95.0",
    "--edition=2021",
    "--crate-type=lib",
    "--crate-name=foundation_l1_map",
    "-C",
    "opt-level=3",
    "-C",
    "overflow-checks=on",
    "-C",
    "relocation-model=pic",
    "-C",
    "lto=off",
    "--emit=obj",
]


def parse_elf_sections(data: bytes) -> dict[str, tuple[int, int, int]]:
    (e_shoff,) = struct.unpack_from("<Q", data, 40)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)
    (shstr_off,) = struct.unpack_from("<Q", data, e_shoff + e_shstrndx * e_shentsize + 24)
    secs: dict[str, tuple[int, int, int]] = {}
    for i in range(e_shnum):
        base = e_shoff + i * e_shentsize
        sh_name, _sh_type, _sh_flags, sh_addr, sh_offset, sh_size = struct.unpack_from(
            "<IIQQQQ", data, base
        )
        end = data.index(b"\x00", shstr_off + sh_name)
        secs[data[shstr_off + sh_name : end].decode()] = (sh_addr, sh_offset, sh_size)
    return secs


def load_fde_extents(bin_path: Path) -> dict[int, int]:
    tsv = ROOT / "work/index/node-115-fde.tsv"
    extents: dict[int, int] = {}
    if tsv.is_file():
        for line in tsv.read_text().splitlines()[1:]:
            parts = line.split("\t")
            if len(parts) >= 2:
                s = int(parts[0], 16)
                e = int(parts[1], 16)
                extents[s] = e
        if extents:
            return extents
    out = subprocess.check_output(["readelf", "-wF", str(bin_path)], text=True)
    for m in re.finditer(r"FDE cie=\S+ pc=([0-9a-f]+)\.\.([0-9a-f]+)", out):
        extents[int(m.group(1), 16)] = int(m.group(2), 16)
    return extents


def find_l1_map_location_fdes(
    data: bytes, secs: dict[str, tuple[int, int, int]], fde_extents: dict[int, int]
) -> dict[int, list[str]]:
    ro_va, ro_off, ro_sz = secs[".rodata"]
    drr_va, drr_off, drr_sz = secs[".data.rel.ro"]
    _rela_va, rela_off, rela_sz = secs[".rela.dyn"]
    text_va, text_off, text_sz = secs[".text"]
    ro_bytes = data[ro_off : ro_off + ro_sz]
    drr_bytes = data[drr_off : drr_off + drr_sz]
    text_bytes = data[text_off : text_off + text_sz]

    needle = b"base/src/l1_map/entry.rs"
    va_set = {ro_va + m.start() for m in re.finditer(re.escape(needle), ro_bytes)}
    locs: dict[int, str] = {}
    for off in range(rela_off, rela_off + rela_sz, 24):
        r_offset, r_info, r_addend = struct.unpack_from("<QQq", data, off)
        if (r_info & 0xFFFFFFFF) == 8 and r_addend in va_set and drr_va <= r_offset < drr_va + drr_sz - 24:
            ln, line, col = struct.unpack_from("<QII", drr_bytes, r_offset - drr_va + 8)
            if ln == len(needle):
                locs[r_offset] = f"base/src/l1_map/entry.rs:{line}:{col}"

    sorted_fdes = sorted(fde_extents.items())
    starts = [s for s, _ in sorted_fdes]
    fde_locs: dict[int, set[str]] = {}
    for i in range(0, len(text_bytes) - 7):
        if text_bytes[i] in (0x48, 0x4C) and text_bytes[i + 1] == 0x8D and (text_bytes[i + 2] & 0xC7) == 0x05:
            (disp,) = struct.unpack_from("<i", text_bytes, i + 3)
            target = text_va + i + 7 + disp
            if target in locs:
                va = text_va + i
                idx = bisect.bisect_right(starts, va) - 1
                if idx >= 0 and sorted_fdes[idx][0] <= va < sorted_fdes[idx][1]:
                    fde_locs.setdefault(sorted_fdes[idx][0], set()).add(locs[target])
    return {s: sorted(v) for s, v in fde_locs.items()}


def compile_l1_map_symbols(lib_rs: Path) -> dict[str, tuple[bytes, list[dict[str, int]]]]:
    with tempfile.TemporaryDirectory() as td:
        obj = Path(td) / "foundation_l1_map.o"
        subprocess.check_call(RUSTC_FLAGS + ["-o", str(obj), str(lib_rs)])
        obj_data = obj.read_bytes()
        (oe_shoff,) = struct.unpack_from("<Q", obj_data, 40)
        oe_shent, oe_shnum, oe_shstrndx = struct.unpack_from("<HHH", obj_data, 58)
        (oshstr_off,) = struct.unpack_from("<Q", obj_data, oe_shoff + oe_shstrndx * oe_shent + 24)
        osecs: list[tuple[str, int, int, int, int]] = []
        rela_by_sec: dict[int, list[dict[str, int]]] = {}
        for i in range(oe_shnum):
            b = oe_shoff + i * oe_shent
            sh_name, sh_type, _sh_flags, _sh_addr, sh_offset, sh_size, _sh_link, sh_info = (
                struct.unpack_from("<IIQQQQII", obj_data, b)
            )
            name = obj_data[oshstr_off + sh_name : obj_data.index(b"\x00", oshstr_off + sh_name)].decode()
            osecs.append((name, sh_type, sh_offset, sh_size, sh_info))
            if sh_type == 4:
                rels = []
                for ro in range(sh_offset, sh_offset + sh_size, 24):
                    r_off, r_info, r_add = struct.unpack_from("<QQq", obj_data, ro)
                    rels.append(
                        {"offset": r_off, "width": 4, "kind": r_info & 0xFFFFFFFF, "addend": r_add}
                    )
                rela_by_sec[sh_info] = rels

        syms_out = subprocess.check_output(["readelf", "-sW", str(obj)], text=True)
        compiled: dict[str, tuple[bytes, list[dict[str, int]]]] = {}
        for line in syms_out.splitlines():
            parts = line.split()
            if len(parts) < 8 or parts[3] != "FUNC" or not parts[7].startswith("_ZN"):
                continue
            sym = parts[7]
            if not any(tok in sym for tok in ("OccupiedEntry", "Entry$LT$")):
                continue
            shndx, sval, ssz = int(parts[6]), int(parts[1], 16), int(parts[2], 0)
            if ssz == 0:
                continue
            _, _, sh_off, _, _ = osecs[shndx]
            cbytes = obj_data[sh_off + sval : sh_off + sval + ssz]
            rels = [
                {
                    "offset": r["offset"] - sval,
                    "width": 4,
                    "kind": r["kind"],
                    "addend": r["addend"],
                }
                for r in rela_by_sec.get(shndx, [])
                if sval <= r["offset"] < sval + ssz
            ]
            if all(r["kind"] in (2, 4, 9, 41, 42) for r in rels):
                compiled[sym] = (cbytes, rels)
        return compiled


def check_no_internal_overlaps(intervals: list[tuple[int, int]]) -> None:
    ordered = sorted(intervals)
    for (s1, e1), (s2, _e2) in zip(ordered, ordered[1:]):
        if s2 < e1:
            raise ValueError(f"Overlapping windows: [{hex(s1)}, {hex(e1)}) and {hex(s2)}")


def check_target_digest(data: bytes, expected_sha: str) -> None:
    if len(data) != TARGET_SIZE:
        raise ValueError(f"Unexpected target size: {len(data)} != {TARGET_SIZE}")
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected_sha:
        raise ValueError(f"Target SHA-256 mismatch: {actual} != {expected_sha}")


def method_name(sym: str) -> str:
    for m in ("or_default", "or_insert", "remove_entry", "get_mut", "get"):
        if m in sym:
            return m
    return "entry"


def generate_records() -> dict:
    bin_path = ROOT / TARGET_REL
    data = bin_path.read_bytes()
    check_target_digest(data, TARGET_SHA256)
    secs = parse_elf_sections(data)
    text_va, text_off, _ = secs[".text"]
    fde_extents = load_fde_extents(bin_path)
    fde_locs = find_l1_map_location_fdes(data, secs, fde_extents)

    used: list[tuple[int, int]] = []
    bw = json.loads((ROOT / "research/byte-windows.json").read_text())
    for w in bw["windows"]:
        used.append((w["start"], w["end"]))
    for p in list((ROOT / "research/work-items").glob("*/records.json")) + list(
        (ROOT / "research/work-items").glob("*/census.json")
    ):
        if p.parent == HERE:
            continue
        try:
            j = json.loads(p.read_text())
            for w in j.get("windows", j.get("records", [])):
                if not isinstance(w, dict):
                    continue
                s = w.get("start_va", w.get("start"))
                e = w.get("end_va", w.get("end"))
                if s is None or e is None:
                    continue
                s = int(s, 16) if isinstance(s, str) else int(s)
                e = int(e, 16) if isinstance(e, str) else int(e)
                used.append((s, e))
        except Exception:
            pass
    used.sort()

    def is_used(s: int, e: int) -> bool:
        for us, ue in used:
            if us >= e:
                return False
            if ue > s:
                return True
        return False

    by_size: dict[int, list[tuple[int, int, bytes]]] = {}
    for s in sorted(fde_locs):
        e = fde_extents[s]
        if is_used(s, e):
            continue
        by_size.setdefault(e - s, []).append(
            (s, e, data[text_off + (s - text_va) : text_off + (e - text_va)])
        )

    compiled = compile_l1_map_symbols(HERE / "lib.rs")
    matched: dict[int, dict] = {}
    for sym in sorted(compiled):
        cbytes, rels = compiled[sym]
        for s, e, tbytes in by_size.get(len(cbytes), []):
            if s in matched:
                continue
            res = byte_progress.compare(cbytes, tbytes, rels)
            if res["relocation_qualified"]:
                mname = method_name(sym)
                matched[s] = {
                    "id": f"foundation-l1-map-{mname}-{s:x}",
                    "component": "foundation",
                    "attribution": f"base/src/l1_map/entry.rs::{mname}",
                    "locations": fde_locs[s],
                    "symbol": sym,
                    "start": s,
                    "end": e,
                    "start_va": hex(s),
                    "end_va": hex(e),
                    "bytes": e - s,
                    "raw_equal_bytes": (e - s) - res["relocation_bytes"],
                    "relocation_bytes": res["relocation_bytes"],
                    "relocation_qualified": True,
                    "target_body_sha256": hashlib.sha256(tbytes).hexdigest(),
                    "compiled_body_sha256": hashlib.sha256(cbytes).hexdigest(),
                    "relocations": rels,
                }

    windows = [matched[s] for s in sorted(matched)]
    check_no_internal_overlaps([(w["start"], w["end"]) for w in windows])
    rustc_ver = subprocess.check_output(["rustc", "+1.95.0", "--version"], text=True).strip()
    total_bytes = sum(w["bytes"] for w in windows)
    total_raw = sum(w["raw_equal_bytes"] for w in windows)
    return {
        "schema_version": 1,
        "work_item": "RE-001-node115-foundation-l1-map-byte-matches",
        "component": "foundation",
        "components": ["foundation"],
        "target": {
            "path": TARGET_REL,
            "size_bytes": TARGET_SIZE,
            "sha256": TARGET_SHA256,
        },
        "toolchain": {
            "rustc_version": rustc_ver,
            "profile": "opt-level = 3, overflow-checks = true, relocation-model = pic, lto = off",
        },
        "summary": {
            "window_count": len(windows),
            "total_bytes": total_bytes,
            "raw_equal_bytes": total_raw,
            "relocation_bytes": total_bytes - total_raw,
            "distinct_symbols": len({w["symbol"] for w in windows}),
            "by_method": {
                m: {
                    "windows": sum(1 for w in windows if w["attribution"].endswith(f"::{m}")),
                    "bytes": sum(w["bytes"] for w in windows if w["attribution"].endswith(f"::{m}")),
                }
                for m in sorted({w["attribution"].split("::")[-1] for w in windows})
            },
        },
        "windows": windows,
    }


def verify(self_test: bool = False) -> None:
    records = json.loads((HERE / "records.json").read_text())
    bin_path = ROOT / TARGET_REL
    data = bin_path.read_bytes()
    check_target_digest(data, records["target"]["sha256"])

    secs = parse_elf_sections(data)
    text_va, text_off, _ = secs[".text"]
    fde_extents = load_fde_extents(bin_path)
    fde_locs = find_l1_map_location_fdes(data, secs, fde_extents)
    compiled = compile_l1_map_symbols(HERE / "lib.rs")

    windows = records["windows"]
    check_no_internal_overlaps([(w["start"], w["end"]) for w in windows])

    bw = json.loads((ROOT / "research/byte-windows.json").read_text())
    bw_intervals = [
        (w["start"], w["end"])
        for w in bw["windows"]
        if not str(w.get("id", "")).startswith("foundation-l1-map-")
    ]

    first_sample = None
    for w in windows:
        s, e = w["start"], w["end"]
        if fde_extents.get(s) != e:
            raise ValueError(f"FDE mismatch for {hex(s)}: expected end {hex(e)}, got {fde_extents.get(s)}")
        if s not in fde_locs:
            raise ValueError(f"Window {hex(s)} does not reference base/src/l1_map/entry.rs Location")
        for bs, be in bw_intervals:
            if bs < e and be > s:
                raise ValueError(f"Window {hex(s)}..{hex(e)} overlaps byte-windows {hex(bs)}..{hex(be)}")

        sym = w["symbol"]
        if sym not in compiled:
            raise ValueError(f"Missing compiled symbol {sym}")
        cbytes, rels = compiled[sym]
        tbytes = data[text_off + (s - text_va) : text_off + (e - text_va)]
        if hashlib.sha256(tbytes).hexdigest() != w["target_body_sha256"]:
            raise ValueError(f"Target body digest mismatch at {hex(s)}")
        if hashlib.sha256(cbytes).hexdigest() != w["compiled_body_sha256"]:
            raise ValueError(f"Compiled body digest mismatch for {sym}")
        if rels != w["relocations"]:
            raise ValueError(f"Relocation list mismatch for {sym}")
        res = byte_progress.compare(cbytes, tbytes, rels)
        if not res["relocation_qualified"]:
            raise ValueError(f"Relocation-qualified comparison failed at {hex(s)}")
        if res["relocation_bytes"] != w["relocation_bytes"]:
            raise ValueError(f"Relocation byte count mismatch at {hex(s)}")
        if first_sample is None:
            first_sample = (cbytes, tbytes, rels)

    assert first_sample is not None
    nc_passed = 0
    if self_test:
        # NC1: tampered target digest rejected
        try:
            check_target_digest(data, "0" * 64)
            raise AssertionError("NC1 failed")
        except ValueError:
            nc_passed += 1

        # NC2: 1-byte non-relocation mutation rejected
        c0, t0, r0 = first_sample
        reloc_set = {o for r in r0 for o in range(r["offset"], r["offset"] + r["width"])}
        mut_idx = next(i for i in range(len(t0)) if i not in reloc_set)
        mutated = bytearray(t0)
        mutated[mut_idx] ^= 0x01
        if byte_progress.compare(c0, bytes(mutated), r0)["relocation_qualified"]:
            raise AssertionError("NC2 failed")
        nc_passed += 1

        # NC3: overlapping relocation field rejected
        bad_rels = r0 + [dict(r0[0], offset=r0[0]["offset"] + 1)]
        try:
            byte_progress.compare(c0, t0, bad_rels)
            raise AssertionError("NC3 failed")
        except ValueError:
            nc_passed += 1

        # NC4: overlapping window pair rejected
        try:
            check_no_internal_overlaps([(0x1000, 0x1080), (0x1040, 0x10A0)])
            raise AssertionError("NC4 failed")
        except ValueError:
            nc_passed += 1

    total_b = sum(w["bytes"] for w in windows)
    raw_b = sum(w["raw_equal_bytes"] for w in windows)
    print(
        f"PASS: {len(windows)}/{len(windows)} relocation-qualified base/src/l1_map/entry.rs FDEs, "
        f"{total_b} B ({raw_b}/{total_b} = {100.0 * raw_b / total_b:.2f}% raw-equal), "
        f"0 overlaps, {nc_passed}/4 negative controls rejected"
    )


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--generate", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.generate:
        rec = generate_records()
        (HERE / "records.json").write_text(json.dumps(rec, indent=2) + "\n")
        print(
            f"Generated {rec['summary']['window_count']} windows "
            f"({rec['summary']['total_bytes']} B, {rec['summary']['raw_equal_bytes']} raw-equal)"
        )
    else:
        verify(self_test=args.self_test)


if __name__ == "__main__":
    main()
