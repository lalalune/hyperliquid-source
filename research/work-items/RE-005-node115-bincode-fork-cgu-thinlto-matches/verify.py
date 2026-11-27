#!/usr/bin/env python3
"""Live ThinLTO compiled-byte verifier for RE-005-node115-bincode-fork-cgu-thinlto-matches."""

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

PACKET_DIR = Path(__file__).resolve().parent
REPO_ROOT = PACKET_DIR.parents[2]
BINARY_PATH = REPO_ROOT / "artifacts" / "node" / "115" / "hl-node"
FDE_TSV = REPO_ROOT / "work" / "index" / "node-115-fde.tsv"
SOURCE_PATH = PACKET_DIR / "main.rs"
RECORDS_PATH = PACKET_DIR / "records.json"

sys.path.insert(0, str(REPO_ROOT / "tools"))
from byte_progress import compare  # noqa: E402
from elf_index import sections  # noqa: E402

EXPECTED_BINARY_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
)
EXPECTED_BINARY_SIZE = 105_896_032


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


def parse_obj_functions(obj: bytes) -> list[tuple[str, bytes, list[dict]]]:
    o_shoff = struct.unpack_from("<Q", obj, 0x28)[0]
    o_shentsize, o_shnum, o_shstrndx = struct.unpack_from("<HHH", obj, 0x3A)
    o_shstr = struct.unpack_from("<Q", obj, o_shoff + o_shstrndx * o_shentsize + 24)[0]
    secs = []
    for i in range(o_shnum):
        off = o_shoff + i * o_shentsize
        sh_name, sh_type, _, _, sh_offset, sh_size, _, sh_info = struct.unpack_from(
            "<IIQQQQII", obj, off
        )
        end = obj.index(b"\x00", o_shstr + sh_name)
        name = obj[o_shstr + sh_name : end].decode("utf-8", "replace")
        secs.append((i, name, sh_type, sh_offset, sh_size, sh_info))

    relocs: dict[int, list[dict]] = {}
    for _, _, stype, soff, ssz, sinfo in secs:
        if stype == 4:
            rows = []
            for p in range(soff, soff + ssz, 24):
                r_off, r_info, r_add = struct.unpack_from("<QQq", obj, p)
                rows.append(
                    {
                        "offset": r_off,
                        "width": 4,
                        "kind": r_info & 0xFFFFFFFF,
                        "addend": r_add,
                    }
                )
            relocs[sinfo] = rows

    out = []
    for idx, name, stype, soff, ssz, _ in secs:
        if stype == 1 and name.startswith(".text."):
            out.append((name, obj[soff : soff + ssz], relocs.get(idx, [])))
    return out


def compile_thinlto(flags: list[str]) -> tuple[list[tuple[str, bytes, list[dict]]], str]:
    ver = subprocess.check_output(["rustc", "+1.95.0", "--version"], text=True).strip()
    with tempfile.TemporaryDirectory(prefix="node115-bincode-thin-") as td:
        out_bin = Path(td) / "bincode_cgu_thin"
        subprocess.run(
            ["rustc", "+1.95.0", *flags, str(SOURCE_PATH), "-o", str(out_bin)],
            cwd=td,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        objs = sorted(glob.glob(os.path.join(td, "bincode_cgu_thin.bincode_cgu_thin.*.rcgu.o")))
        if not objs:
            raise AssertionError("ThinLTO compile produced no rcgu.o object")
        funcs: list[tuple[str, bytes, list[dict]]] = []
        for obp in objs:
            funcs.extend(parse_obj_functions(Path(obp).read_bytes()))
        return funcs, ver


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
        for pattern in ("*-byte-matches*/records.json", "*-gate-closure*/records.json", "*-thinlto-matches*/records.json"):
            for rp in sorted(wi_root.glob(pattern)):
                if rp.resolve() == RECORDS_PATH.resolve():
                    continue
                pr = json.loads(rp.read_text(encoding="utf-8"))
                for pw in pr.get("windows", []):
                    raw_s = pw.get("start_va", pw.get("start"))
                    if raw_s is None:
                        continue
                    ps = raw_s if isinstance(raw_s, int) else int(raw_s, 16)
                    raw_e = pw.get("end_va", pw.get("end"))
                    pe = (raw_e if isinstance(raw_e, int) else int(raw_e, 16)) if raw_e is not None else ps + pw.get("size_bytes", pw.get("size", 0))
                    peer_records.append((rp.parent.name, ps, pe))

    for pname, ps, pe in peer_records:
        for s, e, wid in seen:
            if s < pe and ps < e:
                raise AssertionError(f"Window {wid} overlaps peer packet {pname} ({hex(ps)}..{hex(pe)})")


def verify_anchors_and_windows(
    data: bytes,
    rec: dict,
    fdes: dict[int, int],
    funcs: list[tuple[str, bytes, list[dict]]],
) -> dict:
    secs = {s["name"]: s for s in sections(data)}
    text_sec = secs[".text"]
    ro_sec = secs[".rodata"]
    rela = secs[".rela.dyn"]
    rel_map: dict[int, int] = {}
    for off in range(rela["offset"], rela["offset"] + rela["size"], 24):
        r_off, r_info, r_addend = struct.unpack_from("<QQq", data, off)
        if (r_info & 0xFFFFFFFF) == 8:
            rel_map[r_off] = r_addend

    total_bytes = 0
    total_raw = 0
    matched = []
    for w in rec["windows"]:
        s = int(w["start_va"], 16)
        e = int(w["end_va"], 16)
        if fdes.get(s) != e:
            raise AssertionError(f"Window {w['id']} FDE mismatch: expected {hex(e)}, got {hex(fdes.get(s, 0))}")
        if "anchor_vtable_va" in w:
            vt_va = int(w["anchor_vtable_va"], 16)
            if rel_map.get(vt_va) != s:
                raise AssertionError(f"Window {w['id']} vtable {w['anchor_vtable_va']} mismatch")
        if "anchor_rodata_va" in w:
            rva = int(w["anchor_rodata_va"], 16)
            expected_s = w["anchor_rodata_str"].encode("ascii")
            roff = ro_sec["offset"] + (rva - ro_sec["address"])
            if data[roff : roff + len(expected_s)] != expected_s:
                raise AssertionError(f"Window {w['id']} .rodata anchor mismatch at {w['anchor_rodata_va']}")

        target = data[text_sec["offset"] + (s - text_sec["address"]) : text_sec["offset"] + (e - text_sec["address"])]
        hit = None
        for name, body, rels in funcs:
            if len(body) != len(target):
                continue
            if "Debug" not in name or "fmt" not in name:
                continue
            try:
                cmp = compare(body, target, rels)
            except Exception:
                continue
            if cmp["relocation_qualified"]:
                hit = (name, cmp, len(rels))
                break
        if hit is None:
            raise AssertionError(f"Window {w['id']} ({hex(s)}..{hex(e)}, {len(target)} B) did not match any ThinLTO compiled Debug::fmt FDE")
        name, cmp, nrel = hit
        if cmp["raw_equal_bytes"] != w["expected_raw_equal"]:
            raise AssertionError(
                f"Window {w['id']} raw_equal mismatch: got {cmp['raw_equal_bytes']}, expected {w['expected_raw_equal']}"
            )
        total_bytes += cmp["bytes"]
        total_raw += cmp["raw_equal_bytes"]
        matched.append({"id": w["id"], "symbol": name, "bytes": cmp["bytes"], "raw_equal_bytes": cmp["raw_equal_bytes"], "relocations": nrel})

    return {
        "matched_windows": len(matched),
        "total_bytes": total_bytes,
        "total_raw_equal_bytes": total_raw,
        "windows": matched,
    }


def run_negative_controls(
    data: bytes,
    rec: dict,
    fdes: dict[int, int],
    funcs: list[tuple[str, bytes, list[dict]]],
) -> int:
    # 1. Mutated byte in DecodeError::Debug (0x16087a0) must be rejected
    bad_data = bytearray(data)
    secs = {s["name"]: s for s in sections(data)}
    t_off = secs[".text"]["offset"] + (0x16087a0 - secs[".text"]["address"])
    bad_data[t_off] ^= 0xFF
    try:
        verify_anchors_and_windows(bytes(bad_data), rec, fdes, funcs)
        raise AssertionError("Negative control 1 failed: mutated byte not rejected")
    except AssertionError as exc:
        if "Negative control 1 failed" in str(exc):
            raise

    # 2. Wrong FDE extent must be rejected
    bad_rec = copy.deepcopy(rec)
    bad_rec["windows"][6]["end_va"] = hex(int(bad_rec["windows"][6]["end_va"], 16) - 1)
    try:
        verify_anchors_and_windows(data, bad_rec, fdes, funcs)
        raise AssertionError("Negative control 2 failed: wrong FDE extent not rejected")
    except AssertionError as exc:
        if "Negative control 2 failed" in str(exc):
            raise

    # 3. Dependency overlap must be rejected
    dep_bw = {"windows": [{"id": "fake-dep", "start": 0x16087a0, "end": 0x16090ed, "dependency": "fake"}]}
    try:
        check_disjointness(rec["windows"], byte_windows_data=dep_bw, peer_records=[])
        raise AssertionError("Negative control 3 failed: dependency overlap not rejected")
    except AssertionError as exc:
        if "Negative control 3 failed" in str(exc):
            raise

    # 4. Partial overlap with first-party window must be rejected
    partial_bw = {"windows": [{"id": "fake-partial", "start": 0x16087a0, "end": 0x16087b0, "dependency": None}]}
    try:
        check_disjointness(rec["windows"], byte_windows_data=partial_bw, peer_records=[])
        raise AssertionError("Negative control 4 failed: partial overlap not rejected")
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
    fdes = load_fde_map()
    check_disjointness(rec["windows"])
    funcs, rustc_ver = compile_thinlto(rec["toolchain"]["flags"])
    compiled = verify_anchors_and_windows(data, rec, fdes, funcs)
    neg = run_negative_controls(data, rec, fdes, funcs) if self_test else 0
    return {
        "rustc_version": rustc_ver,
        "compiled": compiled,
        "negative_controls_rejected": neg,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    summary = verify_all(self_test=args.self_test)
    c = summary["compiled"]
    print(
        f"PASS: {c['matched_windows']}/12 ThinLTO bincode-fork CGU windows "
        f"({c['total_bytes']} B, {c['total_raw_equal_bytes']}/{c['total_bytes']} raw-equal), "
        f"{summary['negative_controls_rejected']}/4 negative controls rejected "
        f"[{summary['rustc_version']}]"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
