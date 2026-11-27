#!/usr/bin/env python3
"""Live compiled-byte verification for Stream C (serialization, transport, node-runtime) FDE matches."""

import argparse
import hashlib
import json
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "research/work-items/RE-002-node115-std-census"))

from byte_progress import compare  # noqa: E402
from census import object_functions  # noqa: E402
from fde_extents import fde_extents  # noqa: E402

TEXT_DELTA = 0x1000
RELA_DYN_OFF = 0x6BE8
RELA_DYN_SIZE = 0x163CC8


def compile_lib() -> tuple[bytes, str]:
    rustc = shutil.which("rustc")
    if not rustc:
        raise RuntimeError("rustc not found on PATH")
    ver = subprocess.check_output([rustc, "+1.95.0", "--version"], text=True).strip()
    if "1.95.0 (59807616e 2026-04-14)" not in ver:
        raise RuntimeError(f"Unexpected rustc version: {ver}")
    with tempfile.TemporaryDirectory() as tmp:
        obj_path = Path(tmp) / "stream_c_bytes.o"
        cmd = [
            rustc,
            "+1.95.0",
            "--edition=2021",
            "--crate-type=rlib",
            "--crate-name=stream_c_byte_matches",
            "-C",
            "opt-level=3",
            "-C",
            "overflow-checks=yes",
            "--emit=obj",
            "-o",
            str(obj_path),
            str(HERE / "lib.rs"),
        ]
        subprocess.run(cmd, check=True)
        return obj_path.read_bytes(), ver


def verify_all(run_self_test: bool = False) -> dict:
    records = json.loads((HERE / "records.json").read_text(encoding="utf-8"))
    bin_path = ROOT / records["target"]["path"]
    data = bin_path.read_bytes()
    actual_sha = hashlib.sha256(data).hexdigest()
    if actual_sha != records["target"]["sha256"]:
        raise AssertionError(f"SHA256 mismatch: {actual_sha}")

    _, fdes, _ = fde_extents(data)
    fde_map = {f["start"]: f for f in fdes if f["section"] == ".text"}

    # Check zero overlap with research/byte-windows.json
    bw = json.loads((ROOT / "research/byte-windows.json").read_text(encoding="utf-8"))
    existing_ranges = [(w["start"], w["end"]) for w in bw.get("windows", [])]

    # Build .rela.dyn map for pointer table verification
    relas: dict[int, int] = {}
    for off in range(RELA_DYN_OFF, RELA_DYN_OFF + RELA_DYN_SIZE, 24):
        r_offset, r_info, r_addend = struct.unpack_from("<QQq", data, off)
        if (r_info & 0xFFFFFFFF) == 8:
            relas[r_offset] = r_addend

    obj_bytes, ver = compile_lib()
    compiled = list(object_functions(obj_bytes))
    by_token: dict[str, tuple[bytes, list[dict]]] = {}
    for syms, body, rels in compiled:
        sym = syms[0]
        rel_rows = [{"offset": r[0], "width": 4, "kind": r[1], "addend": r[2]} for r in rels]
        by_token[sym] = (body, rel_rows)

    def lookup(tok: str) -> tuple[bytes, list[dict]]:
        hits = [(s, v) for s, v in by_token.items() if tok in s]
        if len(hits) != 1:
            raise AssertionError(f"Expected 1 compiled symbol for {tok}, found {len(hits)}")
        return hits[0][1]

    totals = {"windows": 0, "bytes": 0, "raw_equal_bytes": 0, "by_component": {}}
    seen_vas = set()
    sample_target_body = None
    sample_built_body = None
    sample_rels = None

    for w in records["windows"]:
        va = int(w["start_va"], 16)
        if va in seen_vas:
            raise AssertionError(f"Duplicate window VA {hex(va)}")
        seen_vas.add(va)
        if va not in fde_map:
            raise AssertionError(f"VA {hex(va)} is not an authenticated .text FDE start")
        fde = fde_map[va]
        sz = fde["end"] - fde["start"]
        if sz != w["size_bytes"]:
            raise AssertionError(f"Size mismatch for {w['id']}: FDE={sz} vs record={w['size_bytes']}")

        for es, ee in existing_ranges:
            if not (fde["end"] <= es or fde["start"] >= ee):
                raise AssertionError(f"Window {w['id']} ({hex(va)}) overlaps existing byte-windows.json [{hex(es)}, {hex(ee)})")

        # Verify rodata anchor or pointer-table anchor in target binary
        anchor_bytes = w["anchor_str"].encode("utf-8")
        if "anchor_va" in w:
            ava = int(w["anchor_va"], 16)
            if data[ava : ava + len(anchor_bytes)] != anchor_bytes:
                raise AssertionError(f"Rodata anchor mismatch for {w['id']} at {hex(ava)}")
        elif "anchor_ptr_table_va" in w:
            tva = int(w["anchor_ptr_table_va"], 16)
            str_va = relas.get(tva)
            if str_va is None or data[str_va : str_va + len(anchor_bytes)] != anchor_bytes:
                raise AssertionError(f"Ptr-table anchor mismatch for {w['id']} at {hex(tva)}")

        tgt_body = data[va - TEXT_DELTA : va - TEXT_DELTA + sz]
        built_body, rel_rows = lookup(w["symbol_token"])
        if len(built_body) != sz:
            raise AssertionError(f"Compiled size mismatch for {w['id']}: {len(built_body)} vs {sz}")

        res = compare(tgt_body, built_body, rel_rows)
        if not res["relocation_qualified"] or res["non_relocation_difference_offsets"]:
            raise AssertionError(f"Byte mismatch for {w['id']} ({hex(va)}): {res}")

        if sample_target_body is None and sz >= 44:
            sample_target_body, sample_built_body, sample_rels = tgt_body, built_body, rel_rows

        totals["windows"] += 1
        totals["bytes"] += res["bytes"]
        totals["raw_equal_bytes"] += res["raw_equal_bytes"]
        comp = totals["by_component"].setdefault(w["component"], {"windows": 0, "bytes": 0, "raw_equal_bytes": 0})
        comp["windows"] += 1
        comp["bytes"] += res["bytes"]
        comp["raw_equal_bytes"] += res["raw_equal_bytes"]

    if run_self_test:
        # Negative control 1: flip a non-relocation byte -> must fail relocation_qualified
        mut = bytearray(sample_built_body)
        mut[0] ^= 0xFF
        res_neg1 = compare(sample_target_body, bytes(mut), sample_rels)
        assert not res_neg1["relocation_qualified"], "Negative control 1 (byte flip) failed to reject"

        # Negative control 2: wrong-size body -> must raise ValueError
        try:
            compare(sample_target_body, sample_built_body[:-1], sample_rels)
            raise AssertionError("Negative control 2 (length mismatch) failed to reject")
        except ValueError:
            pass

        # Negative control 3: corrupted anchor offset +1 -> must not match
        first_ro = next(w for w in records["windows"] if "anchor_va" in w)
        ava = int(first_ro["anchor_va"], 16)
        ab = first_ro["anchor_str"].encode("utf-8")
        assert data[ava + 1 : ava + 1 + len(ab)] != ab, "Negative control 3 failed"

        # Negative control 4: non-FDE VA (+1) must not be in fde_map
        first_va = int(records["windows"][0]["start_va"], 16)
        assert (first_va + 1) not in fde_map, "Negative control 4 failed"

    totals["rustc_version"] = ver
    return totals


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    summary = verify_all(run_self_test=args.self_test)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
