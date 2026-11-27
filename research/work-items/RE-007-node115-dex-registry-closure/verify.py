#!/usr/bin/env python3
"""Static verifier for RE-007-node115-dex-registry-closure."""

from __future__ import annotations

import argparse
import bisect
import copy
import hashlib
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
RECORDS_PATH = HERE / "records.json"
FDE_TSV_PATH = REPO / "work" / "index" / "node-115-fde.tsv"

DEX_REGISTRY_PREFIX = b"l1/src/dex_registry/"


def parse_elf_sections(data: bytes) -> dict[str, tuple[int, int, int]]:
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    shstr_off = struct.unpack_from("<Q", data, e_shoff + e_shstrndx * e_shentsize + 24)[0]
    sections: dict[str, tuple[int, int, int]] = {}
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name, _sh_type, _sh_flags, sh_addr, sh_offset, sh_size = struct.unpack_from(
            "<IIQQQQ", data, off
        )
        end = data.index(b"\x00", shstr_off + sh_name)
        sections[data[shstr_off + sh_name : end].decode("ascii")] = (sh_addr, sh_offset, sh_size)
    return sections


def load_fde_index() -> tuple[dict[int, int], list[tuple[int, int]]]:
    fdes: dict[int, int] = {}
    ordered: list[tuple[int, int]] = []
    with FDE_TSV_PATH.open("r", encoding="utf-8") as fh:
        for line in fh:
            parts = line.strip().split("\t")
            if len(parts) >= 2 and parts[0].startswith("0x"):
                s = int(parts[0], 16)
                e = int(parts[1], 16)
                fdes[s] = e
                ordered.append((s, e))
    ordered.sort()
    return fdes, ordered


def scan_dex_registry_locations(
    data: bytes, sections: dict[str, tuple[int, int, int]]
) -> dict[int, tuple[str, int, int]]:
    ro_va, ro_off, ro_sz = sections[".rodata"]
    dr_va, dr_off, dr_sz = sections[".data.rel.ro"]
    rela_va, rela_off, rela_sz = sections[".rela.dyn"]
    locs: dict[int, tuple[str, int, int]] = {}
    for off in range(rela_off, rela_off + rela_sz, 24):
        r_offset, r_info, r_addend = struct.unpack_from("<QQq", data, off)
        if (
            (r_info & 0xFFFFFFFF) == 8
            and dr_va <= r_offset < dr_va + dr_sz
            and ro_va <= r_addend < ro_va + ro_sz
        ):
            raw = data[ro_off + (r_addend - ro_va) : ro_off + (r_addend - ro_va) + 64]
            if raw.startswith(DEX_REGISTRY_PREFIX):
                doff = dr_off + (r_offset - dr_va)
                slen, line, col = struct.unpack_from("<QII", data, doff + 8)
                if 12 <= slen <= 80 and 1 <= line <= 50000 and 1 <= col <= 500:
                    path_str = data[
                        ro_off + (r_addend - ro_va) : ro_off + (r_addend - ro_va) + slen
                    ].decode("ascii")
                    if path_str.endswith(".rs"):
                        locs[r_offset] = (path_str, line, col)
    return locs


def scan_location_referencing_fdes(
    data: bytes,
    sections: dict[str, tuple[int, int, int]],
    ordered_fdes: list[tuple[int, int]],
    loc_vas: set[int],
) -> set[int]:
    text_va, text_off, text_sz = sections[".text"]
    text = data[text_off : text_off + text_sz]
    fde_starts = [s for s, _ in ordered_fdes]
    hits: set[int] = set()
    limit = len(text) - 7
    i = 0
    while i < limit:
        b0 = text[i]
        if (b0 == 0x48 or b0 == 0x4C) and text[i + 1] == 0x8D and (text[i + 2] & 0xC7) == 0x05:
            disp = struct.unpack_from("<i", text, i + 3)[0]
            target = text_va + i + 7 + disp
            if target in loc_vas:
                ins_va = text_va + i
                idx = bisect.bisect_right(fde_starts, ins_va) - 1
                if idx >= 0 and ordered_fdes[idx][0] <= ins_va < ordered_fdes[idx][1]:
                    hits.add(ordered_fdes[idx][0])
        i += 1
    return hits


def verify_records(
    records: dict,
    data: bytes,
    sections: dict[str, tuple[int, int, int]],
    fdes: dict[int, int],
    ordered_fdes: list[tuple[int, int]],
    observed_locs: dict[int, tuple[str, int, int]],
    observed_loc_fde_starts: set[int],
) -> None:
    tb = records["target_binary"]
    if len(data) != tb["size"]:
        raise AssertionError("binary size mismatch")
    if hashlib.sha256(data).hexdigest() != tb["sha256"]:
        raise AssertionError("binary sha256 mismatch")

    obs_files = sorted({file for file, _, _ in observed_locs.values()})
    if len(observed_locs) != records["location_count"]:
        raise AssertionError(
            f"location_count mismatch: {len(observed_locs)} != {records['location_count']}"
        )
    if obs_files != records["observed_source_files"]:
        raise AssertionError(f"observed_source_files mismatch: {obs_files}")

    recorded_locs = {
        int(loc["va"], 16): (loc["file"], int(loc["line"]), int(loc["col"]))
        for loc in records["locations"]
    }
    if recorded_locs != observed_locs:
        raise AssertionError("recorded locations do not match ELF .data.rel.ro Locations")

    loc_starts: set[int] = set()
    loc_bytes = 0
    for entry in records["dex_registry_location_fdes"]:
        s = int(entry["start"], 16)
        e = int(entry["end"], 16)
        sz = int(entry["size"])
        if s in loc_starts:
            raise AssertionError(f"duplicate location FDE 0x{s:x}")
        loc_starts.add(s)
        if e - s != sz or fdes.get(s) != e:
            raise AssertionError(f"FDE mismatch at 0x{s:x}")
        loc_bytes += sz
    if loc_starts != observed_loc_fde_starts:
        raise AssertionError(
            f"location FDE completeness mismatch: recorded={len(loc_starts)} vs elf={len(observed_loc_fde_starts)}"
        )

    biz_starts: set[int] = set()
    biz_bytes = 0
    for entry in records["dex_registry_business_fdes"]:
        s = int(entry["start"], 16)
        e = int(entry["end"], 16)
        sz = int(entry["size"])
        if s in biz_starts or s in loc_starts:
            raise AssertionError(f"duplicate or overlapping business FDE 0x{s:x}")
        biz_starts.add(s)
        if e - s != sz or fdes.get(s) != e:
            raise AssertionError(f"FDE mismatch for {entry['role']} at 0x{s:x}")
        biz_bytes += sz

    sm = records["summary"]
    if (
        sm["observed_source_files"] != len(obs_files)
        or sm["location_count"] != len(observed_locs)
        or sm["dex_registry_location_fdes"] != len(loc_starts)
        or sm["dex_registry_location_fde_bytes"] != loc_bytes
        or sm["dex_registry_business_fdes"] != len(biz_starts)
        or sm["dex_registry_business_fde_bytes"] != biz_bytes
        or sm["combined_unique_fdes"] != len(loc_starts) + len(biz_starts)
        or sm["combined_unique_fde_bytes"] != loc_bytes + biz_bytes
    ):
        raise AssertionError("summary counts mismatch")

    text_va, text_off, text_sz = sections[".text"]
    ro_va, ro_off, ro_sz = sections[".rodata"]

    for anc in records["instruction_anchors"]:
        va = int(anc["va"], 16)
        want = bytes.fromhex(anc["hex"])
        if not (text_va <= va and va + len(want) <= text_va + text_sz):
            raise AssertionError(f"anchor out of .text: {anc['name']}")
        got = data[text_off + (va - text_va) : text_off + (va - text_va) + len(want)]
        if got != want:
            raise AssertionError(f"anchor mismatch for {anc['name']}: {got.hex()} != {want.hex()}")

    for lit in records["rodata_literals"]:
        va = int(lit["va"], 16)
        want = lit["ascii"].encode("ascii")
        if not (ro_va <= va and va + len(want) <= ro_va + ro_sz):
            raise AssertionError(f"literal out of .rodata: {lit['name']}")
        got = data[ro_off + (va - ro_va) : ro_off + (va - ro_va) + len(want)]
        if got != want:
            raise AssertionError(f"literal mismatch for {lit['name']}: {got!r} != {want!r}")


def run_negative_controls(
    records: dict,
    data: bytes,
    sections: dict[str, tuple[int, int, int]],
    fdes: dict[int, int],
    ordered_fdes: list[tuple[int, int]],
    observed_locs: dict[int, tuple[str, int, int]],
    observed_loc_fde_starts: set[int],
) -> int:
    mutations = [
        ("bad_loc_count", lambda r: r.update({"location_count": 6})),
        (
            "bad_fde_end",
            lambda r: r["dex_registry_business_fdes"][0].update({"end": "0x2b94dc4", "size": 68}),
        ),
        (
            "bad_opcode",
            lambda r: r["instruction_anchors"][0].update({"hex": "483b7711"}),
        ),
        (
            "bad_literal",
            lambda r: r["rodata_literals"][0].update({"ascii": "l1/src/dex_registry/clearinghouses.rX"}),
        ),
    ]
    rejected = 0
    for name, mutate in mutations:
        bad = copy.deepcopy(records)
        mutate(bad)
        try:
            verify_records(bad, data, sections, fdes, ordered_fdes, observed_locs, observed_loc_fde_starts)
        except AssertionError:
            rejected += 1
        else:
            raise AssertionError(f"negative control {name} unexpectedly passed")
    return rejected


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    records = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))
    data = (REPO / records["target_binary"]["path"]).read_bytes()
    sections = parse_elf_sections(data)
    fdes, ordered_fdes = load_fde_index()
    observed_locs = scan_dex_registry_locations(data, sections)
    observed_loc_fde_starts = scan_location_referencing_fdes(
        data, sections, ordered_fdes, set(observed_locs.keys())
    )

    verify_records(records, data, sections, fdes, ordered_fdes, observed_locs, observed_loc_fde_starts)
    neg = 0
    if args.self_test:
        neg = run_negative_controls(
            records, data, sections, fdes, ordered_fdes, observed_locs, observed_loc_fde_starts
        )
    sm = records["summary"]
    print(
        f"PASS: dex-registry closure verified — {sm['observed_source_files']}/3 files, "
        f"{sm['location_count']}/5 Locations, "
        f"{sm['dex_registry_location_fdes']}/373 Location FDEs ({sm['dex_registry_location_fde_bytes']} B), "
        f"{sm['dex_registry_business_fdes']}/20 business FDEs ({sm['dex_registry_business_fde_bytes']} B), "
        f"combined {sm['combined_unique_fdes']} unique FDEs ({sm['combined_unique_fde_bytes']} B), "
        f"{neg}/4 negative controls rejected"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
