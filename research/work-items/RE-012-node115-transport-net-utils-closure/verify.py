#!/usr/bin/env python3
"""Static verifier for RE-012-node115-transport-net-utils-closure."""

from __future__ import annotations

import argparse
import bisect
import copy
import hashlib
import json
import struct
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
RECORDS_PATH = HERE / "records.json"
FDE_TSV_PATH = REPO / "work" / "index" / "node-115-fde.tsv"


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


def load_fde_index() -> tuple[dict[int, int], list[int], list[int]]:
    fdes: dict[int, int] = {}
    starts: list[int] = []
    ends: list[int] = []
    with FDE_TSV_PATH.open("r", encoding="utf-8") as fh:
        for line in fh:
            parts = line.strip().split("\t")
            if len(parts) >= 2 and parts[0].startswith("0x"):
                s = int(parts[0], 16)
                e = int(parts[1], 16)
                fdes[s] = e
                starts.append(s)
                ends.append(e)
    return fdes, starts, ends


def scan_net_utils_locations_and_fdes(
    data: bytes,
    sections: dict[str, tuple[int, int, int]],
    fde_starts: list[int],
    fde_ends: list[int],
) -> tuple[dict[int, tuple[str, int, int]], set[str], set[tuple[int, int]]]:
    ro_va, ro_off, ro_sz = sections[".rodata"]
    dr_va, dr_off, dr_sz = sections[".data.rel.ro"]
    rela_va, rela_off, rela_sz = sections[".rela.dyn"]
    text_va, text_off, text_sz = sections[".text"]

    locs: dict[int, tuple[str, int, int]] = {}
    files: set[str] = set()
    for off in range(rela_off, rela_off + rela_sz, 24):
        r_offset, r_info, r_addend = struct.unpack_from("<QQq", data, off)
        if (
            (r_info & 0xFFFFFFFF) == 8
            and dr_va <= r_offset < dr_va + dr_sz
            and ro_va <= r_addend < ro_va + ro_sz
        ):
            raw = data[ro_off + (r_addend - ro_va) : ro_off + (r_addend - ro_va) + 64]
            if raw.startswith(b"net_utils/src/"):
                doff = dr_off + (r_offset - dr_va)
                slen, ln, col = struct.unpack_from("<QII", data, doff + 8)
                if 10 <= slen <= 60:
                    path_str = data[
                        ro_off + (r_addend - ro_va) : ro_off + (r_addend - ro_va) + slen
                    ].decode("ascii")
                    if path_str.endswith(".rs"):
                        locs[r_offset] = (path_str, ln, col)
                        files.add(path_str)

    text_bytes = data[text_off : text_off + text_sz]
    loc_set = set(locs.keys())
    found_fdes: set[tuple[int, int]] = set()
    referenced_locs: set[int] = set()

    i = 0
    n = len(text_bytes) - 6
    while i < n:
        idx = text_bytes.find(b"\x8d", i)
        if idx == -1 or idx >= n:
            break
        modrm = text_bytes[idx + 1]
        if (modrm & 0xC7) == 0x05 and idx > 0 and text_bytes[idx - 1] in (0x48, 0x4C):
            disp = struct.unpack_from("<i", text_bytes, idx + 2)[0]
            target = text_va + idx + 6 + disp
            if target in loc_set:
                ins_va = text_va + idx - 1
                pos = bisect.bisect_right(fde_starts, ins_va) - 1
                if 0 <= pos < len(fde_starts) and fde_starts[pos] <= ins_va < fde_ends[pos]:
                    found_fdes.add((fde_starts[pos], fde_ends[pos]))
                    referenced_locs.add(target)
        i = idx + 1

    if len(referenced_locs) != len(locs):
        raise AssertionError(
            f"unreferenced net_utils locations: {len(locs) - len(referenced_locs)}"
        )
    return locs, files, found_fdes


def verify_records(
    records: dict,
    data: bytes,
    sections: dict[str, tuple[int, int, int]],
    fdes: dict[int, int],
    fde_starts: list[int],
    fde_ends: list[int],
) -> None:
    tb = records["target_binary"]
    if len(data) != tb["size"]:
        raise AssertionError("binary size mismatch")
    if hashlib.sha256(data).hexdigest() != tb["sha256"]:
        raise AssertionError("binary sha256 mismatch")

    locs, obs_files, obs_fdes = scan_net_utils_locations_and_fdes(
        data, sections, fde_starts, fde_ends
    )
    if len(locs) != records["location_count"]:
        raise AssertionError(
            f"location_count mismatch: {len(locs)} != {records['location_count']}"
        )
    if sorted(obs_files) != records["observed_source_files"]:
        raise AssertionError(f"observed_source_files mismatch: {sorted(obs_files)}")

    # Verify every recorded Location matches the binary.
    rec_loc_count = 0
    for src_file, entries in records["locations_by_file"].items():
        for loc in entries:
            va = int(loc["va"], 16)
            if locs.get(va) != (src_file, int(loc["line"]), int(loc["col"])):
                raise AssertionError(f"Location mismatch at 0x{va:x} for {src_file}")
            rec_loc_count += 1
    if rec_loc_count != len(locs):
        raise AssertionError(f"locations_by_file total {rec_loc_count} != {len(locs)}")

    # Verify every FDE matches both node-115-fde.tsv and our independent .text LEA scan.
    rec_fdes: set[tuple[int, int]] = set()
    total_bytes = 0
    for entry in records["net_utils_src_fdes"]:
        s = int(entry["start"], 16)
        e = int(entry["end"], 16)
        sz = int(entry["size"])
        if (s, e) in rec_fdes:
            raise AssertionError(f"duplicate FDE 0x{s:x}")
        if e - s != sz or fdes.get(s) != e:
            raise AssertionError(f"FDE mismatch at 0x{s:x}")
        rec_fdes.add((s, e))
        total_bytes += sz
    if rec_fdes != obs_fdes:
        raise AssertionError(
            f"FDE set mismatch: recorded={len(rec_fdes)} observed={len(obs_fdes)}"
        )

    sm = records["summary"]
    if (
        sm["source_files"] != len(obs_files)
        or sm["locations"] != len(locs)
        or sm["net_utils_src_fdes"] != len(rec_fdes)
        or sm["net_utils_src_fde_bytes"] != total_bytes
    ):
        raise AssertionError("summary mismatch")

    text_va, text_off, text_sz = sections[".text"]
    ro_va, ro_off, ro_sz = sections[".rodata"]

    for anc in records["instruction_anchors"]:
        va = int(anc["va"], 16)
        want = bytes.fromhex(anc["hex"])
        if not (text_va <= va and va + len(want) <= text_va + text_sz):
            raise AssertionError(f"anchor out of .text: {anc['name']}")
        got = data[text_off + (va - text_va) : text_off + (va - text_va) + len(want)]
        if got != want:
            raise AssertionError(
                f"anchor mismatch for {anc['name']}: {got.hex()} != {want.hex()}"
            )

    for lit in records["rodata_literals"]:
        va = int(lit["va"], 16)
        want = lit["ascii"].encode("ascii")
        if not (ro_va <= va and va + len(want) <= ro_va + ro_sz):
            raise AssertionError(f"literal out of .rodata: {lit['name']}")
        got = data[ro_off + (va - ro_va) : ro_off + (va - ro_va) + len(want)]
        if got != want:
            raise AssertionError(
                f"literal mismatch for {lit['name']}: {got!r} != {want!r}"
            )

    for c in records["rodata_f64_constants"]:
        va = int(c["va"], 16)
        if not (ro_va <= va and va + 8 <= ro_va + ro_sz):
            raise AssertionError(f"f64 constant out of .rodata: {c['name']}")
        got = struct.unpack_from("<d", data, ro_off + (va - ro_va))[0]
        if got != float(c["value"]):
            raise AssertionError(
                f"f64 mismatch for {c['name']}: {got} != {c['value']}"
            )

    # Verify workspace mapping covers all 12 files and exists on disk.
    mod_map = records["workspace_module_map"]
    if sorted(mod_map.keys()) != sorted(obs_files):
        raise AssertionError("workspace_module_map does not cover all observed net_utils/src files")
    for rel_path in set(mod_map.values()):
        if not (REPO / rel_path).is_file():
            raise AssertionError(f"missing workspace module {rel_path}")
    lib_rs = (REPO / "src" / "net-utils" / "src" / "lib.rs").read_text(encoding="utf-8")
    if "#![forbid(unsafe_code)]" not in lib_rs:
        raise AssertionError("src/net-utils/src/lib.rs missing #![forbid(unsafe_code)]")


def run_negative_controls(
    records: dict,
    data: bytes,
    sections: dict[str, tuple[int, int, int]],
    fdes: dict[int, int],
    fde_starts: list[int],
    fde_ends: list[int],
) -> int:
    mutations = [
        ("bad_loc_count", lambda r: r.update({"location_count": 69})),
        (
            "bad_fde_end",
            lambda r: r["net_utils_src_fdes"][0].update(
                {"end": "0x2a64bd8", "size": r["net_utils_src_fdes"][0]["size"] + 1}
            ),
        ),
        (
            "bad_opcode",
            lambda r: r["instruction_anchors"][0].update({"hex": "48b80000000000004e41"}),
        ),
        (
            "bad_literal",
            lambda r: r["rodata_literals"][0].update({"ascii": "net_utils/src/ip_semaphore.rX"}),
        ),
        (
            "bad_f64",
            lambda r: r["rodata_f64_constants"][0].update({"value": 31.0}),
        ),
    ]
    rejected = 0
    for name, fn in mutations:
        mutated = copy.deepcopy(records)
        fn(mutated)
        try:
            verify_records(mutated, data, sections, fdes, fde_starts, fde_ends)
        except AssertionError:
            rejected += 1
        else:
            raise AssertionError(f"negative control {name} was NOT rejected")
    return rejected


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    records = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))
    data = (REPO / records["target_binary"]["path"]).read_bytes()
    sections = parse_elf_sections(data)
    fdes, fde_starts, fde_ends = load_fde_index()

    verify_records(records, data, sections, fdes, fde_starts, fde_ends)
    sm = records["summary"]
    msg = (
        f"PASS: {sm['source_files']}/12 net_utils/src files, {sm['locations']}/68 Locations, "
        f"{sm['net_utils_src_fdes']}/62 FDEs ({sm['net_utils_src_fde_bytes']} B), "
        f"{sm['instruction_anchors']} anchors, {sm['rodata_literals']} literals, "
        f"{sm['rodata_f64_constants']} f64 constants"
    )
    if args.self_test:
        neg = run_negative_controls(records, data, sections, fdes, fde_starts, fde_ends)
        msg += f", {neg}/{neg} negative controls rejected"
    print(msg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
