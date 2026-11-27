#!/usr/bin/env python3
"""Static verifier for RE-009-node115-abci-closure."""

from __future__ import annotations

import argparse
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


def load_fde_map() -> dict[int, int]:
    fdes: dict[int, int] = {}
    with FDE_TSV_PATH.open("r", encoding="utf-8") as fh:
        for line in fh:
            parts = line.strip().split("\t")
            if len(parts) >= 2 and parts[0].startswith("0x"):
                fdes[int(parts[0], 16)] = int(parts[1], 16)
    return fdes


def count_abci_src_locations(
    data: bytes, sections: dict[str, tuple[int, int, int]]
) -> tuple[int, set[str]]:
    ro_va, ro_off, ro_sz = sections[".rodata"]
    dr_va, dr_off, dr_sz = sections[".data.rel.ro"]
    rela_va, rela_off, rela_sz = sections[".rela.dyn"]
    count = 0
    files: set[str] = set()
    for off in range(rela_off, rela_off + rela_sz, 24):
        r_offset, r_info, r_addend = struct.unpack_from("<QQq", data, off)
        if (
            (r_info & 0xFFFFFFFF) == 8
            and dr_va <= r_offset < dr_va + dr_sz
            and ro_va <= r_addend < ro_va + ro_sz
        ):
            raw = data[ro_off + (r_addend - ro_va) : ro_off + (r_addend - ro_va) + 48]
            if raw.startswith(b"l1/src/abci/"):
                doff = dr_off + (r_offset - dr_va)
                slen, _ln, _col = struct.unpack_from("<QII", data, doff + 8)
                if 12 <= slen <= 64:
                    path_str = data[
                        ro_off + (r_addend - ro_va) : ro_off + (r_addend - ro_va) + slen
                    ].decode("ascii")
                    if path_str.endswith(".rs"):
                        count += 1
                        files.add(path_str)
    return count, files


def verify_records(
    records: dict,
    data: bytes,
    sections: dict[str, tuple[int, int, int]],
    fdes: dict[int, int],
) -> None:
    tb = records["target_binary"]
    if len(data) != tb["size"]:
        raise AssertionError("binary size mismatch")
    if hashlib.sha256(data).hexdigest() != tb["sha256"]:
        raise AssertionError("binary sha256 mismatch")

    loc_count, obs_files = count_abci_src_locations(data, sections)
    if loc_count != records["location_count"]:
        raise AssertionError(f"location_count mismatch: {loc_count} != {records['location_count']}")
    if sorted(obs_files) != records["observed_source_files"]:
        raise AssertionError(f"observed_source_files mismatch: {sorted(obs_files)}")

    text_va, text_off, text_sz = sections[".text"]
    ro_va, ro_off, ro_sz = sections[".rodata"]

    total_bytes = 0
    seen: set[int] = set()
    for entry in records["abci_src_fdes"]:
        s = int(entry["start"], 16)
        e = int(entry["end"], 16)
        sz = int(entry["size"])
        if s in seen:
            raise AssertionError(f"duplicate FDE 0x{s:x}")
        seen.add(s)
        if e - s != sz or fdes.get(s) != e:
            raise AssertionError(f"FDE mismatch for {entry['role']} at 0x{s:x}")
        total_bytes += sz

    sm = records["summary"]
    if sm["abci_src_fdes"] != len(records["abci_src_fdes"]) or sm["abci_src_fde_bytes"] != total_bytes:
        raise AssertionError("FDE summary mismatch")

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

    for cst in records["rodata_f64_constants"]:
        va = int(cst["va"], 16)
        want = bytes.fromhex(cst["hex"])
        if not (ro_va <= va and va + len(want) <= ro_va + ro_sz):
            raise AssertionError(f"f64 constant out of .rodata: {cst['name']}")
        got = data[ro_off + (va - ro_va) : ro_off + (va - ro_va) + len(want)]
        if got != want:
            raise AssertionError(f"f64 constant mismatch for {cst['name']}: {got.hex()} != {want.hex()}")


def run_negative_controls(
    records: dict,
    data: bytes,
    sections: dict[str, tuple[int, int, int]],
    fdes: dict[int, int],
) -> int:
    mutations = [
        ("bad_loc_count", lambda r: r.update({"location_count": 58})),
        ("bad_fde_end", lambda r: r["abci_src_fdes"][0].update({"end": "0x229b88f", "size": 303})),
        ("bad_opcode", lambda r: r["instruction_anchors"][0].update({"hex": "c744241800040002"})),
        ("bad_literal", lambda r: r["rodata_literals"][0].update({"ascii": "serialized abci statX"})),
    ]
    rejected = 0
    for name, fn in mutations:
        mutated = copy.deepcopy(records)
        fn(mutated)
        try:
            verify_records(mutated, data, sections, fdes)
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
    fdes = load_fde_map()

    verify_records(records, data, sections, fdes)
    sm = records["summary"]
    msg = (
        f"PASS: {sm['source_files']}/4 l1/src/abci files, {sm['locations']}/57 Locations, "
        f"{sm['abci_src_fdes']}/41 FDEs ({sm['abci_src_fde_bytes']} B), "
        f"{len(records['instruction_anchors'])} anchors, {len(records['rodata_literals'])} literals, "
        f"{len(records['rodata_f64_constants'])} f64 constants"
    )
    if args.self_test:
        neg = run_negative_controls(records, data, sections, fdes)
        msg += f", {neg}/{neg} negative controls rejected"
    print(msg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
