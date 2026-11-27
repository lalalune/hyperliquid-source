#!/usr/bin/env python3
"""Static verifier for RE-009-node115-rocksdb-profiles-and-apply-block-lifecycle."""

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
        name = data[shstr_off + sh_name : end].decode("ascii")
        sections[name] = (sh_addr, sh_offset, sh_size)
    return sections


def load_fde_map() -> dict[int, int]:
    fdes: dict[int, int] = {}
    with FDE_TSV_PATH.open("r", encoding="utf-8") as fh:
        for line in fh:
            parts = line.strip().split("\t")
            if len(parts) >= 2 and parts[0].startswith("0x"):
                fdes[int(parts[0], 16)] = int(parts[1], 16)
    return fdes


def verify_records(records: dict, data: bytes, sections: dict[str, tuple[int, int, int]], fdes: dict[int, int]) -> None:
    target = records["target_binary"]
    if len(data) != target["size"]:
        raise AssertionError(f"size mismatch: {len(data)} != {target['size']}")
    actual_sha = hashlib.sha256(data).hexdigest()
    if actual_sha != target["sha256"]:
        raise AssertionError(f"sha256 mismatch: {actual_sha} != {target['sha256']}")

    text_va, text_off, text_sz = sections[".text"]
    ro_va, ro_off, ro_sz = sections[".rodata"]

    for entry in records["fdes"]:
        s = int(entry["start"], 16)
        e = int(entry["end"], 16)
        sz = int(entry["size"])
        if e - s != sz:
            raise AssertionError(f"FDE size math mismatch for {entry['name']}")
        if fdes.get(s) != e:
            raise AssertionError(f"FDE mismatch for {entry['name']}: expected 0x{e:x}, got {fdes.get(s)}")

    for anc in records["instruction_anchors"]:
        va = int(anc["va"], 16)
        want = bytes.fromhex(anc["hex"])
        if not (text_va <= va and va + len(want) <= text_va + text_sz):
            raise AssertionError(f"anchor out of .text: {anc['name']}")
        got = data[text_off + (va - text_va) : text_off + (va - text_va) + len(want)]
        if got != want:
            raise AssertionError(f"anchor byte mismatch for {anc['name']} at 0x{va:x}: {got.hex()} != {want.hex()}")

    for lit in records["rodata_literals"]:
        va = int(lit["va"], 16)
        want = lit["ascii"].encode("ascii")
        if not (ro_va <= va and va + len(want) <= ro_va + ro_sz):
            raise AssertionError(f"literal out of .rodata: {lit['name']}")
        got = data[ro_off + (va - ro_va) : ro_off + (va - ro_va) + len(want)]
        if got != want:
            raise AssertionError(f"literal mismatch for {lit['name']} at 0x{va:x}: {got!r} != {want!r}")

    c = records["constants"]
    if ((c["tcp_rocksdb_shr11_threshold"] + 1) << 11) != c["tcp_rocksdb_max_bytes"]:
        raise AssertionError("100 GB TCP RocksDB threshold arithmetic mismatch")
    if c["core_default_cache_bytes"] != 8 * c["evm_default_cache_bytes"]:
        raise AssertionError("core vs evm default cache ratio mismatch")
    if c["core_block_size_bytes"] != 2 * c["evm_block_size_bytes"]:
        raise AssertionError("core vs evm block size ratio mismatch")


def run_negative_controls(records: dict, data: bytes, sections: dict[str, tuple[int, int, int]], fdes: dict[int, int]) -> int:
    mutations = [
        ("bad_fde_end", lambda r: r["fdes"][0].update({"end": "0x4524adc", "size": 1148})),
        ("bad_opcode_anchor", lambda r: r["instruction_anchors"][0].update({"hex": "bf00090000"})),
        ("bad_rodata_literal", lambda r: r["rodata_literals"][0].update({"ascii": "ExchangX"})),
        ("bad_100gb_constant", lambda r: r["constants"].update({"tcp_rocksdb_max_bytes": 100000000001})),
    ]
    rejected = 0
    for label, mutate in mutations:
        mutated = copy.deepcopy(records)
        mutate(mutated)
        try:
            verify_records(mutated, data, sections, fdes)
        except AssertionError:
            rejected += 1
        else:
            raise AssertionError(f"negative control {label} was NOT rejected")
    return rejected


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    records = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))
    bin_path = REPO / records["target_binary"]["path"]
    data = bin_path.read_bytes()
    sections = parse_elf_sections(data)
    fdes = load_fde_map()

    verify_records(records, data, sections, fdes)
    msg = (
        f"PASS: {len(records['fdes'])} FDEs, {len(records['instruction_anchors'])} anchors, "
        f"{len(records['rodata_literals'])} literals"
    )
    if args.self_test:
        neg = run_negative_controls(records, data, sections, fdes)
        msg += f", {neg}/{neg} negative controls rejected"
    print(msg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
