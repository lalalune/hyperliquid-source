#!/usr/bin/env python3
"""Verify RE-009 node #115 LtHash homomorphic BLAKE3-XOF math and hardfork version validation."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import struct
import sys
from pathlib import Path

PACKET_DIR = Path(__file__).resolve().parent
REPO_ROOT = PACKET_DIR.parents[2]
BINARY_PATH = REPO_ROOT / "artifacts" / "node" / "115" / "hl-node"
FDE_TSV = REPO_ROOT / "work" / "index" / "node-115-fde.tsv"
RECORDS_PATH = PACKET_DIR / "records.json"

EXPECTED_BINARY_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
)
EXPECTED_BINARY_SIZE = 105_896_032

EXPECTED_FDES = [
    ("lthash_serialize", 0x36C5B50, 0x36C5CE5),
    ("lthash_xof_expand", 0x36C6100, 0x36C628E),
    ("lthash_remove_1", 0x3C27A20, 0x3C27B98),
    ("lthash_remove_2", 0x3C27BA0, 0x3C27D08),
    ("lthash_rebuild_checksum_1", 0x3C27F30, 0x3C28210),
    ("lthash_update_replace_1", 0x3C287D0, 0x3C28A81),
    ("blake3_xof_fill_step", 0x1609E70, 0x1609F57),
    ("hardfork_version_validate", 0x595AFF0, 0x595B1A0),
]

EXPECTED_ANCHORS = [
    ("lthash_xof_fill_0x800", 0x36C61F0, "488d7c2408488db42480000000e85e49f4fdc644247800488d7c2408488db42400080000ba00080000ff1559b7e102"),
    ("lthash_ser_n_elements", 0x36C5BD3, "488d35ba7e0dfdba0a000000"),
    ("lthash_ser_n_bytes", 0x36C5C1E, "488d35797e0dfdba07000000"),
    ("lthash_ser_hash_0x800", 0x36C5C5A, "488d355342d9fcba040000004c89ffe8a204b0004883f8027546488d7c2408b9000800004c89fe4c89f2"),
    ("lthash_mix_out_be_psubw", 0x3C27B10, "f3430f6f8466f8000000660f6fc8660f71d108660f71f008660febc1f3420f6f4c6440660f6fd1660f71d208660f71f108660febca660ff9c1660f6fc8660f71d108660f71f008660febc1f3430f7f8466f80000004983c4084981fc00040000759e"),
    ("lthash_mix_in_be_paddw", 0x3C289D0, "f30f6f0443660f6fc8660f71d108660f71f008660febc1f30f6f8c4468ffffff660f6fd1660f71d208660f71f108660febca660ffdc8660f6fc1660f71d008660f71f108660febc8f30f7f0c434883c008483d7c04000075a7"),
    ("lthash_rebuild_batch_1m", 0x3C27FD4, "ba40420f00"),
    ("lthash_checksum_0x800", 0x3C2808D, "488d7c2470488db42488080000ba00080000ff156b748b02488d7c2410488d742470ff1563748b02"),
    ("hardfork_version_cmp", 0x595B0FA, "488b44244048891c2448894424084839c375054531f6eb37"),
    ("hardfork_version_err_lea", 0x595B135, "488d3d3d6cadfa"),
]

EXPECTED_LITERALS = [
    ("lthashes_fields_rodata", 0x793711, "accounts_hashcontracts_hashstorage_hash"),
    ("lthash_fields_n_elem_bytes", 0x793DC1, "n_elementsn_bytes"),
    ("lthash_field_hash", 0x459EB4, "hash"),
    ("hardfork_unexpected_tpl", 0x431D7A, "unexpected state hardfork version: "),
]


def parse_elf_sections(data: bytes) -> dict[str, tuple[int, int, int]]:
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
    shstr_off = struct.unpack_from("<Q", data, e_shoff + e_shstrndx * e_shentsize + 24)[0]
    secs: dict[str, tuple[int, int, int]] = {}
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name, _sh_type, _sh_flags, sh_addr, sh_offset, sh_size = struct.unpack_from(
            "<IIQQQQ", data, off
        )
        end = data.find(b"\0", shstr_off + sh_name)
        secs[data[shstr_off + sh_name : end].decode("latin1")] = (sh_addr, sh_offset, sh_size)
    return secs


def load_fde_map() -> dict[int, int]:
    fdes: dict[int, int] = {}
    if not FDE_TSV.exists():
        return fdes
    with FDE_TSV.open("r", encoding="utf-8") as fh:
        fh.readline()
        for line in fh:
            parts = line.strip().split("\t")
            if len(parts) >= 2:
                s = int(parts[0], 16) if parts[0].startswith("0x") else int(parts[0])
                e = int(parts[1], 16) if parts[1].startswith("0x") else int(parts[1])
                fdes[s] = e
    return fdes


def read_section_bytes(
    data: bytes, secs: dict[str, tuple[int, int, int]], sec_name: str, va: int, length: int
) -> bytes:
    sh_addr, sh_offset, sh_size = secs[sec_name]
    rel = va - sh_addr
    if rel < 0 or rel + length > sh_size:
        raise ValueError(f"VA 0x{va:x}+{length} outside {sec_name}")
    return data[sh_offset + rel : sh_offset + rel + length]


def build_records(data: bytes) -> dict[str, object]:
    secs = parse_elf_sections(data)
    fde_map = load_fde_map()
    fdes_out = []
    for label, start, end in EXPECTED_FDES:
        if fde_map and fde_map.get(start) != end:
            raise ValueError(f"FDE mismatch for {label}: {fde_map.get(start)} != 0x{end:x}")
        body = read_section_bytes(data, secs, ".text", start, end - start)
        fdes_out.append(
            {
                "label": label,
                "start_va": f"0x{start:x}",
                "end_va": f"0x{end:x}",
                "size": end - start,
                "sha256": hashlib.sha256(body).hexdigest(),
            }
        )
    anchors_out = [
        {
            "label": label,
            "va": f"0x{va:x}",
            "bytes_hex": read_section_bytes(data, secs, ".text", va, len(hex_s) // 2).hex(),
        }
        for label, va, hex_s in EXPECTED_ANCHORS
    ]
    literals_out = [
        {
            "label": label,
            "va": f"0x{va:x}",
            "text": read_section_bytes(data, secs, ".rodata", va, len(txt)).decode("ascii"),
        }
        for label, va, txt in EXPECTED_LITERALS
    ]
    return {
        "schema_version": 1,
        "work_item": "RE-009-node115-lthash-homomorphic-and-hardfork-version",
        "target_binary": {
            "path": "artifacts/node/115/hl-node",
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        },
        "lthash_spec": {
            "hash_bytes": 2048,
            "lanes": 1024,
            "lane_endianness": "big_endian_u16",
            "xof_algorithm": "blake3_unkeyed_xof",
            "checksum_algorithm": "blake3_unkeyed_32b",
            "rebuild_batch_size": 1_000_000,
            "lthash_wire_fields": ["n_elements", "n_bytes", "hash"],
            "lthashes_wire_fields": ["accounts_hash", "contracts_hash", "storage_hash"],
        },
        "fdes": fdes_out,
        "anchors": anchors_out,
        "literals": literals_out,
    }


def verify_records(records: dict[str, object], data: bytes) -> None:
    tb = records["target_binary"]
    if tb["sha256"] != EXPECTED_BINARY_SHA256 or tb["size"] != EXPECTED_BINARY_SIZE:
        raise ValueError("target_binary metadata mismatch")
    if hashlib.sha256(data).hexdigest() != EXPECTED_BINARY_SHA256:
        raise ValueError("on-disk binary SHA-256 mismatch")

    spec = records["lthash_spec"]
    if spec["hash_bytes"] != 2048 or spec["lanes"] != 1024 or spec["lane_endianness"] != "big_endian_u16":
        raise ValueError("lthash_spec mismatch")

    secs = parse_elf_sections(data)
    if len(records["fdes"]) != len(EXPECTED_FDES):
        raise ValueError("FDE count mismatch")
    for row, (label, start, end) in zip(records["fdes"], EXPECTED_FDES):
        if row["label"] != label or int(row["start_va"], 16) != start or int(row["end_va"], 16) != end:
            raise ValueError(f"FDE descriptor mismatch for {label}")
        body = read_section_bytes(data, secs, ".text", start, end - start)
        if hashlib.sha256(body).hexdigest() != row["sha256"]:
            raise ValueError(f"FDE sha256 mismatch for {label}")

    if len(records["anchors"]) != len(EXPECTED_ANCHORS):
        raise ValueError("anchor count mismatch")
    for row, (label, va, hex_s) in zip(records["anchors"], EXPECTED_ANCHORS):
        if row["label"] != label or int(row["va"], 16) != va or row["bytes_hex"] != hex_s:
            raise ValueError(f"anchor mismatch for {label}")
        actual = read_section_bytes(data, secs, ".text", va, len(hex_s) // 2).hex()
        if actual != hex_s:
            raise ValueError(f"binary anchor mismatch for {label}")

    if len(records["literals"]) != len(EXPECTED_LITERALS):
        raise ValueError("literal count mismatch")
    for row, (label, va, txt) in zip(records["literals"], EXPECTED_LITERALS):
        if row["label"] != label or int(row["va"], 16) != va or row["text"] != txt:
            raise ValueError(f"literal mismatch for {label}")
        actual = read_section_bytes(data, secs, ".rodata", va, len(txt)).decode("ascii")
        if actual != txt:
            raise ValueError(f"binary literal mismatch for {label}")


def run_negative_controls(records: dict[str, object], data: bytes) -> int:
    mutations = []
    m1 = copy.deepcopy(records)
    m1["lthash_spec"]["lane_endianness"] = "little_endian_u16"
    mutations.append(("wrong_endianness", m1))

    m2 = copy.deepcopy(records)
    m2["fdes"][1]["sha256"] = "0" * 64
    mutations.append(("corrupted_fde_sha256", m2))

    m3 = copy.deepcopy(records)
    m3["anchors"][4]["bytes_hex"] = "90" * (len(m3["anchors"][4]["bytes_hex"]) // 2)
    mutations.append(("corrupted_be_psubw_anchor", m3))

    m4 = copy.deepcopy(records)
    m4["literals"][0]["text"] = "X" * len(m4["literals"][0]["text"])
    mutations.append(("corrupted_lthashes_literal", m4))

    for name, mutated in mutations:
        try:
            verify_records(mutated, data)
        except ValueError:
            continue
        raise AssertionError(f"negative control {name} was unexpectedly accepted")
    return len(mutations)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    data = BINARY_PATH.read_bytes()
    if args.write:
        records = build_records(data)
        verify_records(records, data)
        RECORDS_PATH.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    else:
        records = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))
        verify_records(records, data)

    neg = run_negative_controls(records, data) if args.self_test else 0
    print(
        f"RE-009-node115-lthash-homomorphic-and-hardfork-version verified: "
        f"{len(EXPECTED_FDES)} FDEs, {len(EXPECTED_ANCHORS)} anchors, {len(EXPECTED_LITERALS)} literals"
        + (f", {neg}/{neg} negative controls rejected." if args.self_test else ".")
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
