#!/usr/bin/env python3
"""Compile lib.rs with rustc 1.95.0 and verify 50 first-party storage/abci FDE byte matches against node #115."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

PACKET_DIR = Path(__file__).resolve().parent
REPO_ROOT = PACKET_DIR.parents[2]
BINARY_PATH = REPO_ROOT / "artifacts" / "node" / "115" / "hl-node"
FDE_TSV = REPO_ROOT / "work" / "index" / "node-115-fde.tsv"
SOURCE_PATH = PACKET_DIR / "lib.rs"
RECORDS_PATH = PACKET_DIR / "records.json"

EXPECTED_BINARY_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
)
EXPECTED_BINARY_SIZE = 105_896_032

# (component, symbol_substring, start_va, end_va, label)
WINDOWS = [
    # storage: IndexedArtifactContentSerde JSON visit_str (2 x 293 B = 586 B)
    ("storage", "storage_indexed_artifact_visit_str_json", 0x1500470, 0x1500595, "storage IndexedArtifactContentSerde JSON visit_str (0x1500470)"),
    ("storage", "storage_indexed_artifact_visit_str_json", 0x57C41A0, 0x57C42C5, "storage IndexedArtifactContentSerde JSON visit_str (0x57c41a0)"),
    # storage: Visitor::expecting (12 x 25 B = 300 B)
    ("storage", "storage_expecting_indexed_artifact_serde", 0x1500A40, 0x1500A59, "storage IndexedArtifactSerde expecting (0x1500a40)"),
    ("storage", "storage_expecting_indexed_artifact_serde", 0x57D19B0, 0x57D19C9, "storage IndexedArtifactSerde expecting (0x57d19b0)"),
    ("storage", "storage_expecting_node_artifact", 0x15A0290, 0x15A02A9, "storage NodeArtifact expecting (0x15a0290)"),
    ("storage", "storage_expecting_node_artifact", 0x5616B50, 0x5616B69, "storage NodeArtifact expecting (0x5616b50)"),
    ("storage", "storage_expecting_evm_db_serde_no_evm_db", 0x25EB5B0, 0x25EB5C9, "storage EvmDbSerde::NoEvmDb expecting (0x25eb5b0)"),
    ("storage", "storage_expecting_evm_db_serde_no_evm_db", 0x38DBB60, 0x38DBB79, "storage EvmDbSerde::NoEvmDb expecting (0x38dbb60)"),
    ("storage", "storage_expecting_evm_db_serde_no_evm_db", 0x50D95E0, 0x50D95F9, "storage EvmDbSerde::NoEvmDb expecting (0x50d95e0)"),
    ("storage", "storage_expecting_evm_db_serde", 0x25EB7C0, 0x25EB7D9, "storage EvmDbSerde expecting (0x25eb7c0)"),
    ("storage", "storage_expecting_evm_db_serde", 0x38DB780, 0x38DB799, "storage EvmDbSerde expecting (0x38db780)"),
    ("storage", "storage_expecting_evm_db_serde", 0x50D93E0, 0x50D93F9, "storage EvmDbSerde expecting (0x50d93e0)"),
    ("storage", "storage_expecting_db_account_info", 0x38DBA40, 0x38DBA59, "storage DbAccountInfo expecting (0x38dba40)"),
    ("storage", "storage_expecting_file_snapshot_l4", 0x27731F0, 0x2773209, "storage FileSnapshotRequest::L4Snapshots expecting (0x27731f0)"),
    # abci: QuorumStatus RMP visit_str (3 x 64 B = 192 B)
    ("abci", "abci_quorum_status_visit_str_rmp", 0x2885DB0, 0x2885DF0, "abci QuorumStatus RMP visit_str (0x2885db0)"),
    ("abci", "abci_quorum_status_visit_str_rmp", 0x3668E30, 0x3668E70, "abci QuorumStatus RMP visit_str (0x3668e30)"),
    ("abci", "abci_quorum_status_visit_str_rmp", 0x535A8F0, 0x535A930, "abci QuorumStatus RMP visit_str (0x535a8f0)"),
    # abci: Visitor::expecting (33 x 25 B = 825 B)
    ("abci", "abci_expecting_abci_state_de", 0x22F5C60, 0x22F5C79, "abci AbciStateDe expecting (0x22f5c60)"),
    ("abci", "abci_expecting_abci_state_de", 0x3C4D7B0, 0x3C4D7C9, "abci AbciStateDe expecting (0x3c4d7b0)"),
    ("abci", "abci_expecting_abci_state_de", 0x5616DD0, 0x5616DE9, "abci AbciStateDe expecting (0x5616dd0)"),
    ("abci", "abci_expecting_cold_hard_quorum_policy", 0x2420960, 0x2420979, "abci ColdHardQuorumPolicy expecting (0x2420960)"),
    ("abci", "abci_expecting_cold_hard_quorum_policy", 0x42297B0, 0x42297C9, "abci ColdHardQuorumPolicy expecting (0x42297b0)"),
    ("abci", "abci_expecting_cold_hard_quorum_policy", 0x53D63D0, 0x53D63E9, "abci ColdHardQuorumPolicy expecting (0x53d63d0)"),
    ("abci", "abci_expecting_noop_hard_quorum_policy", 0x2773C90, 0x2773CA9, "abci NoopHardQuorumPolicy expecting (0x2773c90)"),
    ("abci", "abci_expecting_noop_hard_quorum_policy", 0x4229140, 0x4229159, "abci NoopHardQuorumPolicy expecting (0x4229140)"),
    ("abci", "abci_expecting_noop_hard_quorum_policy", 0x5942450, 0x5942469, "abci NoopHardQuorumPolicy expecting (0x5942450)"),
    ("abci", "abci_expecting_hash_hard_quorum", 0x27731B0, 0x27731C9, "abci HashHardQuorum expecting (0x27731b0)"),
    ("abci", "abci_expecting_hash_hard_quorum", 0x4229120, 0x4229139, "abci HashHardQuorum expecting (0x4229120)"),
    ("abci", "abci_expecting_hash_hard_quorum", 0x5B09050, 0x5B09069, "abci HashHardQuorum expecting (0x5b09050)"),
    ("abci", "abci_expecting_hardfork_hash_tracker", 0x27737D0, 0x27737E9, "abci HardforkHashTracker expecting (0x27737d0)"),
    ("abci", "abci_expecting_hardfork_hash_tracker", 0x4229100, 0x4229119, "abci HardforkHashTracker expecting (0x4229100)"),
    ("abci", "abci_expecting_hardfork_hash_tracker", 0x5B094D0, 0x5B094E9, "abci HardforkHashTracker expecting (0x5b094d0)"),
    ("abci", "abci_expecting_hash_signature_tracker", 0x2773B90, 0x2773BA9, "abci HashSignatureTracker expecting (0x2773b90)"),
    ("abci", "abci_expecting_hash_signature_tracker", 0x4228F10, 0x4228F29, "abci HashSignatureTracker expecting (0x4228f10)"),
    ("abci", "abci_expecting_hash_signature_tracker", 0x5B09030, 0x5B09049, "abci HashSignatureTracker expecting (0x5b09030)"),
    ("abci", "abci_expecting_quorum_status", 0x292C9D0, 0x292C9E9, "abci QuorumStatus expecting (0x292c9d0)"),
    ("abci", "abci_expecting_quorum_status", 0x36CD050, 0x36CD069, "abci QuorumStatus expecting (0x36cd050)"),
    ("abci", "abci_expecting_quorum_status", 0x53D5D70, 0x53D5D89, "abci QuorumStatus expecting (0x53d5d70)"),
    ("abci", "abci_expecting_abci_digest", 0x292D2B0, 0x292D2C9, "abci AbciDigest expecting (0x292d2b0)"),
    ("abci", "abci_expecting_abci_digest", 0x41C6970, 0x41C6989, "abci AbciDigest expecting (0x41c6970)"),
    ("abci", "abci_expecting_abci_digest", 0x53D5AB0, 0x53D5AC9, "abci AbciDigest expecting (0x53d5ab0)"),
    ("abci", "abci_expecting_vote_l1_hash_action", 0x292DD70, 0x292DD89, "abci VoteL1HashAction expecting (0x292dd70)"),
    ("abci", "abci_expecting_vote_l1_hash_action", 0x4454BA0, 0x4454BB9, "abci VoteL1HashAction expecting (0x4454ba0)"),
    ("abci", "abci_expecting_vote_l1_hash_action", 0x5942830, 0x5942849, "abci VoteL1HashAction expecting (0x5942830)"),
    ("abci", "abci_expecting_vote_abci_digest_action", 0x29B03B0, 0x29B03C9, "abci VoteAbciDigestAction expecting (0x29b03b0)"),
    ("abci", "abci_expecting_vote_abci_digest_action", 0x4459FD0, 0x4459FE9, "abci VoteAbciDigestAction expecting (0x4459fd0)"),
    ("abci", "abci_expecting_vote_abci_digest_action", 0x5941E70, 0x5941E89, "abci VoteAbciDigestAction expecting (0x5941e70)"),
    ("abci", "abci_expecting_lt_hash", 0x36CD190, 0x36CD1A9, "abci LtHash expecting (0x36cd190)"),
    ("abci", "abci_expecting_lt_hashes", 0x38DBB80, 0x38DBB99, "abci LtHashes expecting (0x38dbb80)"),
    ("abci", "abci_expecting_cold_quorum_l1_hash", 0x57D1970, 0x57D1989, "abci ColdQuorumL1Hash expecting (0x57d1970)"),
]


def parse_elf_sections(blob: bytes) -> list[tuple[int, str, int, int, int, int, int, int]]:
    e_shoff = struct.unpack_from("<Q", blob, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", blob, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", blob, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", blob, 0x3E)[0]
    shstr_off = struct.unpack_from("<Q", blob, e_shoff + e_shstrndx * e_shentsize + 24)[0]
    out = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name, sh_type, _sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info = (
            struct.unpack_from("<IIQQQQII", blob, off)
        )
        end = blob.find(b"\0", shstr_off + sh_name)
        name = blob[shstr_off + sh_name : end].decode("latin1")
        out.append((i, name, sh_type, sh_addr, sh_offset, sh_size, sh_link, sh_info))
    return out


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


def compile_object() -> tuple[bytes, str]:
    ver = subprocess.check_output(["rustc", "+1.95.0", "--version"], text=True).strip()
    with tempfile.TemporaryDirectory(prefix="re009-byte-match-") as tmpdir:
        obj_path = Path(tmpdir) / "storage_abci_bytes.o"
        subprocess.run(
            [
                "rustc",
                "+1.95.0",
                "--edition=2021",
                "--crate-type=rlib",
                "--crate-name=storage_abci_byte_matches",
                "-C",
                "opt-level=3",
                "-C",
                "overflow-checks=yes",
                "--emit=obj",
                "-o",
                str(obj_path),
                str(SOURCE_PATH),
            ],
            check=True,
        )
        return obj_path.read_bytes(), ver


def extract_compiled_symbols(obj: bytes) -> list[tuple[str, bytes, list[int]]]:
    secs = parse_elf_sections(obj)
    symtab = [s for s in secs if s[2] == 2][0]
    strtab = secs[symtab[6]]
    relas_by_sec: dict[int, list[int]] = {}
    for s in secs:
        if s[2] == 4:
            relas_by_sec[s[7]] = [
                struct.unpack_from("<Q", obj, o)[0]
                for o in range(s[4], s[4] + s[5], 24)
            ]
    out = []
    for o in range(symtab[4], symtab[4] + symtab[5], 24):
        st_name, _st_info, _st_other, st_shndx, st_value, st_size = struct.unpack_from(
            "<IBBHQQ", obj, o
        )
        if st_size == 0 or st_shndx >= len(secs):
            continue
        end = obj.find(b"\0", strtab[4] + st_name)
        name = obj[strtab[4] + st_name : end].decode("latin1")
        sec = secs[st_shndx]
        code = obj[sec[4] + st_value : sec[4] + st_value + st_size]
        rels = sorted(
            r_off - st_value
            for r_off in relas_by_sec.get(st_shndx, [])
            if st_value <= r_off < st_value + st_size
        )
        out.append((name, code, rels))
    return out


def match_symbol(
    syms: list[tuple[str, bytes, list[int]]], needle: str
) -> tuple[str, bytes, list[int]]:
    token = f"{len(needle)}{needle}17h"
    matches = [s for s in syms if token in s[0]]
    if len(matches) != 1:
        raise ValueError(f"expected 1 symbol matching {token!r}, found {len(matches)}: {[m[0] for m in matches]}")
    return matches[0]


def build_records(hl_data: bytes) -> dict[str, object]:
    hl_secs = {s[1]: s for s in parse_elf_sections(hl_data)}
    t_addr, t_off = hl_secs[".text"][3], hl_secs[".text"][4]
    fde_map = load_fde_map()
    obj_bytes, rustc_version = compile_object()
    syms = extract_compiled_symbols(obj_bytes)

    rows = []
    for comp, sym_needle, start_va, end_va, label in WINDOWS:
        if fde_map and fde_map.get(start_va) != end_va:
            raise ValueError(f"FDE mismatch for {label}: index has {fde_map.get(start_va)}, expected 0x{end_va:x}")
        sym_name, compiled, rels = match_symbol(syms, sym_needle)
        target = hl_data[t_off + (start_va - t_addr) : t_off + (end_va - t_addr)]
        if len(compiled) != len(target):
            raise ValueError(f"length mismatch for {label}: compiled={len(compiled)} target={len(target)}")
        mask = bytearray(len(compiled))
        for r_off in rels:
            for k in range(4):
                if r_off + k < len(mask):
                    mask[r_off + k] = 1
        mismatches = [
            i for i in range(len(compiled)) if not mask[i] and compiled[i] != target[i]
        ]
        if mismatches:
            raise ValueError(f"non-relocation mismatches for {label}: {mismatches[:8]}")
        raw_equal = sum(1 for a, b in zip(compiled, target) if a == b)
        rows.append(
            {
                "component": comp,
                "label": label,
                "symbol_key": sym_needle,
                "start_va": f"0x{start_va:x}",
                "end_va": f"0x{end_va:x}",
                "size": len(target),
                "raw_equal_bytes": raw_equal,
                "relocation_offsets": rels,
                "relocation_qualified": True,
                "target_sha256": hashlib.sha256(target).hexdigest(),
                "compiled_sha256": hashlib.sha256(compiled).hexdigest(),
            }
        )

    return {
        "schema_version": 1,
        "work_item": "RE-009-node115-storage-abci-byte-matches",
        "target_binary": {
            "path": "artifacts/node/115/hl-node",
            "size": len(hl_data),
            "sha256": hashlib.sha256(hl_data).hexdigest(),
        },
        "source_sha256": hashlib.sha256(SOURCE_PATH.read_bytes()).hexdigest(),
        "rustc_version": rustc_version,
        "summary": {
            "windows": len(rows),
            "total_bytes": sum(r["size"] for r in rows),
            "raw_equal_bytes": sum(r["raw_equal_bytes"] for r in rows),
            "storage_windows": sum(1 for r in rows if r["component"] == "storage"),
            "storage_bytes": sum(r["size"] for r in rows if r["component"] == "storage"),
            "abci_windows": sum(1 for r in rows if r["component"] == "abci"),
            "abci_bytes": sum(r["size"] for r in rows if r["component"] == "abci"),
        },
        "windows": rows,
    }


def verify_records(records: dict[str, object], hl_data: bytes, rebuild: bool = True) -> None:
    tb = records["target_binary"]
    if tb["sha256"] != EXPECTED_BINARY_SHA256 or tb["size"] != EXPECTED_BINARY_SIZE:
        raise ValueError("target_binary metadata mismatch")
    if hashlib.sha256(hl_data).hexdigest() != EXPECTED_BINARY_SHA256:
        raise ValueError("on-disk binary SHA-256 mismatch")
    if records["source_sha256"] != hashlib.sha256(SOURCE_PATH.read_bytes()).hexdigest():
        raise ValueError("source_sha256 mismatch")

    rows = records["windows"]
    if len(rows) != len(WINDOWS):
        raise ValueError(f"expected {len(WINDOWS)} windows, got {len(rows)}")
    seen = set()
    for r in rows:
        key = (r["start_va"], r["end_va"])
        if key in seen:
            raise ValueError(f"duplicate window {key}")
        seen.add(key)

    if rebuild:
        rebuilt = build_records(hl_data)
        if rebuilt["windows"] != records["windows"] or rebuilt["summary"] != records["summary"]:
            raise ValueError("rebuilt compiled-byte records diverge from committed records.json")
    else:
        hl_secs = {s[1]: s for s in parse_elf_sections(hl_data)}
        t_addr, t_off = hl_secs[".text"][3], hl_secs[".text"][4]
        for r in rows:
            s_va = int(r["start_va"], 16)
            e_va = int(r["end_va"], 16)
            target = hl_data[t_off + (s_va - t_addr) : t_off + (e_va - t_addr)]
            if len(target) != r["size"] or hashlib.sha256(target).hexdigest() != r["target_sha256"]:
                raise ValueError(f"target bytes mismatch for {r['label']}")
            if not r["relocation_qualified"]:
                raise ValueError(f"window not relocation-qualified: {r['label']}")


def run_negative_controls(records: dict[str, object], hl_data: bytes) -> int:
    mutations = []

    m1 = copy.deepcopy(records)
    m1["source_sha256"] = "0" * 64
    mutations.append(("corrupted_source_sha256", m1))

    m2 = copy.deepcopy(records)
    m2["windows"][0]["target_sha256"] = "f" * 64
    mutations.append(("corrupted_target_sha256", m2))

    m3 = copy.deepcopy(records)
    m3["windows"][0]["relocation_qualified"] = False
    mutations.append(("relocation_qualified_false", m3))

    m4 = copy.deepcopy(records)
    m4["windows"][1] = copy.deepcopy(m4["windows"][0])
    mutations.append(("duplicate_window", m4))

    for name, mutated in mutations:
        try:
            verify_records(mutated, hl_data, rebuild=False)
        except ValueError:
            continue
        raise AssertionError(f"negative control {name} was unexpectedly accepted")
    return len(mutations)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="Compile and write records.json")
    parser.add_argument("--self-test", action="store_true", help="Run negative controls")
    args = parser.parse_args()

    hl_data = BINARY_PATH.read_bytes()
    if args.write:
        records = build_records(hl_data)
        RECORDS_PATH.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
        verify_records(records, hl_data, rebuild=False)
    else:
        records = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))
        verify_records(records, hl_data, rebuild=True)

    neg = run_negative_controls(records, hl_data) if args.self_test else 0
    s = records["summary"]
    print(
        f"RE-009-node115-storage-abci-byte-matches verified: "
        f"{s['windows']}/{s['windows']} relocation-qualified windows, "
        f"{s['total_bytes']} B ({s['raw_equal_bytes']} raw-equal), "
        f"storage={s['storage_windows']}w/{s['storage_bytes']}B, "
        f"abci={s['abci_windows']}w/{s['abci_bytes']}B"
        + (f", {neg}/{neg} negative controls rejected." if args.self_test else ".")
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
