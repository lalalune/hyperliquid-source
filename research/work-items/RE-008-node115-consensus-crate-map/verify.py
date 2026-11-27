#!/usr/bin/env python3
"""Verify complete node #115 consensus crate source-path/Location/FDE inventory,
5-variant signing payload serializer (`0x5823db0`), and `try_propose` guards
(`0x2e13ea0`) (`RE-008-node115-consensus-crate-map`).

Target: Linux x86-64 node #115 (`artifacts/node/115/hl-node`,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
Static binary analysis only; never executes captured binaries.
"""

from __future__ import annotations

import argparse
import bisect
import copy
import hashlib
import json
import re
import struct
import sys
from pathlib import Path
from typing import Any

import capstone

ROOT = Path(__file__).resolve().parents[3]
TARGET_BIN = ROOT / "artifacts/node/115/hl-node"
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
PACKET_DIR = Path(__file__).resolve().parent
RECORDS_PATH = PACKET_DIR / "records.json"

sys.path.insert(0, str(ROOT / "tools"))
import elf_index  # noqa: E402

EXPECTED_CONSENSUS_FILES = [
    "node/src/consensus/config.rs",
    "node/src/consensus/execution_state.rs",
    "node/src/consensus/heartbeat_tracker.rs",
    "node/src/consensus/latency_samplers.rs",
    "node/src/consensus/liner.rs",
    "node/src/consensus/mempool.rs",
    "node/src/consensus/network.rs",
    "node/src/consensus/node_ips.rs",
    "node/src/consensus/rpc.rs",
    "node/src/consensus/server.rs",
    "node/src/consensus/signature_tracker.rs",
    "node/src/consensus/signed.rs",
    "node/src/consensus/state.rs",
    "node/src/consensus/timer.rs",
    "node/src/consensus/types.rs",
    "node/src/consensus/validator_set.rs",
    "node/src/consensus/validator_stakes.rs",
]

CORE_FUNCTIONS = [
    ("signed_msg_serialize", 0x5823DB0, 0x58241E1),
    ("var0_block_serialize", 0x5967060, 0x596728E),
    ("var1_vote_serialize", 0x5966B90, 0x5966CC1),
    ("var2_timeout_serialize", 0x5967D90, 0x5967E75),
    ("var3_status_serialize", 0x5B561E0, 0x5B56317),
    ("var4_peer_serialize", 0x5B5B360, 0x5B5B40F),
    ("try_propose", 0x2E13EA0, 0x2E153C9),
    ("proposer_selection", 0x595CB30, 0x595E5B8),
]

WINDOWS = [
    ("msg_ser_jt_dispatch", "signed_msg_serialize", 0x5823DD4, 0x5823DF8),
    ("msg_ser_tags", "signed_msg_serialize", 0x5823F82, 0x582405A),
    ("var1_vote_fields", "var1_vote_serialize", 0x5966BA4, 0x5966C57),
    ("var2_timeout_fields", "var2_timeout_serialize", 0x5967DA2, 0x5967E1F),
    ("try_propose_guards", "try_propose", 0x2E14036, 0x2E140F9),
]

JUMP_TABLES = [
    ("jt_msg_size", 0x935C44, 5, ["0x5823df8", "0x5823f00", "0x5823e67", "0x5823e86", "0x5823e1b"]),
    ("jt_msg_ser", 0x935C58, 5, ["0x5823f82", "0x5824031", "0x5823fdb", "0x5824006", "0x5823fb0"]),
]


class ElfImage:
    def __init__(self, path: Path) -> None:
        self.data = path.read_bytes()
        self.sha256 = hashlib.sha256(self.data).hexdigest()
        if self.sha256 != TARGET_SHA256:
            raise ValueError(f"target SHA-256 mismatch: {self.sha256}")
        self.secs = {s["name"]: s for s in elf_index.sections(self.data)}

    def read_va(self, section: str, va: int, size: int) -> bytes:
        s = self.secs[section]
        start = s["address"]
        end = start + s["size"]
        if not (start <= va and va + size <= end):
            raise ValueError(f"VA range 0x{va:x}..0x{va+size:x} outside {section}")
        off = s["offset"] + (va - start)
        return self.data[off : off + size]


def load_fdes() -> tuple[list[tuple[int, int]], list[int], dict[int, int]]:
    tsv = ROOT / "work/index/node-115-fde.tsv"
    fdes: list[tuple[int, int]] = []
    by_start: dict[int, int] = {}
    with tsv.open("r", encoding="utf-8") as fh:
        fh.readline()
        for line in fh:
            parts = line.strip().split("\t")
            if len(parts) >= 2:
                s, e = int(parts[0], 16), int(parts[1], 16)
                fdes.append((s, e))
                by_start[s] = e
    fdes.sort()
    return fdes, [x[0] for x in fdes], by_start


def disasm_window(img: ElfImage, start: int, end: int) -> tuple[bytes, list[dict[str, Any]]]:
    raw = img.read_va(".text", start, end - start)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    rows: list[dict[str, Any]] = []
    pos = start
    for insn in md.disasm(raw, start):
        if insn.address != pos:
            raise ValueError(f"gap at 0x{pos:x} vs 0x{insn.address:x}")
        rows.append(
            {
                "va": f"0x{insn.address:x}",
                "size": insn.size,
                "bytes": insn.bytes.hex(),
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
            }
        )
        pos += insn.size
    if pos != end:
        raise ValueError(f"window 0x{start:x}..0x{end:x} ended at 0x{pos:x}")
    return raw, rows


def scan_consensus_inventory(
    img: ElfImage, fdes: list[tuple[int, int]], starts: list[int]
) -> dict[str, Any]:
    ro = img.secs[".rodata"]
    ro_addr = ro["address"]
    ro_bytes = img.data[ro["offset"] : ro["offset"] + ro["size"]]
    relro = img.secs[".data.rel.ro"]
    relro_addr = relro["address"]
    rela = img.secs[".rela.dyn"]
    rela_bytes = img.data[rela["offset"] : rela["offset"] + rela["size"]]
    text = img.secs[".text"]
    text_addr = text["address"]
    text_bytes = img.data[text["offset"] : text["offset"] + text["size"]]

    def find_fde(va: int) -> tuple[int, int] | None:
        i = bisect.bisect_right(starts, va) - 1
        if i >= 0 and fdes[i][0] <= va < fdes[i][1]:
            return fdes[i]
        return None

    str_entries: dict[tuple[int, int], str] = {}
    for m in re.finditer(rb"node/src/consensus/[a-zA-Z0-9_./-]+\.rs", ro_bytes):
        path_str = m.group(0).decode("ascii")
        str_entries[(ro_addr + m.start(), len(path_str))] = path_str

    str_va_set = {va for va, _ in str_entries}
    loc_map: dict[int, tuple[str, int, int]] = {}
    for off in range(0, len(rela_bytes), 24):
        r_off, r_info, r_add = struct.unpack_from("<QQq", rela_bytes, off)
        if r_add in str_va_set and (r_info & 0xFFFFFFFF) == 8:
            if relro_addr <= r_off < relro_addr + relro["size"] - 16:
                ro_off = relro["offset"] + (r_off - relro_addr)
                length, line, col = struct.unpack_from("<QII", img.data, ro_off + 8)
                if (r_add, length) in str_entries:
                    loc_map[r_off] = (str_entries[(r_add, length)], line, col)

    loc_fdes: dict[int, set[tuple[int, int]]] = {va: set() for va in loc_map}
    pos = 1
    limit = len(text_bytes) - 6
    while True:
        i = text_bytes.find(b"\x8d", pos, limit)
        if i == -1:
            break
        pos = i + 1
        if text_bytes[i - 1] in (0x48, 0x4C) and (text_bytes[i + 1] & 0xC7) == 0x05:
            disp = struct.unpack_from("<i", text_bytes, i + 2)[0]
            tgt = text_addr + i - 1 + 7 + disp
            if tgt in loc_fdes:
                fde = find_fde(text_addr + i - 1)
                if fde is not None:
                    loc_fdes[tgt].add(fde)

    files_out = []
    all_distinct_fdes: set[tuple[int, int]] = set()
    for (str_va, str_len), fname in sorted(str_entries.items(), key=lambda x: x[1]):
        file_locs = sorted(
            [(loc_va, ln, col) for loc_va, (fn, ln, col) in loc_map.items() if fn == fname],
            key=lambda x: (x[1], x[2], x[0]),
        )
        file_fdes = sorted({fde for loc_va, _, _ in file_locs for fde in loc_fdes[loc_va]})
        all_distinct_fdes.update(file_fdes)
        files_out.append(
            {
                "path": fname,
                "rodata_va": f"0x{str_va:x}",
                "rodata_len": str_len,
                "location_count": len(file_locs),
                "locations": [
                    {"va": f"0x{va:x}", "line": ln, "col": col} for va, ln, col in file_locs
                ],
                "fde_count": len(file_fdes),
                "fdes": [
                    {"start": f"0x{s:x}", "end": f"0x{e:x}", "size": e - s} for s, e in file_fdes
                ],
            }
        )

    return {
        "source_file_count": len(files_out),
        "total_locations": len(loc_map),
        "distinct_fdes": len(all_distinct_fdes),
        "distinct_fde_bytes": sum(e - s for s, e in all_distinct_fdes),
        "files": files_out,
    }


def build_records(img: ElfImage) -> dict[str, Any]:
    fdes, starts, by_start = load_fdes()
    inventory = scan_consensus_inventory(img, fdes, starts)

    fn_records = []
    for name, start, end in CORE_FUNCTIONS:
        if by_start.get(start) != end:
            raise ValueError(f"FDE mismatch for {name}: index has {by_start.get(start)} vs 0x{end:x}")
        raw = img.read_va(".text", start, end - start)
        fn_records.append(
            {
                "name": name,
                "start": f"0x{start:x}",
                "end": f"0x{end:x}",
                "size": end - start,
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        )

    win_records = []
    for name, fn_name, start, end in WINDOWS:
        raw, rows = disasm_window(img, start, end)
        win_records.append(
            {
                "name": name,
                "function": fn_name,
                "start": f"0x{start:x}",
                "end": f"0x{end:x}",
                "size": end - start,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "insns": rows,
            }
        )

    jt_records = []
    for name, va, count, expected_targets in JUMP_TABLES:
        raw = img.read_va(".rodata", va, count * 4)
        targets = [f"0x{va + struct.unpack_from('<i', raw, i * 4)[0]:x}" for i in range(count)]
        if targets != expected_targets:
            raise ValueError(f"jump table {name} at 0x{va:x}: got {targets} != {expected_targets}")
        jt_records.append({"name": name, "va": f"0x{va:x}", "targets": targets})

    return {
        "target_sha256": TARGET_SHA256,
        "capstone_version": capstone.__version__,
        "inventory": inventory,
        "core_functions": fn_records,
        "windows": win_records,
        "jump_tables": jt_records,
    }


def _find_insn(win: dict[str, Any], va_hex: str) -> dict[str, Any]:
    for row in win["insns"]:
        if row["va"] == va_hex:
            return row
    raise AssertionError(f"missing instruction {va_hex} in window {win['name']}")


def check_facts(records: dict[str, Any]) -> list[str]:
    inv = records["inventory"]
    wins = {w["name"]: w for w in records["windows"]}
    jts = {j["name"]: j for j in records["jump_tables"]}
    verified: list[str] = []

    def require(label: str, cond: bool, detail: str) -> None:
        if not cond:
            raise AssertionError(f"fact {label} failed: {detail}")
        verified.append(label)

    # 1. All 17 consensus source files mapped with >=1 Location and >=1 FDE each
    got_paths = [f["path"] for f in inv["files"]]
    require(
        "all_17_consensus_files_mapped",
        got_paths == EXPECTED_CONSENSUS_FILES
        and inv["total_locations"] == 115
        and all(f["location_count"] >= 1 and f["fde_count"] >= 1 for f in inv["files"]),
        f"paths={len(got_paths)} locs={inv['total_locations']}",
    )

    # 2. Both 5-variant jump tables in 0x5823db0
    require(
        "msg_ser_5_variant_jump_tables",
        len(jts["jt_msg_size"]["targets"]) == 5
        and len(jts["jt_msg_ser"]["targets"]) == 5
        and jts["jt_msg_ser"]["targets"] == ["0x5823f82", "0x5824031", "0x5823fdb", "0x5824006", "0x5823fb0"],
        str(jts),
    )

    # 3. Exact 1-byte variant tags 0..=4 written by 0x5823db0
    w_tags = wins["msg_ser_tags"]
    t0 = _find_insn(w_tags, "0x5823f8d")
    t1 = _find_insn(w_tags, "0x582403c")
    t2 = _find_insn(w_tags, "0x5823fe6")
    t3 = _find_insn(w_tags, "0x5824011")
    t4 = _find_insn(w_tags, "0x5823fbb")
    require(
        "msg_ser_variant_tag_bytes_0_to_4",
        t0["op_str"].endswith(", 0")
        and t1["op_str"].endswith(", 1")
        and t2["op_str"].endswith(", 2")
        and t3["op_str"].endswith(", 3")
        and t4["op_str"].endswith(", 4"),
        f"{t0} {t1} {t2} {t3} {t4}",
    )

    # 4. Variant 1 (Vote) serializes 20B voter -> 5x varint u64 -> 32B block_hash
    w_v1 = wins["var1_vote_fields"]
    c_addr = _find_insn(w_v1, "0x5966bab")
    c_h256 = _find_insn(w_v1, "0x5966c4c")
    varint_calls = [r for r in w_v1["insns"] if r["mnemonic"] == "call" and r["op_str"] == "0x5822910"]
    require(
        "var1_vote_exact_field_order",
        c_addr["op_str"] == "0x58221e0" and len(varint_calls) == 5 and c_h256["op_str"] == "0x5822260",
        f"addr={c_addr} varints={len(varint_calls)} h256={c_h256}",
    )

    # 5. Variant 2 (Timeout) serializes 20B signer first -> 4x varint u64
    w_v2 = wins["var2_timeout_fields"]
    t_addr = _find_insn(w_v2, "0x5967da9")
    t_varints = [r for r in w_v2["insns"] if r["mnemonic"] == "call" and r["op_str"] == "0x5822910"]
    require(
        "var2_timeout_exact_field_order",
        t_addr["op_str"] == "0x58221e0" and len(t_varints) == 4,
        f"addr={t_addr} varints={len(t_varints)}",
    )

    # 6. try_propose (0x2e13ea0): proposer check (slot 0x64e86f0) + 20B SIMD == self + anti-equivocation + stake set
    w_tp = wins["try_propose_guards"]
    tp_simd = _find_insn(w_tp, "0x2e140b1")
    tp_dup = _find_insn(w_tp, "0x2e140c3")
    tp_jae = _find_insn(w_tp, "0x2e140ca")
    require(
        "try_propose_proposer_and_equivocation_guards",
        tp_simd["op_str"] == "eax, 0xffff"
        and tp_dup["mnemonic"] == "cmp"
        and "[r13 + 0xae0]" in tp_dup["op_str"]
        and tp_jae["mnemonic"] == "jae",
        f"{tp_simd} / {tp_dup} / {tp_jae}",
    )

    return verified


def run_negative_controls(records: dict[str, Any]) -> list[dict[str, str]]:
    controls = []

    def expect_fail(name: str, mutator) -> None:
        corrupted = copy.deepcopy(records)
        mutator(corrupted)
        try:
            check_facts(corrupted)
        except AssertionError as exc:
            msg = str(exc)
            rejected_by = msg.split(" ")[1] if len(msg.split(" ")) > 1 else msg
            controls.append({"control": name, "rejected_by": rejected_by})
            return
        raise AssertionError(f"negative control {name} unexpectedly passed")

    def mut_drop_file(rec):
        rec["inventory"]["files"].pop()

    def mut_jt_arm(rec):
        rec["jump_tables"][1]["targets"][2] = "0x5823fff"

    def mut_tag_byte(rec):
        for w in rec["windows"]:
            if w["name"] == "msg_ser_tags":
                for r in w["insns"]:
                    if r["va"] == "0x5823fe6":
                        r["op_str"] = "byte ptr [rax + rcx], 9"

    def mut_vote_varints(rec):
        for w in rec["windows"]:
            if w["name"] == "var1_vote_fields":
                for r in w["insns"]:
                    if r["va"] == "0x5966c34":
                        r["op_str"] = "0x5822999"

    def mut_timeout_addr(rec):
        for w in rec["windows"]:
            if w["name"] == "var2_timeout_fields":
                for r in w["insns"]:
                    if r["va"] == "0x5967da9":
                        r["op_str"] = "0x5822260"

    def mut_try_propose_guard(rec):
        for w in rec["windows"]:
            if w["name"] == "try_propose_guards":
                for r in w["insns"]:
                    if r["va"] == "0x2e140ca":
                        r["mnemonic"] = "jb"

    expect_fail("drop_consensus_source_file", mut_drop_file)
    expect_fail("corrupt_msg_ser_jt_arm2", mut_jt_arm)
    expect_fail("corrupt_timeout_tag_byte_2", mut_tag_byte)
    expect_fail("corrupt_vote_varint_count", mut_vote_varints)
    expect_fail("corrupt_timeout_signer_helper", mut_timeout_addr)
    expect_fail("flip_try_propose_equivocation_jae", mut_try_propose_guard)
    return controls


def verify_all(generate: bool = False) -> dict[str, Any]:
    img = ElfImage(TARGET_BIN)
    fresh = build_records(img)
    if generate:
        RECORDS_PATH.write_text(json.dumps(fresh, indent=2) + "\n", encoding="utf-8")
    else:
        existing = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))
        if existing != fresh:
            raise AssertionError("records.json does not match live node #115 binary")
    facts = check_facts(fresh)
    controls = run_negative_controls(fresh)
    return {
        "target_sha256": TARGET_SHA256,
        "source_files_mapped": fresh["inventory"]["source_file_count"],
        "locations_mapped": fresh["inventory"]["total_locations"],
        "distinct_fdes_mapped": fresh["inventory"]["distinct_fdes"],
        "distinct_fde_bytes": fresh["inventory"]["distinct_fde_bytes"],
        "core_functions_verified": len(fresh["core_functions"]),
        "windows_verified": len(fresh["windows"]),
        "facts_verified": len(facts),
        "negative_controls_passed": len(controls),
        "negative_controls": controls,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--generate", action="store_true", help="regenerate records.json from node #115")
    args = ap.parse_args()
    summary = verify_all(generate=args.generate)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
