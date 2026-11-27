#!/usr/bin/env python3
"""Verify node #115 HotStuff voting (`0x2e07a00`), QC processing (`0x2e08750`),
QC equivocation detection (`0x2e1fe30`), and uncommitted ancestor chain
completeness (`0x2e20b00`) (`RE-008-node115-hotstuff-vote-and-qc`).

Target: Linux x86-64 node #115 (`artifacts/node/115/hl-node`,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
Static binary analysis only; never executes captured binaries.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
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

FUNCTIONS = [
    ("try_vote", 0x2E07A00, 0x2E08745),
    ("process_qc", 0x2E08750, 0x2E089F4),
    ("record_qc_and_check_equivocation", 0x2E1FE30, 0x2E20047),
    ("collect_uncommitted_ancestors", 0x2E20B00, 0x2E210EF),
]

WINDOWS = [
    ("try_vote_entry_guards", "try_vote", 0x2E07A14, 0x2E07A88),
    ("try_vote_parent_time_strict", "try_vote", 0x2E07EEB, 0x2E07F39),
    ("try_vote_5mb_cap", "try_vote", 0x2E082E3, 0x2E082F0),
    ("try_vote_timeout_and_drift", "try_vote", 0x2E0845D, 0x2E084AA),
    ("try_vote_next_leader_and_mark", "try_vote", 0x2E084E2, 0x2E0852A),
    ("try_vote_pacing_50ms", "try_vote", 0x2E08638, 0x2E08672),
    ("process_qc_update_and_advance", "process_qc", 0x2E08767, 0x2E08823),
    ("qc_equivocation_simd_check", "record_qc_and_check_equivocation", 0x2E1FF29, 0x2E1FF68),
    ("ancestor_walk_commit_boundary", "collect_uncommitted_ancestors", 0x2E20FFD, 0x2E21030),
]

RODATA_F64_ANCHORS = [
    ("max_future_block_drift_secs", 0x459518, 0x400C000000000000, 3.5),
    ("vote_pacing_delay_secs", 0x459038, 0x3FA999999999999A, 0.05),
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


def load_fde_map() -> dict[int, int]:
    tsv = ROOT / "work/index/node-115-fde.tsv"
    out: dict[int, int] = {}
    with tsv.open("r", encoding="utf-8") as fh:
        fh.readline()
        for line in fh:
            parts = line.strip().split("\t")
            if len(parts) >= 2:
                out[int(parts[0], 16)] = int(parts[1], 16)
    return out


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


def build_records(img: ElfImage) -> dict[str, Any]:
    fdes = load_fde_map()
    fn_records = []
    for name, start, end in FUNCTIONS:
        if fdes.get(start) != end:
            raise ValueError(f"FDE mismatch for {name}: index has {fdes.get(start)} vs 0x{end:x}")
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

    rodata_records = []
    for name, va, bits, _ in RODATA_F64_ANCHORS:
        raw = img.read_va(".rodata", va, 8)
        got_bits = struct.unpack("<Q", raw)[0]
        got_val = struct.unpack("<d", raw)[0]
        if got_bits != bits:
            raise ValueError(f"rodata f64 {name} at 0x{va:x}: got 0x{got_bits:x} != 0x{bits:x}")
        rodata_records.append(
            {
                "name": name,
                "va": f"0x{va:x}",
                "u64_hex": f"0x{got_bits:016x}",
                "f64": got_val,
            }
        )

    return {
        "target_sha256": TARGET_SHA256,
        "capstone_version": capstone.__version__,
        "functions": fn_records,
        "windows": win_records,
        "rodata_f64": rodata_records,
    }


def _find_insn(win: dict[str, Any], va_hex: str) -> dict[str, Any]:
    for row in win["insns"]:
        if row["va"] == va_hex:
            return row
    raise AssertionError(f"missing instruction {va_hex} in window {win['name']}")


def check_facts(records: dict[str, Any]) -> list[str]:
    wins = {w["name"]: w for w in records["windows"]}
    ro = {r["name"]: r for r in records["rodata_f64"]}
    verified: list[str] = []

    def require(label: str, cond: bool, detail: str) -> None:
        if not cond:
            raise AssertionError(f"fact {label} failed: {detail}")
        verified.append(label)

    # 1. Anti-double-vote (current_round > last_voted_round) and committed_round guards
    w_e = wins["try_vote_entry_guards"]
    r_lv = _find_insn(w_e, "0x2e07a6e")
    r_cm = _find_insn(w_e, "0x2e07a7b")
    require(
        "try_vote_anti_double_vote_and_committed",
        "[rbx + 0xae8]" in r_lv["op_str"] and "[rbx + 0x380]" in r_cm["op_str"],
        f"{r_lv} / {r_cm}",
    )

    # 2. Strictly increasing block timestamp over parent
    w_pt = wins["try_vote_parent_time_strict"]
    r_ja = _find_insn(w_pt, "0x2e07f2f")
    require(
        "try_vote_strict_parent_timestamp",
        r_ja["mnemonic"] == "ja" and "0x2e07f4e" in r_ja["op_str"],
        str(r_ja),
    )

    # 3. 5,000,000-byte (0x4c4b40) max block tx payload size
    w_5m = wins["try_vote_5mb_cap"]
    r_5m = _find_insn(w_5m, "0x2e082e3")
    require(
        "try_vote_max_block_bytes_5mb",
        r_5m["mnemonic"] == "cmp" and r_5m["op_str"] == "rbp, 0x4c4b40",
        str(r_5m),
    )

    # 4. Timeout mutual exclusion ([rbx+0x8d0] == 0) and 3.5s future timestamp drift (0x459518)
    w_td = wins["try_vote_timeout_and_drift"]
    r_to = _find_insn(w_td, "0x2e0845d")
    r_dr = _find_insn(w_td, "0x2e0849c")
    require(
        "try_vote_timeout_excl_and_drift_3_5s",
        "[rbx + 0x8d0], 0" in r_to["op_str"]
        and r_dr["mnemonic"] == "ucomisd"
        and ro["max_future_block_drift_secs"]["f64"] == 3.5,
        f"{r_to} / {r_dr}",
    )

    # 5. HotStuff star routing to proposer(parent_round + 2) and last_voted_round update
    w_nl = wins["try_vote_next_leader_and_mark"]
    r_p2 = _find_insn(w_nl, "0x2e084e5")
    r_mv = _find_insn(w_nl, "0x2e08523")
    require(
        "try_vote_star_route_plus2_and_mark_voted",
        r_p2["mnemonic"] == "add"
        and r_p2["op_str"] == "rax, 2"
        and "[rbx + 0xae8], rax" in r_mv["op_str"],
        f"{r_p2} / {r_mv}",
    )

    # 6. 50ms vote pacing delay constant (0.05s at 0x459038)
    w_p = wins["try_vote_pacing_50ms"]
    r_p = _find_insn(w_p, "0x2e08638")
    require(
        "try_vote_pacing_50ms",
        r_p["mnemonic"] == "movsd" and ro["vote_pacing_delay_secs"]["f64"] == 0.05,
        str(r_p),
    )

    # 7. process_qc calls equivocation detector (0x2e1fe30), updates highest_qc (> [r15+0x750]), calls advance_round (0x2e19920)
    w_qc = wins["process_qc_update_and_advance"]
    r_eq = _find_insn(w_qc, "0x2e0878c")
    r_hq = _find_insn(w_qc, "0x2e0879b")
    r_ar = _find_insn(w_qc, "0x2e0881e")
    require(
        "process_qc_equivocation_highest_and_advance",
        r_eq["op_str"] == "0x2e1fe30"
        and "[r15 + 0x750]" in r_hq["op_str"]
        and r_ar["op_str"] == "0x2e19920",
        f"{r_eq} / {r_hq} / {r_ar}",
    )

    # 8. 32-byte SIMD equivocation check (pcmpeqb + pmovmskb == 0xffff) and ancestor walk commit boundary
    w_sim = wins["qc_equivocation_simd_check"]
    w_aw = wins["ancestor_walk_commit_boundary"]
    r_sim = _find_insn(w_sim, "0x2e1ff5d")
    r_aw0 = _find_insn(w_aw, "0x2e2102b")
    require(
        "qc_simd_equivocation_and_ancestor_ok_tag0",
        r_sim["op_str"] == "eax, 0xffff" and r_aw0["op_str"] == "byte ptr [rcx], 0",
        f"{r_sim} / {r_aw0}",
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

    def mut_5mb(rec):
        for w in rec["windows"]:
            if w["name"] == "try_vote_5mb_cap":
                for r in w["insns"]:
                    if r["va"] == "0x2e082e3":
                        r["op_str"] = "rbp, 0x100000"

    def mut_drift(rec):
        for r in rec["rodata_f64"]:
            if r["name"] == "max_future_block_drift_secs":
                r["f64"] = 10.0

    def mut_pacing(rec):
        for r in rec["rodata_f64"]:
            if r["name"] == "vote_pacing_delay_secs":
                r["f64"] = 0.5

    def mut_plus2(rec):
        for w in rec["windows"]:
            if w["name"] == "try_vote_next_leader_and_mark":
                for r in w["insns"]:
                    if r["va"] == "0x2e084e5":
                        r["op_str"] = "rax, 1"

    def mut_equiv_call(rec):
        for w in rec["windows"]:
            if w["name"] == "process_qc_update_and_advance":
                for r in w["insns"]:
                    if r["va"] == "0x2e0878c":
                        r["op_str"] = "0x2e1ffff"

    def mut_simd_mask(rec):
        for w in rec["windows"]:
            if w["name"] == "qc_equivocation_simd_check":
                for r in w["insns"]:
                    if r["va"] == "0x2e1ff5d":
                        r["op_str"] = "eax, 0xff"

    expect_fail("corrupt_5mb_block_cap", mut_5mb)
    expect_fail("corrupt_3_5s_future_drift", mut_drift)
    expect_fail("corrupt_50ms_vote_pacing", mut_pacing)
    expect_fail("corrupt_next_leader_plus2", mut_plus2)
    expect_fail("corrupt_qc_equivocation_callee", mut_equiv_call)
    expect_fail("corrupt_qc_simd_mask", mut_simd_mask)
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
        "functions_verified": len(fresh["functions"]),
        "total_function_bytes": sum(f["size"] for f in fresh["functions"]),
        "windows_verified": len(fresh["windows"]),
        "window_bytes": sum(w["size"] for w in fresh["windows"]),
        "rodata_f64_anchors": len(fresh["rodata_f64"]),
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
