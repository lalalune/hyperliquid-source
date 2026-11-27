#!/usr/bin/env python3
"""Verify node #115 staking delegation, undelegation, lockup, and governance
proposal gates (`RE-008-node115-staking-delegation`).

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
    ("token_delegate_handler", 0x2C68BB0, 0x2C68E80),
    ("c_staking_delegate_or_undelegate", 0x3C34FD0, 0x3C35A0E),
    ("delegate_core", 0x4221F40, 0x4222753),
    ("undelegate_core", 0x4221510, 0x4221A8E),
    ("sub_active_stake", 0x42258D0, 0x4225A2C),
    ("add_active_stake", 0x4225A30, 0x4225B7F),
    ("c_staking_propose_gate", 0x3C348B0, 0x3C34FCA),
]

WINDOWS = [
    ("token_delegate_guards", "token_delegate_handler", 0x2C68BC4, 0x2C68C5A),
    ("token_delegate_self_1yr", "token_delegate_handler", 0x2C68E2E, 0x2C68E80),
    ("c_staking_mode_and_epoch", "c_staking_delegate_or_undelegate", 0x3C3512B, 0x3C3518F),
    ("c_staking_delegations_disabled", "c_staking_delegate_or_undelegate", 0x3C355CB, 0x3C355E1),
    ("c_staking_avail_sub", "c_staking_delegate_or_undelegate", 0x3C35889, 0x3C35892),
    ("c_staking_call_delegate_core", "c_staking_delegate_or_undelegate", 0x3C35945, 0x3C35995),
    ("c_staking_self_undeleg_disable", "c_staking_delegate_or_undelegate", 0x3C3583B, 0x3C3587A),
    ("delegate_core_balance_check", "delegate_core", 0x4221F88, 0x4221F9A),
    ("delegate_core_lockup_lookup", "delegate_core", 0x4222005, 0x422201B),
    ("delegate_core_epoch_min", "delegate_core", 0x4222565, 0x4222592),
    ("undelegate_core_lockup_and_self_min", "undelegate_core", 0x42218B9, 0x4221911),
    ("undelegate_core_epoch_min", "undelegate_core", 0x4221999, 0x42219D9),
    ("sub_active_stake_tail", "sub_active_stake", 0x42259ED, 0x4225A1D),
    ("add_active_stake_tail", "add_active_stake", 0x4225B4B, 0x4225B7F),
    ("propose_len_and_stake", "c_staking_propose_gate", 0x3C3491E, 0x3C349A1),
    ("propose_limit_and_duration", "c_staking_propose_gate", 0x3C34C22, 0x3C34CB2),
]

RODATA_F64_ANCHORS = [
    ("self_delegation_lock_1yr", 0x459058, 0x417E187E00000000, 31557600.0),
    ("delegation_lockup_local", 0x4578A0, 0x4122750000000000, 604800.0),
    ("delegation_lockup_sandbox", 0x4578A8, 0x405E000000000000, 120.0),
    ("delegation_lockup_testnet", 0x4578B0, 0x405E000000000000, 120.0),
    ("delegation_lockup_mainnet", 0x4578B8, 0x40F5180000000000, 86400.0),
    ("propose_duration_test_long", 0x455BC0, 0x4072C00000000000, 300.0),
    ("propose_duration_test_short", 0x455BC8, 0x405E000000000000, 120.0),
    ("propose_duration_main_long", 0x459418, 0x411FA40000000000, 518400.0),
    ("propose_duration_main_short", 0x459AC0, 0x40F5180000000000, 86400.0),
]

RELA_SLOTS = [
    ("slot_c_staking_delegate_or_undelegate", 0x64E7E70, 0x3C34FD0),
    ("slot_validator_registration_time", 0x64E7E78, 0x3C3A0B0),
    ("slot_exempt_self_delegation_set", 0x64E7E80, 0x46F40B0),
    ("slot_time_add_secs", 0x64E7E88, 0x3D66200),
    ("slot_c_staking_propose_gate", 0x64E5BD0, 0x3C348B0),
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
    if not tsv.exists():
        return {}
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
        raise ValueError(f"window 0x{start:x}..0x{end:x} ended at 0x{pos:x} (not instruction-aligned)")
    return raw, rows


def resolve_rela_slots(img: ElfImage) -> dict[int, int]:
    rela = img.secs[".rela.dyn"]
    chunk = img.data[rela["offset"] : rela["offset"] + rela["size"]]
    wanted = {slot for _, slot, _ in RELA_SLOTS}
    found: dict[int, int] = {}
    for off in range(0, len(chunk), 24):
        r_off, r_info, r_add = struct.unpack_from("<QQq", chunk, off)
        if r_off in wanted and (r_info & 0xFFFFFFFF) == 8:
            found[r_off] = r_add
    return found


def build_records(img: ElfImage) -> dict[str, Any]:
    fdes = load_fde_map()
    fn_records = []
    for name, start, end in FUNCTIONS:
        if fdes and fdes.get(start) != end:
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
    for name, va, bits, val in RODATA_F64_ANCHORS:
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

    rela_map = resolve_rela_slots(img)
    slot_records = []
    for name, slot_va, target_va in RELA_SLOTS:
        if rela_map.get(slot_va) != target_va:
            raise ValueError(
                f"slot {name} 0x{slot_va:x}: got {rela_map.get(slot_va)} != 0x{target_va:x}"
            )
        slot_records.append(
            {
                "name": name,
                "slot_va": f"0x{slot_va:x}",
                "target_va": f"0x{target_va:x}",
            }
        )

    return {
        "target_sha256": TARGET_SHA256,
        "capstone_version": capstone.__version__,
        "functions": fn_records,
        "windows": win_records,
        "rodata_f64": rodata_records,
        "rela_slots": slot_records,
    }


def _find_insn(win: dict[str, Any], va_hex: str) -> dict[str, Any]:
    for row in win["insns"]:
        if row["va"] == va_hex:
            return row
    raise AssertionError(f"missing instruction {va_hex} in window {win['name']}")


def check_facts(records: dict[str, Any]) -> list[str]:
    wins = {w["name"]: w for w in records["windows"]}
    ro = {r["name"]: r for r in records["rodata_f64"]}
    slots = {s["name"]: s for s in records["rela_slots"]}
    verified: list[str] = []

    def require(label: str, cond: bool, detail: str) -> None:
        if not cond:
            raise AssertionError(f"fact {label} failed: {detail}")
        verified.append(label)

    # 1. TokenDelegate native-token & zero-amount guards (0x10a / 0x33)
    w = wins["token_delegate_guards"]
    r_nt = _find_insn(w, "0x2c68c3a")
    r_z = _find_insn(w, "0x2c68c44")
    require(
        "token_delegate_native_and_zero",
        r_nt["mnemonic"] == "mov"
        and "0x10a" in r_nt["op_str"]
        and r_z["mnemonic"] == "mov"
        and "0x33" in r_z["op_str"],
        f"{r_nt} / {r_z}",
    )

    # 2. TokenDelegate 20-byte SIMD self-delegation detection
    r_cmp = _find_insn(w, "0x2c68c29")
    r_je = _find_insn(w, "0x2c68c2e")
    require(
        "token_delegate_self_simd_check",
        r_cmp["op_str"] == "eax, 0xffff" and r_je["mnemonic"] == "je" and "0x2c68d4c" in r_je["op_str"],
        f"{r_cmp} / {r_je}",
    )

    # 3. TokenDelegate 1-year self-delegation lockup (31,557,600.0 s at 0x459058)
    w_yr = wins["token_delegate_self_1yr"]
    r_yr = _find_insn(w_yr, "0x2c68e38")
    require(
        "token_delegate_self_lock_1yr",
        r_yr["mnemonic"] == "movq"
        and ro["self_delegation_lock_1yr"]["u64_hex"] == "0x417e187e00000000"
        and ro["self_delegation_lock_1yr"]["f64"] == 31557600.0,
        f"{r_yr} / {ro['self_delegation_lock_1yr']}",
    )

    # 4. c_staking unknown validator (0x95) + missing epoch (0x9b) + mode==2 delegate split
    w_m = wins["c_staking_mode_and_epoch"]
    r_95 = _find_insn(w_m, "0x3c35130")
    r_m2 = _find_insn(w_m, "0x3c35168")
    require(
        "c_staking_validator_and_mode2",
        "0x95" in r_95["op_str"] and r_m2["mnemonic"] == "cmp" and r_m2["op_str"] == "r12, 2",
        f"{r_95} / {r_m2}",
    )

    # 5. c_staking delegations disabled tag 0x10c
    w_d = wins["c_staking_delegations_disabled"]
    r_10c = _find_insn(w_d, "0x3c355d7")
    require(
        "c_staking_delegations_disabled_10c",
        r_10c["mnemonic"] == "mov" and "0x10c" in r_10c["op_str"],
        str(r_10c),
    )

    # 6. c_staking saturating available-balance subtraction before delegate_core
    w_a = wins["c_staking_avail_sub"]
    r_sub = _find_insn(w_a, "0x3c3588b")
    r_cmov = _find_insn(w_a, "0x3c3588e")
    require(
        "c_staking_avail_saturating_sub",
        r_sub["mnemonic"] == "sub" and r_cmov["mnemonic"] == "cmovb",
        f"{r_sub} / {r_cmov}",
    )

    # 7. c_staking self-undelegation auto-disables delegations below [r13+0x308]
    w_su = wins["c_staking_self_undeleg_disable"]
    r_thr = _find_insn(w_su, "0x3c35862")
    r_set = _find_insn(w_su, "0x3c3586f")
    require(
        "c_staking_self_undeleg_auto_disable",
        r_thr["mnemonic"] == "cmp"
        and "[r13 + 0x308]" in r_thr["op_str"]
        and r_set["mnemonic"] == "mov"
        and r_set["op_str"] == "byte ptr [r12 + 0x18], 1",
        f"{r_thr} / {r_set}",
    )

    # 8. delegate_core insufficient balance tag 0x10b
    w_db = wins["delegate_core_balance_check"]
    r_10b = _find_insn(w_db, "0x4221f8c")
    require(
        "delegate_core_insufficient_balance_10b",
        r_10b["mnemonic"] == "mov" and r_10b["op_str"] == "ax, 0x10b",
        str(r_10b),
    )

    # 9. delegate_core 4-chain lockup table at 0x4578a0 [604800, 120, 120, 86400]
    w_dl = wins["delegate_core_lockup_lookup"]
    r_tbl = _find_insn(w_dl, "0x422200c")
    require(
        "delegate_core_chain_lockup_table",
        r_tbl["mnemonic"] == "movsd"
        and "[rax + r14*8]" in r_tbl["op_str"]
        and ro["delegation_lockup_local"]["f64"] == 604800.0
        and ro["delegation_lockup_sandbox"]["f64"] == 120.0
        and ro["delegation_lockup_testnet"]["f64"] == 120.0
        and ro["delegation_lockup_mainnet"]["f64"] == 86400.0,
        f"{r_tbl}",
    )

    # 10. delegate_core epoch-min update on epoch change
    w_de = wins["delegate_core_epoch_min"]
    r_ec = _find_insn(w_de, "0x4222570")
    r_add = _find_insn(w_de, "0x4222581")
    require(
        "delegate_core_epoch_min_and_checked_add",
        r_ec["mnemonic"] == "cmp" and "[rbx + 0x10]" in r_ec["op_str"] and r_add["mnemonic"] == "add",
        f"{r_ec} / {r_add}",
    )

    # 11. undelegate_core lockup (0x10e) and self-delegation minimum (0x145)
    w_ul = wins["undelegate_core_lockup_and_self_min"]
    r_10e = _find_insn(w_ul, "0x42218d3")
    r_145 = _find_insn(w_ul, "0x42218fd")
    require(
        "undelegate_core_lockup_10e_and_self_min_145",
        r_10e["op_str"] == "si, 0x10e" and r_145["op_str"] == "si, 0x145",
        f"{r_10e} / {r_145}",
    )

    # 12. undelegate_core epoch-min cmovb
    w_ue = wins["undelegate_core_epoch_min"]
    r_ucm = _find_insn(w_ue, "0x42219ac")
    require(
        "undelegate_core_epoch_min_cmovb",
        r_ucm["mnemonic"] == "cmovb" and r_ucm["op_str"] == "rax, rbx",
        str(r_ucm),
    )

    # 13. sub_active_stake epoch-min cmovb and add_active_stake overflow 0xc3
    w_sa = wins["sub_active_stake_tail"]
    w_aa = wins["add_active_stake_tail"]
    r_sac = _find_insn(w_sa, "0x4225a16")
    r_aac = _find_insn(w_aa, "0x4225b6c")
    require(
        "active_stake_update_helpers",
        r_sac["mnemonic"] == "cmovb" and "0xc3" in r_aac["op_str"],
        f"{r_sac} / {r_aac}",
    )

    # 14. Governance propose length bounds (1..=50 -> 0x10f, 1..=1000 -> 0x110) and 1e9 stake floor (0x111)
    w_p1 = wins["propose_len_and_stake"]
    r_10f = _find_insn(w_p1, "0x3c34922")
    r_110 = _find_insn(w_p1, "0x3c34945")
    r_111 = _find_insn(w_p1, "0x3c34991")
    r_stk = _find_insn(w_p1, "0x3c34995")
    require(
        "propose_bounds_10f_110_111",
        r_10f["op_str"] == "cx, 0x10f"
        and r_110["op_str"] == "cx, 0x110"
        and r_111["op_str"] == "cx, 0x111"
        and r_stk["op_str"] == "rax, 0x3b9aca00",
        f"{r_10f} / {r_110} / {r_111} / {r_stk}",
    )

    # 15. Governance propose active limit <= 2 (max 3 per user -> 0x113) and duration constants
    w_p2 = wins["propose_limit_and_duration"]
    r_113 = _find_insn(w_p2, "0x3c34c22")
    r_lim = _find_insn(w_p2, "0x3c34c26")
    require(
        "propose_limit_113_and_durations",
        r_113["op_str"] == "cx, 0x113"
        and r_lim["op_str"] == "rax, 2"
        and ro["propose_duration_test_long"]["f64"] == 300.0
        and ro["propose_duration_test_short"]["f64"] == 120.0
        and ro["propose_duration_main_long"]["f64"] == 518400.0
        and ro["propose_duration_main_short"]["f64"] == 86400.0,
        f"{r_113} / {r_lim}",
    )

    # 16. Relocation slots bind handlers to exact targets
    require(
        "rela_slots_exact",
        slots["slot_c_staking_delegate_or_undelegate"]["target_va"] == "0x3c34fd0"
        and slots["slot_validator_registration_time"]["target_va"] == "0x3c3a0b0"
        and slots["slot_exempt_self_delegation_set"]["target_va"] == "0x46f40b0"
        and slots["slot_time_add_secs"]["target_va"] == "0x3d66200"
        and slots["slot_c_staking_propose_gate"]["target_va"] == "0x3c348b0",
        str(slots),
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

    def mut_zero_tag(rec):
        for w in rec["windows"]:
            if w["name"] == "token_delegate_guards":
                for r in w["insns"]:
                    if r["va"] == "0x2c68c44":
                        r["op_str"] = "word ptr [rbx], 0x34"

    def mut_mainnet_lockup(rec):
        for r in rec["rodata_f64"]:
            if r["name"] == "delegation_lockup_mainnet":
                r["f64"] = 604800.0

    def mut_self_min_tag(rec):
        for w in rec["windows"]:
            if w["name"] == "undelegate_core_lockup_and_self_min":
                for r in w["insns"]:
                    if r["va"] == "0x42218fd":
                        r["op_str"] = "si, 0x146"

    def mut_auto_disable(rec):
        for w in rec["windows"]:
            if w["name"] == "c_staking_self_undeleg_disable":
                for r in w["insns"]:
                    if r["va"] == "0x3c3586f":
                        r["op_str"] = "byte ptr [r12 + 0x18], 0"

    def mut_propose_stake(rec):
        for w in rec["windows"]:
            if w["name"] == "propose_len_and_stake":
                for r in w["insns"]:
                    if r["va"] == "0x3c34995":
                        r["op_str"] = "rax, 0x100"

    def mut_propose_limit(rec):
        for w in rec["windows"]:
            if w["name"] == "propose_limit_and_duration":
                for r in w["insns"]:
                    if r["va"] == "0x3c34c26":
                        r["op_str"] = "rax, 9"

    expect_fail("corrupt_zero_amount_tag_33", mut_zero_tag)
    expect_fail("corrupt_mainnet_lockup_86400", mut_mainnet_lockup)
    expect_fail("corrupt_self_min_tag_145", mut_self_min_tag)
    expect_fail("corrupt_self_undeleg_disable_flag", mut_auto_disable)
    expect_fail("corrupt_propose_stake_floor_1e9", mut_propose_stake)
    expect_fail("corrupt_propose_active_limit_2", mut_propose_limit)
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
        "window_rows": sum(len(w["insns"]) for w in fresh["windows"]),
        "rodata_f64_anchors": len(fresh["rodata_f64"]),
        "rela_slots_verified": len(fresh["rela_slots"]),
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
