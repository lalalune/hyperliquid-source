#!/usr/bin/env python3
"""Verify node #115 CStaking withdrawal queue (`0x3c3bbd0`, `0x36cb770`, `0x3c3b790`)
(`RE-008-node115-staking-withdrawal-queue`).

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
    ("c_staking_queue_withdrawal", 0x3C3BBD0, 0x3C3BF47),
    ("withdrawal_queue_enqueue", 0x36CB770, 0x36CBA51),
    ("c_staking_drain_withdrawals", 0x3C3B790, 0x3C3B8D5),
]

WINDOWS = [
    ("enqueue_max_5_and_balance", "withdrawal_queue_enqueue", 0x36CB7D7, 0x36CB85C),
    ("enqueue_delay_table", "withdrawal_queue_enqueue", 0x36CB893, 0x36CB8AB),
    ("enqueue_push_entry_32b", "withdrawal_queue_enqueue", 0x36CB9ED, 0x36CBA38),
    ("dispatch_long_term_and_bal", "c_staking_queue_withdrawal", 0x3C3BD46, 0x3C3BDB4),
    ("dispatch_tag_141", "c_staking_queue_withdrawal", 0x3C3BEA1, 0x3C3BEB0),
    ("dispatch_call_enqueue", "c_staking_queue_withdrawal", 0x3C3BF0C, 0x3C3BF35),
    ("drain_mature_split", "c_staking_drain_withdrawals", 0x3C3B875, 0x3C3B8C7),
]

RODATA_F64_ANCHORS = [
    ("withdraw_delay_local_mainnet", 0x450D00, 0x4122750000000000, 604800.0),
    ("withdraw_delay_sandbox_testnet", 0x450D08, 0x4072C00000000000, 300.0),
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

    # 1. Max 5 concurrent withdrawals per user (cmp [rax+8], 4 -> 0x143)
    w_e = wins["enqueue_max_5_and_balance"]
    r_143 = _find_insn(w_e, "0x36cb7d7")
    r_cap4 = _find_insn(w_e, "0x36cb7db")
    require(
        "enqueue_max_5_concurrent_143",
        r_143["op_str"] == "cx, 0x143" and r_cap4["op_str"] == "qword ptr [rax + 8], 4",
        f"{r_143} / {r_cap4}",
    )

    # 2. Checked sum pending + amount <= liquid_balance else 0x142
    r_add = _find_insn(w_e, "0x36cb844")
    r_142 = _find_insn(w_e, "0x36cb852")
    require(
        "enqueue_checked_balance_142",
        r_add["mnemonic"] == "add" and r_142["op_str"] == "cx, 0x142",
        f"{r_add} / {r_142}",
    )

    # 3. 2-entry withdrawal delay table at 0x450d00 (604800s Local/Mainnet, 300s Sandbox/Testnet)
    w_d = wins["enqueue_delay_table"]
    r_cmp = _find_insn(w_d, "0x36cb898")
    r_ld = _find_insn(w_d, "0x36cb8a6")
    require(
        "enqueue_delay_table_7d_300s",
        r_cmp["op_str"] == "bpl, 2"
        and "[rdx + rax*8]" in r_ld["op_str"]
        and ro["withdraw_delay_local_mainnet"]["f64"] == 604800.0
        and ro["withdraw_delay_sandbox_testnet"]["f64"] == 300.0,
        f"{r_cmp} / {r_ld}",
    )

    # 4. 32-byte queue entry push (shl rcx, 5) + 0x1a2 OK + 0xc3 overflow
    w_p = wins["enqueue_push_entry_32b"]
    r_shl = _find_insn(w_p, "0x36cb9f5")
    r_ok = _find_insn(w_p, "0x36cba16")
    r_c3 = _find_insn(w_p, "0x36cba32")
    require(
        "enqueue_32b_entry_ok_and_c3",
        r_shl["op_str"] == "rcx, 5" and r_ok["op_str"] == "cx, 0x1a2" and r_c3["op_str"] == "cx, 0xc3",
        f"{r_shl} / {r_ok} / {r_c3}",
    )

    # 5. Long-term staking lockup guard (0x141) and balance guard (0x142) in 0x3c3bbd0
    w_lt = wins["dispatch_long_term_and_bal"]
    w_141 = wins["dispatch_tag_141"]
    r_d142 = _find_insn(w_lt, "0x3c3bdaa")
    r_d141 = _find_insn(w_141, "0x3c3bea6")
    require(
        "dispatch_long_term_141_and_bal_142",
        "0x141" in r_d141["op_str"] and "0x142" in r_d142["op_str"],
        f"{r_d141} / {r_d142}",
    )

    # 6. Dispatch calls 0x36cb770 and drain updates pending (+0x268) & balances (+0x228)
    w_ce = wins["dispatch_call_enqueue"]
    w_dr = wins["drain_mature_split"]
    r_call = _find_insn(w_ce, "0x3c3bf30")
    r_dr1 = _find_insn(w_dr, "0x3c3b87f")
    r_dr2 = _find_insn(w_dr, "0x3c3b8c2")
    require(
        "dispatch_to_enqueue_and_drain_helpers",
        r_call["op_str"] == "0x36cb770" and r_dr1["op_str"] == "0x3d70460" and r_dr2["op_str"] == "0x3d5dfb0",
        f"{r_call} / {r_dr1} / {r_dr2}",
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

    def mut_cap5(rec):
        for w in rec["windows"]:
            if w["name"] == "enqueue_max_5_and_balance":
                for r in w["insns"]:
                    if r["va"] == "0x36cb7db":
                        r["op_str"] = "qword ptr [rax + 8], 9"

    def mut_7d(rec):
        for r in rec["rodata_f64"]:
            if r["name"] == "withdraw_delay_local_mainnet":
                r["f64"] = 86400.0

    def mut_300s(rec):
        for r in rec["rodata_f64"]:
            if r["name"] == "withdraw_delay_sandbox_testnet":
                r["f64"] = 60.0

    def mut_141(rec):
        for w in rec["windows"]:
            if w["name"] == "dispatch_tag_141":
                for r in w["insns"]:
                    if r["va"] == "0x3c3bea6":
                        r["op_str"] = "word ptr [rax], 0x140"

    def mut_c3(rec):
        for w in rec["windows"]:
            if w["name"] == "enqueue_push_entry_32b":
                for r in w["insns"]:
                    if r["va"] == "0x36cba32":
                        r["op_str"] = "cx, 0xc4"

    def mut_enqueue_call(rec):
        for w in rec["windows"]:
            if w["name"] == "dispatch_call_enqueue":
                for r in w["insns"]:
                    if r["va"] == "0x3c3bf30":
                        r["op_str"] = "0x36cb999"

    expect_fail("corrupt_max_5_concurrent_withdrawals", mut_cap5)
    expect_fail("corrupt_mainnet_7d_delay", mut_7d)
    expect_fail("corrupt_testnet_300s_delay", mut_300s)
    expect_fail("corrupt_long_term_tag_141", mut_141)
    expect_fail("corrupt_overflow_tag_c3", mut_c3)
    expect_fail("corrupt_enqueue_callee", mut_enqueue_call)
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
