#!/usr/bin/env python3
"""Verify the bounded node #115 block rules & TC verification static packet.

Authenticates the pinned Linux x86-64 node #115 ELF, checks FDE boundaries and
full body SHA-256 digests for `0x59d6b80` (`signed.rs:194`), `0x5960390`
(`TimeoutCertificate::verify`), and `0x564b510` (TC parallel signature verify
dispatch), pins key instruction windows, relocation slots, and literals via
Capstone 5.0.7 decoded from FDE starts, and executes in-memory corruption
negative controls.

No target code is executed.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

import capstone
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PIN = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

SCOPED_FUNCTIONS = [
    ("block_verify_rules", 0x59d6b80, 0x59d70ab),
    ("tc_verify", 0x5960390, 0x59608a8),
    ("tc_verify_parallel_dispatch", 0x564b510, 0x564b5e4),
]

SCOPED_WINDOWS = [
    # 0x59d6b80 (signed.rs:194): block round, proposer check, tag 0x0d, max 100 tx cap (0x29), dup tx (0x2a), TC/QC ordering (0x0c)
    ("block_round_saturating_inc", 0x59d6b80, 0x59d6b9a, 0x59d6bd7),
    ("block_proposer_slot_call", 0x59d6b80, 0x59d6c16, 0x59d6c49),
    ("block_proposer_mismatch_0d", 0x59d6b80, 0x59d6e7f, 0x59d6eb2),
    ("block_tx_count_cap_100_29", 0x59d6b80, 0x59d6f04, 0x59d6f17),
    ("block_dup_tx_hash_2a", 0x59d6b80, 0x59d6f78, 0x59d6fa5),
    ("block_tc_extra_qc_order_and_calls", 0x59d6b80, 0x59d6fd9, 0x59d7042),
    ("block_extra_qc_order_err_0c", 0x59d6b80, 0x59d7078, 0x59d707f),
    # 0x5960390: TC stake-set lookup, signer collection, empty -> 0x08, high_qc/round bounds -> 0x0b, quorum -> 0x08, nested QC
    ("tc_verify_stakes_and_collect", 0x5960390, 0x59603aa, 0x59603e5),
    ("tc_verify_empty_sigs_to_08", 0x5960390, 0x596059d, 0x59605af),
    ("tc_verify_round_quorum_nested", 0x5960390, 0x59606ef, 0x596073a),
    ("tc_verify_err_tags_08_0b", 0x5960390, 0x596079c, 0x59607c1),
]

SCOPED_FACTS = [
    # Relocation slots (R_X86_64_RELATIVE = 8)
    {"kind": "relocation", "address": "0x64e64c0", "target": "0x59d6b80", "label": "slot_block_verify_rules"},
    {"kind": "relocation", "address": "0x64e86f0", "target": "0x595cb30", "label": "slot_proposer_selection"},
    {"kind": "relocation", "address": "0x64e64b0", "target": "0x595e5c0", "label": "slot_stakes_for_round"},
    {"kind": "relocation", "address": "0x64e8780", "target": "0x595bc40", "label": "slot_consensus_quorum"},
    # Read-only literal
    {"kind": "literal", "address": "0x9385ff", "ascii": "Unexpected proposer for block", "label": "rodata_unexpected_proposer"},
    # Direct and RIP-relative calls
    {"kind": "rip", "address": "0x59d6c21", "mnemonic": "call", "target": "0x64e86f0", "label": "block_proposer_call"},
    {"kind": "direct", "address": "0x59d6cca", "mnemonic": "call", "target": "0x57e8d40", "label": "block_digest_on_mismatch_call"},
    {"kind": "direct", "address": "0x59d6f78", "mnemonic": "call", "target": "0x51d28d0", "label": "block_tx_dedup_insert_call"},
    {"kind": "direct", "address": "0x59d6fc7", "mnemonic": "call", "target": "0x595fd20", "label": "block_qc_nested_decide_call"},
    {"kind": "direct", "address": "0x59d7010", "mnemonic": "call", "target": "0x5960390", "label": "block_tc_verify_call"},
    {"kind": "direct", "address": "0x59d7031", "mnemonic": "call", "target": "0x595fd20", "label": "block_extra_qc_nested_decide_call"},
    {"kind": "rip", "address": "0x59603b4", "mnemonic": "call", "target": "0x64e64b0", "label": "tc_stakes_slot_call"},
    {"kind": "direct", "address": "0x59603d4", "mnemonic": "call", "target": "0x4dffc40", "label": "tc_collect_signers_call"},
    {"kind": "rip", "address": "0x5960714", "mnemonic": "call", "target": "0x64e8780", "label": "tc_quorum_slot_call"},
    {"kind": "direct", "address": "0x596072b", "mnemonic": "call", "target": "0x595fd20", "label": "tc_high_qc_nested_decide_call"},
    {"kind": "direct", "address": "0x5960785", "mnemonic": "call", "target": "0x564b510", "label": "tc_parallel_sig_verify_call"},
]


def require(condition: bool, label: str) -> None:
    if not condition:
        raise ValueError(label)


def load_elf_support():
    helper_path = ROOT / "research/work-items/RE-001-node115-registry-row-labels/verify.py"
    spec = importlib.util.spec_from_file_location("node115_elf_support", helper_path)
    helper = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(helper)
    return helper


class Overlay:
    def __init__(self, image, address: int, replacement: bytes):
        self.image = image
        self.address = address
        self.replacement = replacement
        self.sections = image.sections

    def get(self, address: int, size: int) -> bytes:
        result = bytearray(self.image.get(address, size))
        for i, value in enumerate(self.replacement):
            relative = self.address + i - address
            if 0 <= relative < size:
                result[relative] = value
        return bytes(result)


def generate_records(target: Path) -> dict:
    data = target.read_bytes()
    require(hashlib.sha256(data).hexdigest() == PIN, "target SHA-256")
    require(capstone.__version__ == "5.0.7", "Capstone 5.0.7 required")
    helper = load_elf_support()
    image = helper.Image(data)
    _, fdes = helper.eh_frame_records(data, image.sections)
    fde_by_start = {f["start"]: f for f in fdes}
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True

    functions = []
    decoded_cache = {}
    for name, start, end in SCOPED_FUNCTIONS:
        f = fde_by_start[start]
        require(f["end"] == end, f"FDE end mismatch for {name}")
        raw = image.get(start, end - start)
        rows = list(decoder.disasm(raw, start))
        decoded_cache[start] = rows
        functions.append(
            {
                "name": name,
                "start": hex(start),
                "end": hex(end),
                "size": end - start,
                "instruction_count": len(rows),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        )

    windows = []
    for label, fde_start, w_start, w_end in SCOPED_WINDOWS:
        f = fde_by_start[fde_start]
        rows = [r for r in decoded_cache[fde_start] if w_start <= r.address < w_end]
        require(
            rows and rows[0].address == w_start and rows[-1].address + rows[-1].size == w_end,
            f"window align {label}",
        )
        raw = image.get(w_start, w_end - w_start)
        windows.append(
            {
                "label": label,
                "fde": [hex(f["start"]), hex(f["end"])],
                "start": hex(w_start),
                "end": hex(w_end),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "rows": [[hex(r.address), r.bytes.hex(), f"{r.mnemonic} {r.op_str}".strip()] for r in rows],
            }
        )

    return {
        "schema_version": 1,
        "work_item": "RE-008-node115-block-rules-and-tc-verify",
        "component": "consensus",
        "target_path": "artifacts/node/115/hl-node",
        "target_sha256": PIN,
        "capstone_version": capstone.__version__,
        "functions": functions,
        "windows": windows,
        "facts": SCOPED_FACTS,
    }


def check_facts(image, relocations, packet, decoder) -> None:
    for fact in packet["facts"]:
        address = int(fact["address"], 16)
        kind = fact["kind"]
        if kind == "literal":
            expected = fact["ascii"].encode("ascii")
            require(image.get(address, len(expected)) == expected, fact["label"])
            continue
        if kind == "relocation":
            observed = relocations.get(address)
            require(
                observed is not None and observed[0] == 8 and observed[1] == int(fact["target"], 16),
                fact["label"],
            )
            continue
        rows = list(decoder.disasm(image.get(address, 15), address, count=1))
        require(len(rows) == 1, fact["label"])
        row = rows[0]
        if kind == "direct":
            require(
                row.mnemonic == fact["mnemonic"]
                and len(row.operands) == 1
                and row.operands[0].type == X86_OP_IMM
                and row.operands[0].imm == int(fact["target"], 16),
                fact["label"],
            )
        elif kind == "rip":
            operands = [o for o in row.operands if o.type == X86_OP_MEM and o.mem.base == X86_REG_RIP]
            require(
                row.mnemonic == fact["mnemonic"]
                and len(operands) == 1
                and row.address + row.size + operands[0].mem.disp == int(fact["target"], 16),
                fact["label"],
            )
        else:
            raise ValueError(f"unknown fact kind: {kind}")


def verify_packet(target: Path, packet: dict) -> dict:
    data = target.read_bytes()
    require(hashlib.sha256(data).hexdigest() == PIN == packet["target_sha256"], "target SHA-256")
    require(capstone.__version__ == packet["capstone_version"], "Capstone version match")
    helper = load_elf_support()
    image = helper.Image(data)
    relocations = image.relocs()
    _, fdes = helper.eh_frame_records(data, image.sections)
    fde_by_start = {f["start"]: f for f in fdes}
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True

    decoded_cache = {}
    total_fn_bytes = 0
    for fn in packet["functions"]:
        start, end = int(fn["start"], 16), int(fn["end"], 16)
        f = fde_by_start.get(start)
        require(f is not None and f["end"] == end, f"FDE match {fn['name']}")
        raw = image.get(start, end - start)
        require(hashlib.sha256(raw).hexdigest() == fn["sha256"], f"function SHA-256 {fn['name']}")
        rows = list(decoder.disasm(raw, start))
        require(len(rows) == fn["instruction_count"], f"instruction count {fn['name']}")
        decoded_cache[start] = rows
        total_fn_bytes += len(raw)

    window_bytes = 0
    window_rows = 0
    for window in packet["windows"]:
        start, end = int(window["start"], 16), int(window["end"], 16)
        fde_start, fde_end = int(window["fde"][0], 16), int(window["fde"][1], 16)
        f = fde_by_start.get(fde_start)
        require(
            f is not None and f["end"] == fde_end and fde_start <= start and end <= fde_end,
            f"enclosing FDE {window['label']}",
        )
        rows = [r for r in decoded_cache[fde_start] if start <= r.address < end]
        require(
            rows and rows[0].address == start and rows[-1].address + rows[-1].size == end,
            f"window bounds {window['label']}",
        )
        raw = image.get(start, end - start)
        require(hashlib.sha256(raw).hexdigest() == window["sha256"], f"window SHA-256 {window['label']}")
        actual = [[hex(r.address), r.bytes.hex(), f"{r.mnemonic} {r.op_str}".strip()] for r in rows]
        require(actual == window["rows"], f"window rows {window['label']}")
        window_bytes += len(raw)
        window_rows += len(rows)

    check_facts(image, relocations, packet, decoder)

    negative_controls = [
        ("corrupt_tx_cap_100", Overlay(image, 0x59d6f0b, b"\x65"), relocations),
        ("corrupt_proposer_literal", Overlay(image, 0x9385ff, b"X"), relocations),
        ("flip_dup_tx_tag_2a", Overlay(image, 0x59d6f9f, b"\x2b"), relocations),
        ("flip_extra_qc_tag_0c", Overlay(image, 0x59d707a, b"\x0d"), relocations),
        ("flip_tc_round_tag_0b", Overlay(image, 0x59607b3, b"\x0c"), relocations),
        ("wrong_block_rules_slot", image, {**relocations, 0x64e64c0: (8, 0x59d6b81)}),
    ]
    caught = []
    for ctrl_name, ctrl_img, ctrl_relocs in negative_controls:
        failed = False
        try:
            for window in packet["windows"]:
                start, end = int(window["start"], 16), int(window["end"], 16)
                raw = ctrl_img.get(start, end - start)
                require(hashlib.sha256(raw).hexdigest() == window["sha256"], window["label"])
            check_facts(ctrl_img, ctrl_relocs, packet, decoder)
        except ValueError as exc:
            failed = True
            caught.append({"control": ctrl_name, "rejected_by": str(exc)})
        require(failed, f"negative control not caught: {ctrl_name}")

    return {
        "target_sha256": PIN,
        "functions_verified": len(packet["functions"]),
        "total_function_bytes": total_fn_bytes,
        "windows_verified": len(packet["windows"]),
        "window_bytes": window_bytes,
        "window_rows": window_rows,
        "facts_verified": len(packet["facts"]),
        "negative_controls_passed": len(caught),
        "negative_controls": caught,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, default=ROOT / "artifacts/node/115/hl-node")
    parser.add_argument("--generate", action="store_true", help="Write records.json from the pinned target")
    args = parser.parse_args()
    records_path = HERE / "records.json"
    if args.generate:
        rec = generate_records(args.target)
        records_path.write_text(json.dumps(rec, indent=2) + "\n")
    packet = json.loads(records_path.read_text())
    report = verify_packet(args.target, packet)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
