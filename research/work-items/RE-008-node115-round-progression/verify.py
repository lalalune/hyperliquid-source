#!/usr/bin/env python3
"""Verify the bounded node #115 consensus round-progression static packet.

Authenticates the pinned Linux x86-64 node #115 ELF, checks FDE boundaries and
full body SHA-256 digests for the five functions in scope, pins key instruction
sequences, relocation slots, and read-only literals via Capstone 5.0.7 decoded
from FDE starts, and executes in-memory corruption/negative controls.

No target code is executed.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

import capstone
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PIN = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

# Five FDE-bounded functions in node #115 covering jailed-validator history lookup,
# TC high-QC selection, timeout quorum + 1/3 amplification, local timeout broadcast,
# and round advancement.
SCOPED_FUNCTIONS = [
    ("jailed_validators_for_round", 0x595c3a0, 0x595c5f3),
    ("tc_from_timeouts", 0x5960010, 0x5960381),
    ("check_timeout_quorum_and_advance", 0x2e112f0, 0x2e11afb),
    ("broadcast_local_timeout", 0x2e154e0, 0x2e157b2),
    ("advance_round", 0x2e19920, 0x2e1a118),
]

# Selected instruction windows anchored inside those five FDEs (each verified
# against FDE-start Capstone decoding so interior bytes cannot masquerade as
# instruction starts).
SCOPED_WINDOWS = [
    # 0x595c3a0: jailed_validators_for_round warning threshold + query round math + outputs
    ("jailed_warn_threshold", 0x595c3a0, 0x595c3b5, 0x595c431),
    ("jailed_query_round", 0x595c3a0, 0x595c53c, 0x595c584),
    ("jailed_output_tags", 0x595c3a0, 0x595c5ca, 0x595c5e5),
    # 0x5960010: tc_from_timeouts empty None niche + last-wins max high_qc.round loop
    ("tc_empty_niche", 0x5960010, 0x5960027, 0x5960072),
    ("tc_max_high_qc_loop", 0x5960010, 0x59600d0, 0x596012e),
    ("tc_round_store", 0x5960010, 0x59602f0, 0x5960312),
    # 0x2e112f0: check_timeout_quorum_and_advance 1/3 amplification + quorum -> TC -> advance
    ("timeout_amplify_and_quorum", 0x2e112f0, 0x2e11896, 0x2e11902),
    ("timeout_amplify_overflow", 0x2e112f0, 0x2e11ac8, 0x2e11add),
    ("timeout_tc_and_advance", 0x2e112f0, 0x2e119bd, 0x2e11a2f),
    # 0x2e154e0: broadcast_local_timeout flag write + tag 2 / conditional tag 3 queue pushes
    ("local_timeout_queue_tags", 0x2e154e0, 0x2e15687, 0x2e1571c),
    # 0x2e19920: advance_round stale check, saturating +1, metric 6/7/8, state reset, leader timer
    ("advance_round_guard", 0x2e19920, 0x2e19937, 0x2e1997c),
    ("advance_round_metric_tag", 0x2e19920, 0x2e19b67, 0x2e19b9a),
    ("advance_round_state_reset", 0x2e19920, 0x2e19dad, 0x2e19dfa),
    ("advance_round_proposer_cmp", 0x2e19920, 0x2e19e6b, 0x2e19edc),
    ("advance_round_ret_setae", 0x2e19920, 0x2e19fdd, 0x2e19fe3),
]

SCOPED_FACTS = [
    # Relocation slots (R_X86_64_RELATIVE = 8)
    {"kind": "relocation", "address": "0x64e64b0", "target": "0x595e5c0", "label": "slot_stakes_for_round"},
    {"kind": "relocation", "address": "0x64e8780", "target": "0x595bc40", "label": "slot_consensus_quorum"},
    {"kind": "relocation", "address": "0x64e8788", "target": "0x5960010", "label": "slot_tc_from_timeouts"},
    {"kind": "relocation", "address": "0x64e86f0", "target": "0x595cb30", "label": "slot_proposer_selection"},
    {"kind": "relocation", "address": "0x64e0b18", "target": "0x150b310", "label": "slot_high_round_warn_log"},
    {"kind": "relocation", "address": "0x64e5b78", "target": "0x57e7100", "label": "slot_round_metric_record"},
    {"kind": "relocation", "address": "0x64e0840", "target": "0x5cf1fc0", "label": "slot_timer_reset"},
    {"kind": "relocation", "address": "0x64e86d8", "target": "0x59631f0", "label": "slot_outbound_queue_grow"},
    # Read-only literals
    {"kind": "literal", "address": "0x9383de", "ascii": "jailed validators", "label": "rodata_jailed_validators"},
    {"kind": "literal", "address": "0x43d23c", "ascii": "\tQuerying \xc0% for high round, is execution behind?", "label": "rodata_high_round_warn"},
    # Key RIP-relative calls and direct calls
    {"kind": "rip", "address": "0x595c3b5", "mnemonic": "lea", "target": "0x9383de", "register": "rax", "label": "jailed_label_lea"},
    {"kind": "direct", "address": "0x595c57f", "mnemonic": "call", "target": "0x4dce7b0", "label": "jailed_history_range_call"},
    {"kind": "direct", "address": "0x595c5c0", "mnemonic": "call", "target": "0x51f5470", "label": "jailed_history_btree_last_call"},
    {"kind": "rip", "address": "0x2e115e1", "mnemonic": "call", "target": "0x64e64b0", "label": "timeout_stakes_slot_call"},
    {"kind": "direct", "address": "0x2e117c0", "mnemonic": "call", "target": "0x4e44c00", "label": "timeout_signed_stake_sum_call"},
    {"kind": "direct", "address": "0x2e1188e", "mnemonic": "call", "target": "0x4e406f0", "label": "timeout_total_stake_sum_call"},
    {"kind": "rip", "address": "0x2e118bc", "mnemonic": "call", "target": "0x64e8780", "label": "timeout_quorum_slot_call"},
    {"kind": "direct", "address": "0x2e118ed", "mnemonic": "call", "target": "0x2e154e0", "label": "timeout_amplify_local_call"},
    {"kind": "rip", "address": "0x2e119d9", "mnemonic": "call", "target": "0x64e8788", "label": "timeout_tc_build_slot_call"},
    {"kind": "direct", "address": "0x2e11a1b", "mnemonic": "call", "target": "0x2e19920", "label": "timeout_advance_round_call"},
    {"kind": "direct", "address": "0x2e11a27", "mnemonic": "call", "target": "0x2e13ea0", "label": "timeout_try_propose_call"},
    {"kind": "rip", "address": "0x2e199ac", "mnemonic": "call", "target": "0x64e86f0", "label": "advance_cur_proposer_call"},
    {"kind": "rip", "address": "0x2e19e85", "mnemonic": "call", "target": "0x64e86f0", "label": "advance_next_proposer_call"},
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
        require(rows and rows[0].address == w_start and rows[-1].address + rows[-1].size == w_end, f"window align {label}")
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
        "work_item": "RE-008-node115-round-progression",
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
            expected = fact["ascii"].encode("latin-1")
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
            if "register" in fact:
                require(row.reg_name(row.operands[0].reg) == fact["register"], fact["label"])
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
        require(f is not None and f["end"] == fde_end and fde_start <= start and end <= fde_end, f"enclosing FDE {window['label']}")
        rows = [r for r in decoded_cache[fde_start] if start <= r.address < end]
        require(rows and rows[0].address == start and rows[-1].address + rows[-1].size == end, f"window bounds {window['label']}")
        raw = image.get(start, end - start)
        require(hashlib.sha256(raw).hexdigest() == window["sha256"], f"window SHA-256 {window['label']}")
        actual = [[hex(r.address), r.bytes.hex(), f"{r.mnemonic} {r.op_str}".strip()] for r in rows]
        require(actual == window["rows"], f"window rows {window['label']}")
        window_bytes += len(raw)
        window_rows += len(rows)

    check_facts(image, relocations, packet, decoder)

    # Corruption / negative controls: each damage must be caught.
    negative_controls = [
        ("flip_jailed_literal", Overlay(image, 0x9383de, b"X"), relocations),
        ("flip_amplify_mul_imm", Overlay(image, 0x2e118d0, b"\x04"), relocations),
        ("flip_advance_round_setae", Overlay(image, 0x2e19fe0, b"\x0f\x92\xc0"), relocations),
        ("flip_tc_empty_niche_inc", Overlay(image, 0x5960064, b"\x49\xff\xce"), relocations),
        ("wrong_slot_reloc", image, {**relocations, 0x64e8788: (8, 0x5960011)}),
        ("corrupt_timeout_amplify_call", Overlay(image, 0x2e118ed, b"\xe8\x00\x00\x00\x00"), relocations),
    ]
    caught = []
    for ctrl_name, ctrl_img, ctrl_relocs in negative_controls:
        failed = False
        try:
            # Check windows + facts against corrupted image/relocs
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
