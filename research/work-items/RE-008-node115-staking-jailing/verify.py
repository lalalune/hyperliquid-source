#!/usr/bin/env python3
"""Verify the bounded node #115 staking & jailing static packet.

Authenticates the pinned Linux x86-64 node #115 ELF, checks FDE boundaries and
full body SHA-256 digests for the five staking/jailing functions in scope,
pins key instruction windows, relocation slots, f64/string constants via
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
    ("jailing_apply_action", 0x3c3c260, 0x3c3cfb1),
    ("jailing_jail_validator", 0x3c35a10, 0x3c35fdb),
    ("jailing_expire_prune", 0x3c35fe0, 0x3c36b95),
    ("staking_epoch_quorum", 0x36c7f70, 0x36c8424),
    ("staking_epoch_profiles", 0x36c7b30, 0x36c7f6d),
]

SCOPED_WINDOWS = [
    # 0x3c3c260 (jailing.rs:38): 3-arm dispatch, weighted median jail-until, status codes 0x1a2/0x99/0xa0/0x9f, 300s check
    ("jailing_action_dispatch", 0x3c3c260, 0x3c3c28d, 0x3c3c2c1),
    ("jailing_weighted_median_loop", 0x3c3c260, 0x3c3c8a5, 0x3c3c94c),
    ("jailing_ok_and_disabled_status", 0x3c3c260, 0x3c3cbcf, 0x3c3cbfc),
    ("jailing_until_time_cmp", 0x3c3c260, 0x3c3cda6, 0x3c3cdd8),
    ("jailing_manual_unjail_300s_and_errors", 0x3c3c260, 0x3c3ce45, 0x3c3cf0a),
    # 0x3c35a10: protected-validator check before jailing
    ("jailing_protected_chain_branch", 0x3c35a10, 0x3c35a2e, 0x3c35a65),
    # 0x36c7f70 (staking.rs:185): missing-epoch 0x9b drop + weight-comparison 0x422e0f0 handoff
    ("staking_quorum_missing_epoch_9b", 0x36c7f70, 0x36c80a3, 0x36c80bb),
    ("staking_quorum_weight_cmp_call", 0x36c7f70, 0x36c82d7, 0x36c82f2),
    # 0x36c7b30 (staking.rs:239/243): missing-epoch 0x9b record + duplicate-profile assertion
    ("staking_profiles_missing_epoch_9b", 0x36c7b30, 0x36c7c0e, 0x36c7c23),
    ("staking_profiles_assert_tail", 0x36c7b30, 0x36c7f20, 0x36c7f6d),
]

SCOPED_FACTS = [
    # Relocation slots (R_X86_64_RELATIVE = 8)
    {"kind": "relocation", "address": "0x64e5be8", "target": "0x46f3fc0", "label": "slot_exempt_validator_set"},
    {"kind": "relocation", "address": "0x64e7e88", "target": "0x3d66200", "label": "slot_time_add_seconds"},
    {"kind": "relocation", "address": "0x64e7f00", "target": "0x3c377b0", "label": "slot_protected_validator_guard"},
    {"kind": "relocation", "address": "0x64df730", "target": "0x1680e60", "label": "slot_core_panic"},
    # Constants in .rodata
    {"kind": "bytes", "address": "0x458f40", "hex": "0000000000c07240", "label": "rodata_manual_unjail_300s_f64"},
    {
        "kind": "literal",
        "address": "0x79db30",
        "ascii": "assertion failed: profiles.insert(validator_profile)",
        "label": "rodata_profiles_insert_assert",
    },
    # Direct and RIP-relative calls / constant loads
    {"kind": "direct", "address": "0x3c3c2b7", "mnemonic": "call", "target": "0x3c35a10", "label": "self_jail_call"},
    {"kind": "direct", "address": "0x3c3c890", "mnemonic": "call", "target": "0x3d6f520", "label": "jail_votes_sort_call"},
    {"kind": "direct", "address": "0x3c3c97b", "mnemonic": "call", "target": "0x3c35a10", "label": "vote_jail_call"},
    {"kind": "rip", "address": "0x3c3ce45", "mnemonic": "movq", "target": "0x458f40", "label": "manual_unjail_load_300s"},
    {"kind": "rip", "address": "0x3c3ce4d", "mnemonic": "call", "target": "0x64e7e88", "label": "manual_unjail_time_add_call"},
    {"kind": "direct", "address": "0x3c3cef1", "mnemonic": "call", "target": "0x39038f0", "label": "manual_unjail_remove_call"},
    {"kind": "direct", "address": "0x36c7bde", "mnemonic": "call", "target": "0x4551810", "label": "profiles_epoch_ring_search_call"},
    {"kind": "direct", "address": "0x36c80af", "mnemonic": "call", "target": "0x36dae30", "label": "quorum_missing_epoch_drop_call"},
    {"kind": "direct", "address": "0x36c82e4", "mnemonic": "call", "target": "0x422e0f0", "label": "quorum_weight_cmp_call"},
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
        "work_item": "RE-008-node115-staking-jailing",
        "component": "staking",
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
        if kind == "bytes":
            expected = bytes.fromhex(fact["hex"])
            require(image.get(address, len(expected)) == expected, fact["label"])
            continue
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
        ("corrupt_300s_constant", Overlay(image, 0x458f46, b"\x73"), relocations),
        ("corrupt_profiles_literal", Overlay(image, 0x79db30, b"X"), relocations),
        ("flip_manual_unjail_status_9f", Overlay(image, 0x3c3cf03, b"\x9e"), relocations),
        ("flip_jailed_until_status_a0", Overlay(image, 0x3c3ceac, b"\xa1"), relocations),
        ("flip_median_jb_to_jbe", Overlay(image, 0x3c3c936, b"\x76"), relocations),
        ("wrong_time_add_slot", image, {**relocations, 0x64e7e88: (8, 0x3d66201)}),
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
