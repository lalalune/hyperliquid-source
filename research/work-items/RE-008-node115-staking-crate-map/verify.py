#!/usr/bin/env python3
"""Verify node #115 staking crate source-path/Location/FDE map and validator
lifecycle rules (`CValidatorAction` `0x2c77640`, `0x3c3d480`, `0x3c3a700`,
`ValidatorProfile::validate` `0x469b540`, `register_active_validator` `0x4225b80`)
(`RE-008-node115-staking-crate-map`).

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

EXPECTED_STAKING_FILES = [
    "l1/src/action/vote_global.rs",
    "l1/src/c_staking/jailing.rs",
    "l1/src/exchange/stake_requirement.rs",
    "l1/src/staking.rs",
]

CORE_FUNCTIONS = [
    ("c_validator_action_handler", 0x2C77640, 0x2C77BA5),
    ("c_staking_validator_lifecycle", 0x3C3D480, 0x3C3F412),
    ("c_staking_validate_profile", 0x3C3A700, 0x3C3ADF5),
    ("validator_profile_validate", 0x469B540, 0x469B725),
    ("register_active_validator", 0x4225B80, 0x4225C74),
]

WINDOWS = [
    ("c_val_action_reg_guards", "c_validator_action_handler", 0x2C77890, 0x2C778DE),
    ("c_val_action_wei_and_bal", "c_validator_action_handler", 0x2C77978, 0x2C779E4),
    ("lifecycle_max_1000", "c_staking_validator_lifecycle", 0x3C3D5CE, 0x3C3D5F7),
    ("lifecycle_unregister_144", "c_staking_validator_lifecycle", 0x3C3DACD, 0x3C3DAE8),
    ("lifecycle_cooldowns_135_136", "c_staking_validator_lifecycle", 0x3C3EB77, 0x3C3EC32),
    ("profile_validate_ip_and_len", "validator_profile_validate", 0x469B5DE, 0x469B620),
    ("profile_validate_commission", "validator_profile_validate", 0x469B620, 0x469B656),
    ("register_active_dup_97", "register_active_validator", 0x4225B9D, 0x4225BAC),
]

RELA_SLOTS = [
    ("slot_c_staking_validator_lifecycle", 0x64E7F10, 0x3C3D480),
    ("slot_validator_profile_validate", 0x64E9650, 0x469B540),
    ("slot_validator_signer_guard", 0x64E7F00, 0x3C377B0),
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


def scan_staking_inventory(
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
    for pat in [
        rb"l1/src/c_staking/[a-zA-Z0-9_./-]+\.rs",
        rb"l1/src/staking\.rs",
        rb"l1/src/exchange/stake_requirement\.rs",
        rb"l1/src/action/vote_global\.rs",
    ]:
        for m in re.finditer(pat, ro_bytes):
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
    fdes, starts, by_start = load_fdes()
    inventory = scan_staking_inventory(img, fdes, starts)

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

    rela_map = resolve_rela_slots(img)
    slot_records = []
    for name, slot_va, target_va in RELA_SLOTS:
        if rela_map.get(slot_va) != target_va:
            raise ValueError(f"slot {name} 0x{slot_va:x}: got {rela_map.get(slot_va)} != 0x{target_va:x}")
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
        "inventory": inventory,
        "core_functions": fn_records,
        "windows": win_records,
        "rela_slots": slot_records,
    }


def _find_insn(win: dict[str, Any], va_hex: str) -> dict[str, Any]:
    for row in win["insns"]:
        if row["va"] == va_hex:
            return row
    raise AssertionError(f"missing instruction {va_hex} in window {win['name']}")


def check_facts(records: dict[str, Any]) -> list[str]:
    inv = records["inventory"]
    wins = {w["name"]: w for w in records["windows"]}
    slots = {s["name"]: s for s in records["rela_slots"]}
    verified: list[str] = []

    def require(label: str, cond: bool, detail: str) -> None:
        if not cond:
            raise AssertionError(f"fact {label} failed: {detail}")
        verified.append(label)

    # 1. All 4 observed staking/jailing/stake-requirement/vote-global source paths mapped
    got_paths = [f["path"] for f in inv["files"]]
    require(
        "all_4_staking_source_files_mapped",
        got_paths == EXPECTED_STAKING_FILES
        and inv["total_locations"] == 12
        and all(f["location_count"] >= 1 and f["fde_count"] >= 1 for f in inv["files"]),
        f"paths={got_paths} locs={inv['total_locations']}",
    )

    # 2. CValidatorAction Register wei ceiling (0xccccccccccccccc) and disable_delegations 0x10c
    w_r = wins["c_val_action_reg_guards"]
    r_cap = _find_insn(w_r, "0x2c778a2")
    r_10c = _find_insn(w_r, "0x2c778d2")
    require(
        "c_val_action_wei_cap_and_disabled_10c",
        "0xccccccccccccccc" in r_cap["op_str"] and "0x10c" in r_10c["op_str"],
        f"{r_cap} / {r_10c}",
    )

    # 3. CValidatorAction self-delegation min (0x145) and balance check (0x10b)
    w_wb = wins["c_val_action_wei_and_bal"]
    r_145 = _find_insn(w_wb, "0x2c7799b")
    r_10b = _find_insn(w_wb, "0x2c779d1")
    require(
        "c_val_action_self_min_145_and_bal_10b",
        r_145["op_str"] == "dx, 0x145" and r_10b["op_str"] == "dx, 0x10b",
        f"{r_145} / {r_10b}",
    )

    # 4. Max 1,000 registered validators (<= 0x3e7 -> 0x96)
    w_m = wins["lifecycle_max_1000"]
    r_max = _find_insn(w_m, "0x3c3d5d3")
    r_96 = _find_insn(w_m, "0x3c3d5f0")
    require(
        "lifecycle_max_1000_validators_96",
        "0x3e7" in r_max["op_str"] and "0x96" in r_96["op_str"],
        f"{r_max} / {r_96}",
    )

    # 5. Unregister rejects non-zero delegations with 0x144
    w_u = wins["lifecycle_unregister_144"]
    r_u0 = _find_insn(w_u, "0x3c3dacd")
    r_144 = _find_insn(w_u, "0x3c3dadc")
    require(
        "lifecycle_unregister_zero_deleg_144",
        "[rbx + 0x20], 0" in r_u0["op_str"] and "0x144" in r_144["op_str"],
        f"{r_u0} / {r_144}",
    )

    # 6. Per-validator (0x135) and global (0x136) signer/IP change cooldowns
    w_cd = wins["lifecycle_cooldowns_135_136"]
    r_135 = _find_insn(w_cd, "0x3c3ebae")
    r_136 = _find_insn(w_cd, "0x3c3ec2c")
    require(
        "lifecycle_signer_ip_cooldowns_135_136",
        r_135["mnemonic"] == "ja"
        and "0x3c3f058" in r_135["op_str"]
        and r_136["mnemonic"] == "ja"
        and "0x3c3f083" in r_136["op_str"],
        f"{r_135} / {r_136}",
    )

    # 7. ValidatorProfile::validate IP global (0x12f), name 1..=50 (0x130), desc 1..=1000 (0x131)
    w_p = wins["profile_validate_ip_and_len"]
    r_12f = _find_insn(w_p, "0x469b5e1")
    r_130 = _find_insn(w_p, "0x469b5f6")
    r_131 = _find_insn(w_p, "0x469b60f")
    require(
        "profile_validate_ip_name_desc_12f_130_131",
        r_12f["op_str"] == "ax, 0x12f"
        and r_130["op_str"] == "ax, 0x130"
        and r_131["op_str"] == "ax, 0x131",
        f"{r_12f} / {r_130} / {r_131}",
    )

    # 8. ValidatorProfile::validate commission 0..=10_000 bps (0x2710) and increase cap <= 100 bps (< 0x65) -> 0x132
    w_c = wins["profile_validate_commission"]
    r_132 = _find_insn(w_c, "0x469b624")
    r_maxc = _find_insn(w_c, "0x469b628")
    r_inc = _find_insn(w_c, "0x469b647")
    require(
        "profile_validate_commission_132",
        r_132["op_str"] == "ax, 0x132"
        and r_maxc["op_str"] == "rdx, 0x2710"
        and r_inc["op_str"] == "rdx, 0x65",
        f"{r_132} / {r_maxc} / {r_inc}",
    )

    # 9. register_active_validator duplicate tag 0x97
    w_dup = wins["register_active_dup_97"]
    r_97 = _find_insn(w_dup, "0x4225b9d")
    require(
        "register_active_validator_dup_97",
        r_97["op_str"] == "ax, 0x97",
        str(r_97),
    )

    # 10. Relocation slots exact
    require(
        "rela_slots_exact",
        slots["slot_c_staking_validator_lifecycle"]["target_va"] == "0x3c3d480"
        and slots["slot_validator_profile_validate"]["target_va"] == "0x469b540"
        and slots["slot_validator_signer_guard"]["target_va"] == "0x3c377b0",
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

    def mut_drop_file(rec):
        rec["inventory"]["files"].pop()

    def mut_max_validators(rec):
        for w in rec["windows"]:
            if w["name"] == "lifecycle_max_1000":
                for r in w["insns"]:
                    if r["va"] == "0x3c3d5d3":
                        r["op_str"] = "qword ptr [rsi + 0xe8], 0x10"

    def mut_unregister_tag(rec):
        for w in rec["windows"]:
            if w["name"] == "lifecycle_unregister_144":
                for r in w["insns"]:
                    if r["va"] == "0x3c3dadc":
                        r["op_str"] = "word ptr [r12], 0x145"

    def mut_commission_inc(rec):
        for w in rec["windows"]:
            if w["name"] == "profile_validate_commission":
                for r in w["insns"]:
                    if r["va"] == "0x469b647":
                        r["op_str"] = "rdx, 0x200"

    def mut_dup_tag(rec):
        for w in rec["windows"]:
            if w["name"] == "register_active_dup_97":
                for r in w["insns"]:
                    if r["va"] == "0x4225b9d":
                        r["op_str"] = "ax, 0x98"

    def mut_profile_slot(rec):
        for s in rec["rela_slots"]:
            if s["name"] == "slot_validator_profile_validate":
                s["target_va"] = "0x469b999"

    expect_fail("drop_staking_source_file", mut_drop_file)
    expect_fail("corrupt_max_1000_validators", mut_max_validators)
    expect_fail("corrupt_unregister_tag_144", mut_unregister_tag)
    expect_fail("corrupt_commission_increase_cap_1pct", mut_commission_inc)
    expect_fail("corrupt_duplicate_validator_tag_97", mut_dup_tag)
    expect_fail("corrupt_profile_validate_slot", mut_profile_slot)
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
