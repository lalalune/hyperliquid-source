#!/usr/bin/env python3
"""Static binary verifier for RE-008-node115-staking-governance-and-requirements."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
RECORDS_PATH = HERE / "records.json"
FDE_TSV_PATH = REPO / "work" / "index" / "node-115-fde.tsv"
TARGET_REL = "artifacts/node/115/hl-node"
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET_SIZE = 105896032

FDE_SPECS: list[tuple[str, int]] = [
    ("gov_vote", 0x3C33F10),
    ("prune_expired_proposals", 0x3C33520),
    ("stake_requirement_iter_next", 0x294CEB0),
    ("stake_requirement_collect_a", 0x235A050),
    ("stake_requirement_collect_b", 0x5B7A610),
    ("stake_requirement_collect_c", 0x5B9C890),
    ("stake_requirement_count_category", 0x2C58C70),
    ("stake_requirement_iter_b", 0x543EF80),
    ("stake_requirement_iter_c", 0x543FFC0),
    ("staking_validator_stake_rollup", 0x3DD9480),
    ("staking_saturating_sum_stakes", 0x4351DE0),
]

WINDOW_SPECS: list[tuple[str, int, int]] = [
    ("gov_vote_4x_boost_shift_guard", 0x3C343CB, 0x3C343E2),
    ("gov_vote_ended_tag_0x117", 0x3C340B5, 0x3C340CF),
    ("gov_vote_dup_and_zero_tags", 0x3C3431E, 0x3C34330),
    ("gov_vote_ok_tag_0x1a2", 0x3C3476E, 0x3C3477D),
    ("gov_prune_ge_end_time", 0x3C336E8, 0x3C33704),
    ("stake_req_table_mul_checked", 0x294CF53, 0x294CF6A),
    ("staking_rollup_saturating_add", 0x4351E40, 0x4351E4F),
]

EXPECTED_STAKE_TABLE: list[tuple[int, list[int]]] = [
    (0x457D00, [100_000, 10_000_000_000, 10_000_000_000, 50_000_000_000_000]),
    (0x457B00, [50_000, 20_000_000_000_000, 5_000_000_000, 20_000_000_000_000]),
    (0x457F00, [200_000, 50_000_000_000_000, 10_000_000_000, 50_000_000_000_000]),
    (0x457D00, [100_000, 10_000_000_000, 10_000_000_000, 50_000_000_000_000]),
]

EXPECTED_CATEGORY_ARMS = [0x2C58C9F, 0x2C58E0F, 0x2C58CEE, 0x2C58DCD]

EXPECTED_USER_ERRORS: list[tuple[int, int, str]] = [
    (0xC5, 0x46EFD79, "Mul result error"),
    (0x114, 0x46F2307, "Proposal does not exist"),
    (0x115, 0x46F27EC, "Already voted"),
    (0x116, 0x46F0DD8, "Insufficient delegations to vote"),
    (0x117, 0x46F043B, "Voting on the proposal has already ended."),
]


def parse_elf_sections(data: bytes) -> dict[str, tuple[int, int, int]]:
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    shstr_off = struct.unpack_from("<Q", data, e_shoff + e_shstrndx * e_shentsize + 24)[0]
    sections: dict[str, tuple[int, int, int]] = {}
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name, _sh_type, _sh_flags, sh_addr, sh_offset, sh_size = struct.unpack_from(
            "<IIQQQQ", data, off
        )
        end = data.index(b"\x00", shstr_off + sh_name)
        sections[data[shstr_off + sh_name : end].decode("ascii")] = (sh_addr, sh_offset, sh_size)
    return sections


def load_fde_map() -> dict[int, int]:
    fdes: dict[int, int] = {}
    with FDE_TSV_PATH.open("r", encoding="utf-8") as fh:
        for line in fh:
            parts = line.strip().split("\t")
            if len(parts) >= 2 and parts[0].startswith("0x"):
                fdes[int(parts[0], 16)] = int(parts[1], 16)
    return fdes


def slice_va(data: bytes, sec: tuple[int, int, int], s: int, e: int) -> bytes:
    va, off, sz = sec
    if not (va <= s <= e <= va + sz):
        raise AssertionError(f"VA range 0x{s:x}..0x{e:x} outside section 0x{va:x}..0x{va+sz:x}")
    return data[off + (s - va) : off + (e - va)]


def build_records(data: bytes, secs: dict[str, tuple[int, int, int]], fdes: dict[int, int]) -> dict:
    text_sec = secs[".text"]
    ro_sec = secs[".rodata"]

    fde_rows = []
    total_fde_bytes = 0
    for name, s in FDE_SPECS:
        e = fdes[s]
        b = slice_va(data, text_sec, s, e)
        total_fde_bytes += len(b)
        fde_rows.append(
            {
                "name": name,
                "start_va": f"0x{s:x}",
                "end_va": f"0x{e:x}",
                "size": len(b),
                "sha256": hashlib.sha256(b).hexdigest(),
            }
        )

    win_rows = []
    for name, s, e in WINDOW_SPECS:
        b = slice_va(data, text_sec, s, e)
        win_rows.append(
            {
                "name": name,
                "start_va": f"0x{s:x}",
                "end_va": f"0x{e:x}",
                "size": len(b),
                "bytes_hex": b.hex(),
            }
        )

    stake_rows = []
    for cat in range(4):
        rel = struct.unpack_from("<i", slice_va(data, ro_sec, 0x602D1C + cat * 4, 0x602D1C + (cat + 1) * 4), 0)[0]
        row_va = 0x602D1C + rel
        vals = list(struct.unpack_from("<4Q", slice_va(data, ro_sec, row_va, row_va + 32), 0))
        stake_rows.append({"category": cat, "row_va": f"0x{row_va:x}", "chains": vals})

    cat_arms = []
    for cat in range(4):
        rel = struct.unpack_from("<i", slice_va(data, ro_sec, 0x60AEEC + cat * 4, 0x60AEEC + (cat + 1) * 4), 0)[0]
        cat_arms.append({"category": cat, "arm_va": f"0x{0x60AEEC + rel:x}"})

    user_errors = []
    for tag, exp_arm, exp_msg in EXPECTED_USER_ERRORS:
        rel = struct.unpack_from("<i", slice_va(data, ro_sec, 0x7D8C1C + tag * 4, 0x7D8C1C + (tag + 1) * 4), 0)[0]
        arm_va = 0x7D8C1C + rel
        if arm_va != exp_arm:
            raise AssertionError(f"UserError 0x{tag:x} arm mismatch: 0x{arm_va:x} != 0x{exp_arm:x}")
        user_errors.append({"tag": tag, "tag_hex": f"0x{tag:x}", "arm_va": f"0x{arm_va:x}", "message": exp_msg})

    return {
        "schema_version": 1,
        "work_item": "RE-008-node115-staking-governance-and-requirements",
        "target_binary": {
            "path": TARGET_REL,
            "size": TARGET_SIZE,
            "sha256": TARGET_SHA256,
        },
        "summary": {
            "fde_count": len(fde_rows),
            "fde_total_bytes": total_fde_bytes,
            "instruction_windows": len(win_rows),
            "stake_requirement_rows": len(stake_rows),
            "user_error_anchors": len(user_errors),
        },
        "fdes": fde_rows,
        "instruction_windows": win_rows,
        "stake_requirement_table": {
            "offset_table_va": "0x602d1c",
            "category_jump_table_va": "0x60aeec",
            "rows": stake_rows,
            "category_arms": cat_arms,
        },
        "user_error_anchors": {
            "jump_table_va": "0x7d8c1c",
            "entries": user_errors,
        },
    }


def verify_records(records: dict, data: bytes, secs: dict[str, tuple[int, int, int]], fdes: dict[int, int]) -> None:
    tb = records["target_binary"]
    if len(data) != tb["size"] or hashlib.sha256(data).hexdigest() != tb["sha256"]:
        raise AssertionError("target binary identity mismatch")

    text_sec = secs[".text"]
    ro_sec = secs[".rodata"]

    tot_fde = 0
    for row in records["fdes"]:
        s = int(row["start_va"], 16)
        e = int(row["end_va"], 16)
        if fdes.get(s) != e or e - s != row["size"]:
            raise AssertionError(f"FDE mismatch for {row['name']}")
        b = slice_va(data, text_sec, s, e)
        if hashlib.sha256(b).hexdigest() != row["sha256"]:
            raise AssertionError(f"FDE sha256 mismatch for {row['name']}")
        tot_fde += len(b)

    for w in records["instruction_windows"]:
        s = int(w["start_va"], 16)
        e = int(w["end_va"], 16)
        b = slice_va(data, text_sec, s, e)
        if len(b) != w["size"] or b.hex() != w["bytes_hex"]:
            raise AssertionError(f"instruction window mismatch for {w['name']}")

    # Check 4x4 stake requirement table
    st = records["stake_requirement_table"]
    off_tbl = int(st["offset_table_va"], 16)
    for idx, (row, (exp_row_va, exp_vals)) in enumerate(zip(st["rows"], EXPECTED_STAKE_TABLE)):
        rel = struct.unpack_from("<i", slice_va(data, ro_sec, off_tbl + idx * 4, off_tbl + (idx + 1) * 4), 0)[0]
        row_va = off_tbl + rel
        vals = list(struct.unpack_from("<4Q", slice_va(data, ro_sec, row_va, row_va + 32), 0))
        if row_va != exp_row_va or int(row["row_va"], 16) != row_va or vals != exp_vals or row["chains"] != exp_vals:
            raise AssertionError(f"stake requirement table mismatch at category {idx}")

    cat_tbl = int(st["category_jump_table_va"], 16)
    for idx, (arm_rec, exp_arm) in enumerate(zip(st["category_arms"], EXPECTED_CATEGORY_ARMS)):
        rel = struct.unpack_from("<i", slice_va(data, ro_sec, cat_tbl + idx * 4, cat_tbl + (idx + 1) * 4), 0)[0]
        arm_va = cat_tbl + rel
        if arm_va != exp_arm or int(arm_rec["arm_va"], 16) != arm_va:
            raise AssertionError(f"category jump table mismatch at category {idx}")

    # Check UserError jump table + exact .rodata string target in each arm
    ue = records["user_error_anchors"]
    jt = int(ue["jump_table_va"], 16)
    for entry in ue["entries"]:
        tag = int(entry["tag"])
        rel = struct.unpack_from("<i", slice_va(data, ro_sec, jt + tag * 4, jt + (tag + 1) * 4), 0)[0]
        arm_va = jt + rel
        if arm_va != int(entry["arm_va"], 16):
            raise AssertionError(f"UserError arm mismatch for tag 0x{tag:x}")
        arm_bytes = slice_va(data, text_sec, arm_va, arm_va + 0x40)
        msg_bytes = entry["message"].encode("ascii")
        # Locate RIP-relative LEA in the arm pointing to msg_bytes in .rodata
        matched_msg = False
        ro_va, ro_off, ro_sz = ro_sec
        for i in range(len(arm_bytes) - 7):
            if arm_bytes[i] in (0x48, 0x4C) and arm_bytes[i + 1] == 0x8D and (arm_bytes[i + 2] & 0xC7) == 0x05:
                disp = struct.unpack_from("<i", arm_bytes, i + 3)[0]
                tva = arm_va + i + 7 + disp
                if ro_va <= tva and tva + len(msg_bytes) <= ro_va + ro_sz:
                    if data[ro_off + (tva - ro_va) : ro_off + (tva - ro_va) + len(msg_bytes)] == msg_bytes:
                        matched_msg = True
                        break
        if not matched_msg:
            raise AssertionError(f"UserError message {entry['message']!r} not anchored in arm 0x{arm_va:x}")

    sm = records["summary"]
    if (
        sm["fde_count"] != len(records["fdes"])
        or sm["fde_total_bytes"] != tot_fde
        or sm["instruction_windows"] != len(records["instruction_windows"])
        or sm["stake_requirement_rows"] != len(st["rows"])
        or sm["user_error_anchors"] != len(ue["entries"])
    ):
        raise AssertionError("summary count mismatch")


def run_negative_controls(records: dict, data: bytes, secs: dict[str, tuple[int, int, int]], fdes: dict[int, int]) -> int:
    def mut_fde_sha(r: dict) -> None:
        r["fdes"][0]["sha256"] = "0" * 64

    def mut_window_bytes(r: dict) -> None:
        h = r["instruction_windows"][0]["bytes_hex"]
        r["instruction_windows"][0]["bytes_hex"] = ("ff" if not h.startswith("ff") else "00") + h[2:]

    def mut_stake_val(r: dict) -> None:
        r["stake_requirement_table"]["rows"][0]["chains"][3] += 1

    def mut_error_msg(r: dict) -> None:
        r["user_error_anchors"]["entries"][1]["message"] = "Wrong error text"

    rejected = 0
    for name, fn in [
        ("bad_fde_sha", mut_fde_sha),
        ("bad_window_bytes", mut_window_bytes),
        ("bad_stake_table_value", mut_stake_val),
        ("bad_user_error_msg", mut_error_msg),
    ]:
        m = copy.deepcopy(records)
        fn(m)
        try:
            verify_records(m, data, secs, fdes)
        except AssertionError:
            rejected += 1
        else:
            raise AssertionError(f"negative control {name} was NOT rejected")
    return rejected


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    data = (REPO / TARGET_REL).read_bytes()
    secs = parse_elf_sections(data)
    fdes = load_fde_map()

    if args.write:
        records = build_records(data, secs, fdes)
        RECORDS_PATH.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    else:
        records = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))

    verify_records(records, data, secs, fdes)
    sm = records["summary"]
    msg = (
        f"PASS: {sm['fde_count']}/{sm['fde_count']} FDEs ({sm['fde_total_bytes']} B), "
        f"{sm['instruction_windows']} windows, {sm['stake_requirement_rows']}x4 stake table, "
        f"{sm['user_error_anchors']} UserError anchors verified"
    )
    if args.self_test:
        neg = run_negative_controls(records, data, secs, fdes)
        msg += f", {neg}/{neg} negative controls rejected"
    print(msg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
