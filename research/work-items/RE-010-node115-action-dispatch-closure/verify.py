#!/usr/bin/env python3
"""Static verifier and deterministic generator for RE-010-node115-action-dispatch-closure."""

from __future__ import annotations

import argparse
import copy
import fnmatch
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
RECORDS_PATH = HERE / "records.json"
COMPONENTS_PATH = REPO / "research" / "components.json"
ARMS_TSV_PATH = REPO / "research" / "work-items" / "action-dispatch-router-115" / "arms.tsv"
ROUTER_RS_PATH = REPO / "src" / "action-dispatch" / "src" / "router.rs"
FDE_TSV_PATH = REPO / "work" / "index" / "node-115-fde.tsv"
TARGET_REL = "artifacts/node/115/hl-node"
TARGET_SIZE = 105_896_032
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

CORE_DISPATCH_FDES: list[tuple[str, int, str]] = [
    ("central_action_router", 0x2BDA7C0, "Central 92-arm action router (jump table 0x609f00, flag 50 mask 0x501d)"),
    ("timed_action_router", 0x55F99B0, "Timed 92-arm action router (jump table 0x927b08, 17 arm shapes, arm 52 recursion)"),
    ("action_tag_selector", 0x2BDB5B0, "92-arm action tag selector (jump table 0x60a080, 36 targets)"),
    ("action_tag_classifier", 0x36C30F0, "92-arm action tag classifier (jump table 0x79afb0, 7 targets)"),
    ("action_tag_dispatcher", 0x2BDBAA0, "92-arm action tag dispatcher (jump table 0x60a360)"),
]

SHARED_ADMISSION_HELPER_FDES: list[tuple[str, int, str]] = [
    ("admission_alias_override", 0x2A8AB70, "Shared leading handler call 1: alias override lookup"),
    ("admission_hash_key", 0x4717440, "Shared leading handler call 2: 20-byte key hasher"),
    ("admission_probe_alias", 0x3ED25B0, "Shared leading handler call 3: alias table probe"),
    ("admission_check_1", 0x2C202B0, "Shared handler admission check 1 (0x1a2 success word)"),
    ("admission_check_2", 0x2C206B0, "Shared handler admission check 2 (0x1a2 success word)"),
]

ROUTER_CALLER_FDES: list[tuple[str, int, str]] = [
    ("router_caller_1", 0x27048A0, "Direct E8 caller of central router 0x2bda7c0 (2 sites: 0x2704c0c, 0x2704c54)"),
    ("router_caller_2", 0x2C69220, "Direct E8 caller of central router 0x2bda7c0 (2 sites: 0x2c69574, 0x2c69744)"),
    ("router_caller_3", 0x2C71250, "Direct E8 caller of central router 0x2bda7c0 (1 site: 0x2c719c3)"),
]

PRIOR_KEY_CLONE_VAS: set[int] = {
    0x2C05370,
    0x2C05C70,
    0x2C0E9A0,
    0x2C13570,
    0x2C14DE0,
    0x2C15220,
    0x2C16020,
    0x2C182B0,
    0x2C1AEE0,
    0x2C1C240,
}

INSTRUCTION_ANCHORS: list[tuple[str, int, str]] = [
    ("central_router_entry", 0x2BDA7C0, "554157415641554154534881ecb80000004989cf4989d449"),
    ("timed_router_entry", 0x55F99B0, "554157415641554154534881ec180100004d89cd4d89c449"),
    ("tag_selector_entry", 0x2BDB5B0, "534883ec304c8b064981e886000000b8140000004c0f42c0"),
    ("tag_classifier_entry", 0x36C30F0, "488b374881ee86000000b914000000480f42f131c0488d15"),
    ("tag_dispatcher_entry", 0x2BDBAA0, "554157415641554154534881ec180100004989cf4989d548"),
    ("prior_key_clone0_entry", 0x2C05370, "554157415641554154534881ecf800000048898c24d00000"),
    ("shared_admission_check1", 0x2C202B0, "554157415641554154534883ec584889"),
    ("shared_admission_check2", 0x2C206B0, "554157415641554154534881ec280100"),
]

RODATA_CONSTANTS: list[tuple[str, int, str]] = [
    ("central_router_jtab_head", 0x609F00, "4c095d02050e5d02830d5d02d10d5d02ba0c5d02b40e5d022c0f5d02eb0d5d02"),
    ("timed_router_jtab_head", 0x927B08, "231fcd046926cd048525cd040f26cd044824cd040628cd04b828cd043c26cd04"),
    ("tag_selector_jtab_head", 0x60A080, "75155d0275155d0269165d02a3175d029b165d0275155d0275155d02b8175d02"),
    ("tag_classifier_jtab_head", 0x79AFB0, "6581f2026581f2029081f2028d81f2028d81f2026581f2026581f2026581f202"),
    ("tag_dispatcher_jtab_head", 0x60A360, "cf175d02151f5d02311e5d02bb1e5d02f41c5d02b2205d0264215d02e81e5d02"),
]


def parse_elf_sections(data: bytes) -> dict[str, tuple[int, int, int]]:
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    shstr_off = struct.unpack_from("<Q", data, e_shoff + e_shstrndx * e_shentsize + 24)[0]
    sections: dict[str, tuple[int, int, int]] = {}
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name, _t, _f, sh_addr, sh_offset, sh_size = struct.unpack_from("<IIQQQQ", data, off)
        end = data.index(b"\x00", shstr_off + sh_name)
        sections[data[shstr_off + sh_name : end].decode("ascii")] = (sh_addr, sh_offset, sh_size)
    return sections


def load_fde_index() -> dict[int, int]:
    fdes: dict[int, int] = {}
    with FDE_TSV_PATH.open("r", encoding="utf-8") as fh:
        for line in fh:
            parts = line.strip().split("\t")
            if len(parts) >= 2 and parts[0].startswith("0x"):
                fdes[int(parts[0], 16)] = int(parts[1], 16)
    return fdes


def classify_l1_path(src_path: str, components: list[dict]) -> str:
    norm = "l1/" + src_path[len("l1/src/") :]
    for comp in components:
        for pat in comp["patterns"]:
            if fnmatch.fnmatch(norm, pat):
                return comp["id"]
    return "UNCLASSIFIED"


def scan_action_dispatch_locations(
    data: bytes, sections: dict[str, tuple[int, int, int]], components: list[dict]
) -> dict[int, tuple[str, int, int]]:
    ro_va, ro_off, ro_sz = sections[".rodata"]
    dr_va, dr_off, dr_sz = sections[".data.rel.ro"]
    rela_va, rela_off, rela_sz = sections[".rela.dyn"]
    locs: dict[int, tuple[str, int, int]] = {}
    for off in range(rela_off, rela_off + rela_sz, 24):
        r_offset, r_info, r_addend = struct.unpack_from("<QQq", data, off)
        if (
            (r_info & 0xFFFFFFFF) == 8
            and dr_va <= r_offset < dr_va + dr_sz
            and ro_va <= r_addend < ro_va + ro_sz
        ):
            raw = data[ro_off + (r_addend - ro_va) : ro_off + (r_addend - ro_va) + 96]
            if raw.startswith(b"l1/src/"):
                doff = dr_off + (r_offset - dr_va)
                slen, line, col = struct.unpack_from("<QII", data, doff + 8)
                if 10 <= slen <= 128 and 1 <= line <= 50000 and 1 <= col <= 500:
                    try:
                        path_str = data[
                            ro_off + (r_addend - ro_va) : ro_off + (r_addend - ro_va) + slen
                        ].decode("ascii")
                    except UnicodeDecodeError:
                        continue
                    if path_str.endswith(".rs") and classify_l1_path(path_str, components) == "action-dispatch":
                        locs[r_offset] = (path_str, line, col)
    return locs


def load_router_arms() -> list[tuple[int, int, int, str, bool]]:
    rows = []
    for line in ARMS_TSV_PATH.read_text(encoding="utf-8").splitlines()[1:]:
        parts = line.split("\t")
        rows.append((int(parts[0]), int(parts[1], 16), int(parts[2], 16), parts[3], parts[4] == "1"))
    return rows


def load_rust_router_handlers() -> dict[int, int]:
    text = ROUTER_RS_PATH.read_text(encoding="utf-8")
    out: dict[int, int] = {}
    for m in re.finditer(r"RouterArm\s*\{\s*index:\s*(\d+),\s*canonical_tag:\s*0x[0-9a-f]+,\s*handler_va:\s*(0x[0-9a-f]+)", text):
        out[int(m.group(1))] = int(m.group(2), 16)
    return out


def build_records(data: bytes, fdes: dict[int, int], arms: list[tuple[int, int, int, str, bool]]) -> dict:
    core_rows = []
    core_bytes = 0
    for name, s, role in CORE_DISPATCH_FDES:
        e = fdes[s]
        sz = e - s
        core_bytes += sz
        core_rows.append({"name": name, "start": hex(s), "end": hex(e), "size": sz, "role": role})

    handler_rows = []
    handler_bytes = 0
    for idx, tag, hva, arg_shape, gated in arms:
        e = fdes[hva]
        sz = e - hva
        handler_bytes += sz
        handler_rows.append(
            {
                "index": idx,
                "tag": hex(tag),
                "start": hex(hva),
                "end": hex(e),
                "size": sz,
                "arg_shape": arg_shape,
                "gated_by_flag_50": gated,
                "is_prior_key_clone": hva in PRIOR_KEY_CLONE_VAS,
            }
        )

    helper_rows = []
    helper_bytes = 0
    for name, s, role in SHARED_ADMISSION_HELPER_FDES:
        e = fdes[s]
        sz = e - s
        helper_bytes += sz
        helper_rows.append({"name": name, "start": hex(s), "end": hex(e), "size": sz, "role": role})

    caller_rows = []
    caller_bytes = 0
    for name, s, role in ROUTER_CALLER_FDES:
        e = fdes[s]
        sz = e - s
        caller_bytes += sz
        caller_rows.append({"name": name, "start": hex(s), "end": hex(e), "size": sz, "role": role})

    return {
        "work_item": "RE-010-node115-action-dispatch-closure",
        "component": "action-dispatch",
        "target_binary": {
            "path": TARGET_REL,
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "coordinate_system": "ELF64 linked virtual address",
        },
        "observed_source_files": [],
        "location_count": 0,
        "location_note": (
            "Zero .data.rel.ro Location entries match l1/src/exchange/handlers/* or "
            "l1/src/exchange/impl_execute_action.rs in node #115 because those split paths were "
            "agent-created planning patterns (research/components.json); actual #115 dispatch lives "
            "in the 5 central dispatch/router FDEs, 92 router handler FDEs, 5 shared admission helpers, "
            "and 3 direct router-caller FDEs recorded here."
        ),
        "core_dispatch_fdes": core_rows,
        "router_handler_fdes": handler_rows,
        "shared_admission_helper_fdes": helper_rows,
        "router_caller_fdes": caller_rows,
        "instruction_anchors": [
            {"name": name, "va": hex(va), "hex": hx} for name, va, hx in INSTRUCTION_ANCHORS
        ],
        "rodata_constants": [
            {"name": name, "va": hex(va), "hex": hx} for name, va, hx in RODATA_CONSTANTS
        ],
        "summary": {
            "observed_source_files": 0,
            "location_count": 0,
            "core_dispatch_fdes": len(core_rows),
            "core_dispatch_fde_bytes": core_bytes,
            "router_handler_fdes": len(handler_rows),
            "router_handler_fde_bytes": handler_bytes,
            "prior_key_clone_count": sum(1 for r in handler_rows if r["is_prior_key_clone"]),
            "shared_admission_helper_fdes": len(helper_rows),
            "shared_admission_helper_fde_bytes": helper_bytes,
            "router_caller_fdes": len(caller_rows),
            "router_caller_fde_bytes": caller_bytes,
            "combined_unique_fdes": len(core_rows) + len(handler_rows) + len(helper_rows) + len(caller_rows),
            "combined_unique_fde_bytes": core_bytes + handler_bytes + helper_bytes + caller_bytes,
        },
    }


def verify_records(
    records: dict,
    data: bytes,
    sections: dict[str, tuple[int, int, int]],
    fdes: dict[int, int],
    observed_locs: dict[int, tuple[str, int, int]],
    arms: list[tuple[int, int, int, str, bool]],
    rust_handlers: dict[int, int],
) -> None:
    tb = records["target_binary"]
    if len(data) != tb["size"] or tb["size"] != TARGET_SIZE:
        raise AssertionError("binary size mismatch")
    if hashlib.sha256(data).hexdigest() != tb["sha256"] or tb["sha256"] != TARGET_SHA256:
        raise AssertionError("binary sha256 mismatch")

    if len(observed_locs) != records["location_count"] or len(observed_locs) != 0:
        raise AssertionError(f"unexpected action-dispatch Locations: {len(observed_locs)}")
    if records["observed_source_files"] != []:
        raise AssertionError("observed_source_files must be empty")

    all_seen: set[int] = set()

    def check_group(entries: list[dict], label: str) -> tuple[int, int]:
        total = 0
        for entry in entries:
            s = int(entry["start"], 16)
            e = int(entry["end"], 16)
            sz = int(entry["size"])
            if s in all_seen:
                raise AssertionError(f"duplicate or overlapping FDE 0x{s:x} in {label}")
            all_seen.add(s)
            if e - s != sz or fdes.get(s) != e:
                raise AssertionError(f"FDE mismatch in {label} at 0x{s:x}")
            total += sz
        return len(entries), total

    c_cnt, c_bytes = check_group(records["core_dispatch_fdes"], "core_dispatch_fdes")
    h_cnt, h_bytes = check_group(records["router_handler_fdes"], "router_handler_fdes")
    a_cnt, a_bytes = check_group(records["shared_admission_helper_fdes"], "shared_admission_helper_fdes")
    r_cnt, r_bytes = check_group(records["router_caller_fdes"], "router_caller_fdes")

    if h_cnt != 92 or len(arms) != 92 or len(rust_handlers) != 92:
        raise AssertionError(f"expected 92 router handlers, got {h_cnt}/{len(arms)}/{len(rust_handlers)}")

    clone_count = 0
    for row, (idx, tag, hva, _shape, _gated) in zip(records["router_handler_fdes"], arms):
        if row["index"] != idx or int(row["tag"], 16) != tag or int(row["start"], 16) != hva:
            raise AssertionError(f"router arm {idx} mismatch against arms.tsv")
        if rust_handlers.get(idx) != hva:
            raise AssertionError(f"router.rs arm {idx} VA mismatch: {hex(rust_handlers.get(idx, 0))} != {hex(hva)}")
        if row["is_prior_key_clone"]:
            if row["size"] != 1087:
                raise AssertionError(f"prior-key clone {idx} expected 1087 B, got {row['size']}")
            clone_count += 1
    if clone_count != 10:
        raise AssertionError(f"expected 10 prior-key clones, got {clone_count}")

    sm = records["summary"]
    if (
        sm["core_dispatch_fdes"] != c_cnt
        or sm["core_dispatch_fde_bytes"] != c_bytes
        or sm["router_handler_fdes"] != h_cnt
        or sm["router_handler_fde_bytes"] != h_bytes
        or sm["prior_key_clone_count"] != clone_count
        or sm["shared_admission_helper_fdes"] != a_cnt
        or sm["shared_admission_helper_fde_bytes"] != a_bytes
        or sm["router_caller_fdes"] != r_cnt
        or sm["router_caller_fde_bytes"] != r_bytes
        or sm["combined_unique_fdes"] != len(all_seen)
        or sm["combined_unique_fde_bytes"] != c_bytes + h_bytes + a_bytes + r_bytes
    ):
        raise AssertionError("summary counts mismatch")

    text_va, text_off, text_sz = sections[".text"]
    ro_va, ro_off, ro_sz = sections[".rodata"]

    for anc in records["instruction_anchors"]:
        va = int(anc["va"], 16)
        want = bytes.fromhex(anc["hex"])
        if not (text_va <= va and va + len(want) <= text_va + text_sz):
            raise AssertionError(f"anchor out of .text: {anc['name']}")
        got = data[text_off + (va - text_va) : text_off + (va - text_va) + len(want)]
        if got != want:
            raise AssertionError(f"anchor mismatch for {anc['name']}: {got.hex()} != {want.hex()}")

    for cst in records["rodata_constants"]:
        va = int(cst["va"], 16)
        want = bytes.fromhex(cst["hex"])
        if not (ro_va <= va and va + len(want) <= ro_va + ro_sz):
            raise AssertionError(f"constant out of .rodata: {cst['name']}")
        got = data[ro_off + (va - ro_va) : ro_off + (va - ro_va) + len(want)]
        if got != want:
            raise AssertionError(f"constant mismatch for {cst['name']}: {got.hex()} != {want.hex()}")


def run_negative_controls(
    records: dict,
    data: bytes,
    sections: dict[str, tuple[int, int, int]],
    fdes: dict[int, int],
    observed_locs: dict[int, tuple[str, int, int]],
    arms: list[tuple[int, int, int, str, bool]],
    rust_handlers: dict[int, int],
) -> int:
    mutations = [
        ("bad_loc_count", lambda r: r.update({"location_count": 1})),
        (
            "bad_handler_end",
            lambda r: r["router_handler_fdes"][0].update({"size": r["router_handler_fdes"][0]["size"] + 1}),
        ),
        (
            "bad_opcode",
            lambda r: r["instruction_anchors"][0].update({"hex": "00" + r["instruction_anchors"][0]["hex"][2:]}),
        ),
        (
            "bad_jtab_constant",
            lambda r: r["rodata_constants"][0].update({"hex": "ff" + r["rodata_constants"][0]["hex"][2:]}),
        ),
    ]
    rejected = 0
    for name, mutate in mutations:
        bad = copy.deepcopy(records)
        mutate(bad)
        try:
            verify_records(bad, data, sections, fdes, observed_locs, arms, rust_handlers)
        except AssertionError:
            rejected += 1
        else:
            raise AssertionError(f"negative control {name} unexpectedly passed")
    return rejected


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--generate", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    components = json.loads(COMPONENTS_PATH.read_text(encoding="utf-8"))["components"]
    data = (REPO / TARGET_REL).read_bytes()
    sections = parse_elf_sections(data)
    fdes = load_fde_index()
    observed_locs = scan_action_dispatch_locations(data, sections, components)
    arms = load_router_arms()
    rust_handlers = load_rust_router_handlers()

    if args.generate:
        records = build_records(data, fdes, arms)
        RECORDS_PATH.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    else:
        records = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))

    verify_records(records, data, sections, fdes, observed_locs, arms, rust_handlers)
    neg = 0
    if args.self_test:
        neg = run_negative_controls(records, data, sections, fdes, observed_locs, arms, rust_handlers)
    sm = records["summary"]
    print(
        f"PASS: action-dispatch closure verified — 0/0 split-path Locations, "
        f"{sm['core_dispatch_fdes']}/5 core dispatch FDEs ({sm['core_dispatch_fde_bytes']} B), "
        f"{sm['router_handler_fdes']}/92 router handler FDEs ({sm['router_handler_fde_bytes']} B, "
        f"{sm['prior_key_clone_count']}/10 prior-key clones), "
        f"{sm['shared_admission_helper_fdes']}/5 shared admission helpers ({sm['shared_admission_helper_fde_bytes']} B), "
        f"{sm['router_caller_fdes']}/3 router callers ({sm['router_caller_fde_bytes']} B), "
        f"combined {sm['combined_unique_fdes']} unique FDEs ({sm['combined_unique_fde_bytes']} B), "
        f"{neg}/4 negative controls rejected"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
