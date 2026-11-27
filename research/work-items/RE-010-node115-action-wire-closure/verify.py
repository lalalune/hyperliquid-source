#!/usr/bin/env python3
"""Static verifier and deterministic generator for RE-010-node115-action-wire-closure."""

from __future__ import annotations

import argparse
import bisect
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
FDE_TSV_PATH = REPO / "work" / "index" / "node-115-fde.tsv"
TARGET_REL = "artifacts/node/115/hl-node"
TARGET_SIZE = 105_896_032
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

LEA_RIP_RE = re.compile(rb"[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]")

BUSINESS_FDES: list[tuple[str, int, str]] = [
    ("eip712_domain_separator", 0x169E950, "EIP-712 HyperliquidSignTransaction domain separator"),
    ("eip712_signing_digest", 0x44E5DB0, "EIP-712 0x19 0x01 signing digest builder"),
    ("action_method_dispatcher", 0x36C3180, "92-variant Action method dispatcher (table 0x79b120)"),
    ("action_serializer_dispatch", 0x2BCE570, "92-variant Action serde serializer dispatch"),
    ("error_display_418_tags", 0x46EF710, "418-tag Action error Display formatter (table 0x7d8c1c)"),
    ("error_template_decoder", 0x1680500, "core::fmt::Arguments template byte decoder"),
]

INSTRUCTION_ANCHORS: list[tuple[str, int, str]] = [
    ("rmp_signable_bswap_nonce", 0x36AAA26, "4d8b6710488b04244889c14c29f14883f9070f8653020000490fcc48"),
    ("rmp_signable_vault_tag_1", 0x36AAA53, "41807f1801755d4839c2750e4889e7ff1520"),
    ("vault_transfer_loc_call", 0x283C6DC, "4c8d1d3df4bf03488d7c2438488d5424084c8d4c24204889"),
    ("withdraw3_loc_call", 0x246CD3C, "4c8d1d9537fc03488d7c2438488d5424084c8d4c24204889"),
    ("user_outcome_enable_guard", 0x283B5B0, "4889f880b9a902000000741780b9a802000000741866c7401093"),
    ("vote_global_loc_call", 0x28D467A, "80f9010f8513120000488d35bec0b603bf03000000ff1513"),
    ("eip712_signing_digest_entry", 0x44E5DB0, "554157415641554154534883ec284885"),
]

RODATA_LITERALS: list[tuple[str, int, str]] = [
    ("action_delayer_struct_desc", 0x5C9A34, "struct ActionDelayer with 6 elements"),
    ("delayed_action_struct_name", 0x5C9A83, "struct DelayedAction"),
    ("rmp_signable_path", 0x4470C4, "l1/src/action/rmp_signable.rs"),
    ("vault_transfer_path", 0x431977, "l1/src/action/vault_transfer.rs"),
    ("user_outcome_path", 0x43F111, "l1/src/action/user_outcome.rs"),
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


def load_fde_index() -> tuple[dict[int, int], list[tuple[int, int]]]:
    fdes: dict[int, int] = {}
    ordered: list[tuple[int, int]] = []
    with FDE_TSV_PATH.open("r", encoding="utf-8") as fh:
        for line in fh:
            parts = line.strip().split("\t")
            if len(parts) >= 2 and parts[0].startswith("0x"):
                s = int(parts[0], 16)
                e = int(parts[1], 16)
                fdes[s] = e
                ordered.append((s, e))
    ordered.sort()
    return fdes, ordered


def classify_l1_path(src_path: str, components: list[dict]) -> str:
    norm = "l1/" + src_path[len("l1/src/") :]
    for comp in components:
        for pat in comp["patterns"]:
            if fnmatch.fnmatch(norm, pat):
                return comp["id"]
    return "UNCLASSIFIED"


def scan_action_wire_locations(
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
                    if path_str.endswith(".rs") and classify_l1_path(path_str, components) == "action-wire":
                        locs[r_offset] = (path_str, line, col)
    return locs


def scan_location_referencing_fdes(
    data: bytes,
    sections: dict[str, tuple[int, int, int]],
    ordered_fdes: list[tuple[int, int]],
    loc_vas: set[int],
) -> dict[int, list[int]]:
    text_va, text_off, text_sz = sections[".text"]
    text = data[text_off : text_off + text_sz]
    fde_starts = [s for s, _ in ordered_fdes]
    fde_to_locs: dict[int, set[int]] = {}
    for m in LEA_RIP_RE.finditer(text):
        i = m.start()
        if i + 7 > len(text):
            continue
        disp = struct.unpack_from("<i", text, i + 3)[0]
        target = text_va + i + 7 + disp
        if target in loc_vas:
            ins_va = text_va + i
            idx = bisect.bisect_right(fde_starts, ins_va) - 1
            if idx >= 0 and ordered_fdes[idx][0] <= ins_va < ordered_fdes[idx][1]:
                fde_to_locs.setdefault(ordered_fdes[idx][0], set()).add(target)
    return {s: sorted(vas) for s, vas in sorted(fde_to_locs.items())}


def build_records(
    data: bytes,
    fdes: dict[int, int],
    observed_locs: dict[int, tuple[str, int, int]],
    fde_to_locs: dict[int, list[int]],
) -> dict:
    obs_files = sorted({f for f, _, _ in observed_locs.values()})
    loc_rows = [
        {"va": hex(va), "file": f, "line": ln, "col": col}
        for va, (f, ln, col) in sorted(observed_locs.items(), key=lambda kv: (kv[1][0], kv[1][1], kv[0]))
    ]
    loc_fde_rows = []
    loc_bytes = 0
    for s, vas in sorted(fde_to_locs.items()):
        e = fdes[s]
        sz = e - s
        loc_bytes += sz
        files = sorted({observed_locs[v][0] for v in vas})
        loc_fde_rows.append(
            {
                "start": hex(s),
                "end": hex(e),
                "size": sz,
                "location_vas": [hex(v) for v in vas],
                "source_files": files,
            }
        )
    biz_rows = []
    biz_bytes = 0
    for name, s, role in BUSINESS_FDES:
        e = fdes[s]
        sz = e - s
        biz_bytes += sz
        biz_rows.append({"name": name, "start": hex(s), "end": hex(e), "size": sz, "role": role})
    return {
        "work_item": "RE-010-node115-action-wire-closure",
        "component": "action-wire",
        "target_binary": {
            "path": TARGET_REL,
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "coordinate_system": "ELF64 linked virtual address",
        },
        "observed_source_files": obs_files,
        "location_count": len(loc_rows),
        "locations": loc_rows,
        "action_wire_location_fdes": loc_fde_rows,
        "action_wire_business_fdes": biz_rows,
        "instruction_anchors": [
            {"name": name, "va": hex(va), "hex": hx} for name, va, hx in INSTRUCTION_ANCHORS
        ],
        "rodata_literals": [
            {"name": name, "va": hex(va), "ascii": txt} for name, va, txt in RODATA_LITERALS
        ],
        "summary": {
            "observed_source_files": len(obs_files),
            "location_count": len(loc_rows),
            "action_wire_location_fdes": len(loc_fde_rows),
            "action_wire_location_fde_bytes": loc_bytes,
            "action_wire_business_fdes": len(biz_rows),
            "action_wire_business_fde_bytes": biz_bytes,
            "combined_unique_fdes": len(loc_fde_rows) + len(biz_rows),
            "combined_unique_fde_bytes": loc_bytes + biz_bytes,
        },
    }


def verify_records(
    records: dict,
    data: bytes,
    sections: dict[str, tuple[int, int, int]],
    fdes: dict[int, int],
    observed_locs: dict[int, tuple[str, int, int]],
    fde_to_locs: dict[int, list[int]],
) -> None:
    tb = records["target_binary"]
    if len(data) != tb["size"] or tb["size"] != TARGET_SIZE:
        raise AssertionError("binary size mismatch")
    if hashlib.sha256(data).hexdigest() != tb["sha256"] or tb["sha256"] != TARGET_SHA256:
        raise AssertionError("binary sha256 mismatch")

    obs_files = sorted({f for f, _, _ in observed_locs.values()})
    if len(observed_locs) != records["location_count"]:
        raise AssertionError(f"location_count mismatch: {len(observed_locs)} != {records['location_count']}")
    if obs_files != records["observed_source_files"]:
        raise AssertionError(f"observed_source_files mismatch: {obs_files}")

    recorded_locs = {
        int(loc["va"], 16): (loc["file"], int(loc["line"]), int(loc["col"]))
        for loc in records["locations"]
    }
    if recorded_locs != observed_locs:
        raise AssertionError("recorded locations do not match ELF .data.rel.ro Locations")

    loc_starts: set[int] = set()
    loc_bytes = 0
    for entry in records["action_wire_location_fdes"]:
        s = int(entry["start"], 16)
        e = int(entry["end"], 16)
        sz = int(entry["size"])
        if s in loc_starts:
            raise AssertionError(f"duplicate location FDE 0x{s:x}")
        loc_starts.add(s)
        if e - s != sz or fdes.get(s) != e:
            raise AssertionError(f"FDE mismatch at 0x{s:x}")
        loc_bytes += sz
    if loc_starts != set(fde_to_locs.keys()):
        raise AssertionError(
            f"location FDE completeness mismatch: recorded={len(loc_starts)} vs elf={len(fde_to_locs)}"
        )

    biz_starts: set[int] = set()
    biz_bytes = 0
    for entry in records["action_wire_business_fdes"]:
        s = int(entry["start"], 16)
        e = int(entry["end"], 16)
        sz = int(entry["size"])
        if s in biz_starts or s in loc_starts:
            raise AssertionError(f"duplicate or overlapping business FDE 0x{s:x}")
        biz_starts.add(s)
        if e - s != sz or fdes.get(s) != e:
            raise AssertionError(f"business FDE mismatch for {entry['name']} at 0x{s:x}")
        biz_bytes += sz

    sm = records["summary"]
    if (
        sm["observed_source_files"] != len(obs_files)
        or sm["location_count"] != len(observed_locs)
        or sm["action_wire_location_fdes"] != len(loc_starts)
        or sm["action_wire_location_fde_bytes"] != loc_bytes
        or sm["action_wire_business_fdes"] != len(biz_starts)
        or sm["action_wire_business_fde_bytes"] != biz_bytes
        or sm["combined_unique_fdes"] != len(loc_starts) + len(biz_starts)
        or sm["combined_unique_fde_bytes"] != loc_bytes + biz_bytes
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

    for lit in records["rodata_literals"]:
        va = int(lit["va"], 16)
        want = lit["ascii"].encode("ascii")
        if not (ro_va <= va and va + len(want) <= ro_va + ro_sz):
            raise AssertionError(f"literal out of .rodata: {lit['name']}")
        got = data[ro_off + (va - ro_va) : ro_off + (va - ro_va) + len(want)]
        if got != want:
            raise AssertionError(f"literal mismatch for {lit['name']}: {got!r} != {want!r}")


def run_negative_controls(
    records: dict,
    data: bytes,
    sections: dict[str, tuple[int, int, int]],
    fdes: dict[int, int],
    observed_locs: dict[int, tuple[str, int, int]],
    fde_to_locs: dict[int, list[int]],
) -> int:
    mutations = [
        ("bad_loc_count", lambda r: r.update({"location_count": r["location_count"] + 1})),
        (
            "bad_fde_end",
            lambda r: r["action_wire_business_fdes"][0].update({"end": "0x169f714", "size": 3524}),
        ),
        (
            "bad_opcode",
            lambda r: r["instruction_anchors"][0].update({"hex": "00" + r["instruction_anchors"][0]["hex"][2:]}),
        ),
        (
            "bad_literal",
            lambda r: r["rodata_literals"][0].update({"ascii": "struct ActionDelayer with 6 elementX"}),
        ),
    ]
    rejected = 0
    for name, mutate in mutations:
        bad = copy.deepcopy(records)
        mutate(bad)
        try:
            verify_records(bad, data, sections, fdes, observed_locs, fde_to_locs)
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
    fdes, ordered_fdes = load_fde_index()
    observed_locs = scan_action_wire_locations(data, sections, components)
    fde_to_locs = scan_location_referencing_fdes(data, sections, ordered_fdes, set(observed_locs.keys()))

    if args.generate:
        records = build_records(data, fdes, observed_locs, fde_to_locs)
        RECORDS_PATH.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    else:
        records = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))

    verify_records(records, data, sections, fdes, observed_locs, fde_to_locs)
    neg = 0
    if args.self_test:
        neg = run_negative_controls(records, data, sections, fdes, observed_locs, fde_to_locs)
    sm = records["summary"]
    print(
        f"PASS: action-wire closure verified — {sm['observed_source_files']}/5 files, "
        f"{sm['location_count']}/13 Locations, "
        f"{sm['action_wire_location_fdes']}/15 Location FDEs ({sm['action_wire_location_fde_bytes']} B), "
        f"{sm['action_wire_business_fdes']}/6 business FDEs ({sm['action_wire_business_fde_bytes']} B), "
        f"combined {sm['combined_unique_fdes']} unique FDEs ({sm['combined_unique_fde_bytes']} B), "
        f"{neg}/4 negative controls rejected"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
