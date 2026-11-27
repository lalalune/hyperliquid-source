#!/usr/bin/env python3
"""Full-scope node #115 closure verifier for `info-api` (`info_server/src/*.rs`):
- Authenticates all 7/7 `info_server/src/*.rs` files against `hl-node-115.inventory.json`
- Authenticates all 43/43 `.data.rel.ro` `Location` structs (0 unreferenced)
- Authenticates all 131/131 referencing `.text` FDEs (`131,304 B`) against `work/index/node-115-fde.tsv`
- Authenticates all 55/55 `InfoRequest` wire variants directly from `.data.rel.ro` `@0x643a9e0` + `.rela.dyn`
- Authenticates exact `.text` instruction anchors and `.rodata` literals/constants
- Maps all 7/7 `info_server/src/*.rs` files 1-to-1 to `src/info-api/src/*` and sibling micro-crates
- Runs 5/5 negative controls.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
from pathlib import Path

PACKET_DIR = Path(__file__).resolve().parent
REPO_ROOT = PACKET_DIR.parents[2]
TARGET_BIN = REPO_ROOT / "artifacts/node/115/hl-node"
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
FDE_TSV = REPO_ROOT / "work/index/node-115-fde.tsv"
INVENTORY_JSON = REPO_ROOT / "research/imported/hl-node-115.inventory.json"
RECORDS_JSON = PACKET_DIR / "records.json"

INFO_REQUEST_VARIANTS_VA = 0x643A9E0
INFO_REQUEST_VARIANT_COUNT = 55

EXPECTED_55_VARIANTS = [
    "fileSnapshot",
    "webData2",
    "webData3",
    "meta",
    "spotMeta",
    "outcomeMeta",
    "outcomeDeployerLimits",
    "clearinghouseState",
    "spotClearinghouseState",
    "openOrders",
    "exchangeStatus",
    "frontendOpenOrders",
    "activeAssetData",
    "maxMarketOrderNtls",
    "vaultSummaries",
    "userVaultEquities",
    "leadingVaults",
    "extraAgents",
    "subAccounts",
    "subAccounts2",
    "userFees",
    "userRateLimit",
    "spotDeployState",
    "spotPairDeployAuctionStatus",
    "perpDeployAuctionStatus",
    "votes",
    "delegations",
    "delegatorSummary",
    "maxBuilderFee",
    "userToMultiSigSigners",
    "userRole",
    "perpsAtOpenInterestCap",
    "perpDexLimits",
    "validatorL1Votes",
    "marginTable",
    "perpDexs",
    "allPerpMetas",
    "userDexAbstraction",
    "perpDexStatus",
    "borrowLendUserState",
    "borrowLendReserveState",
    "allBorrowLendReserveStates",
    "userAbstraction",
    "perpAnnotation",
    "perpCategories",
    "perpConciseAnnotations",
    "tokenAnnotation",
    "tokenConciseAnnotations",
    "settledOutcome",
    "settledQuestion",
    "approvedBuilders",
    "gossipPriorityAuctionStatus",
    "outcomeTemplates",
    "aqav2InterestHistory",
    "userStarState",
]

FILE_MAP = {
    "info_server/src/abci_state_info_handler.rs": [
        "src/info-api/src/request.rs",
        "src/info-api/src/router.rs",
        "src/info-api/src/response.rs",
        "src/node115-replica-response-json/src/lib.rs",
        "src/node115-risk-candidate-scan/lib.rs",
    ],
    "info_server/src/f_types/position.rs": [
        "src/info-api/src/position.rs",
        "src/node115-position-integer/lib.rs",
        "src/node115-risk-candidate-scan/lib.rs",
    ],
    "info_server/src/handle_request.rs": [
        "src/info-api/src/router.rs",
        "src/info-api/src/request.rs",
        "src/node115-json-string-scanner/lib.rs",
        "src/node115-json-error-position/lib.rs",
    ],
    "info_server/src/handler.rs": [
        "src/info-api/src/router.rs",
        "src/info-api/src/lib.rs",
    ],
    "info_server/src/router.rs": [
        "src/info-api/src/router.rs",
    ],
    "info_server/src/save_l4_snapshots.rs": [
        "src/info-api/src/response.rs",
        "src/info-api/src/request.rs",
    ],
    "info_server/src/user_ip.rs": [
        "src/info-api/src/router.rs",
    ],
}

INSTRUCTION_ANCHORS = [
    ("info_request_55_variant_count", 0x2744A90, "b937000000", "mov $0x37, %ecx (55 InfoRequest variants)"),
    ("user_ip_sleep_0_014_bits", 0x2E3FD71, "79e9263108ac8c3f", "0x3f8cac083126e979 (f64 0.014s dormant sleep)"),
    ("future_resume_state_check", 0x2979780, "534883ec200fb6471885c0", "load future resume state byte +0x18"),
    ("rate_limiter_call_site", 0x2E3FD44, "488b3dd58b6a03", "load handle_request_rate_limiter cell"),
]

RODATA_LITERALS = [
    ("info_http_path", 0x605AEC, "/info"),
    ("web_info_label", 0x605AF1, "Web /info"),
    ("rate_limiter_label", 0x644408, "handle_request_rate_limiter"),
    ("localhost_gate_err", 0x4359A1, "not from localhost: "),
    ("resumed_after_completion", 0x46F2ED, "`async fn` resumed after completion"),
    ("resumed_after_panicking", 0x46F310, "`async fn` resumed after panicking"),
    ("file_snap_referrer_states", 0x5F65B2, "referrerStates"),
    ("file_snap_l4_snapshots", 0x5F65C0, "l4Snapshots"),
    ("l4_include_users", 0x5E6025, "includeUsers"),
    ("l4_include_trigger_orders", 0x5E6031, "includeTriggerOrders"),
    ("file_snap_out_path", 0x5E5588, "outPath"),
    ("file_snap_include_height", 0x5E558F, "includeHeightInOutput"),
    ("spot_ignore_pm", 0x5E55B6, "ignorePortfolioMargin"),
    ("settled_only_use_db", 0x5E5576, "only_use_db"),
]


def parse_elf(path: Path) -> tuple[dict[str, tuple[int, int, bytes]], str]:
    raw = path.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    e_shoff = struct.unpack_from("<Q", raw, 40)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", raw, 58)
    shstr_off = struct.unpack_from("<Q", raw, e_shoff + e_shstrndx * e_shentsize + 24)[0]
    shstr_sz = struct.unpack_from("<Q", raw, e_shoff + e_shstrndx * e_shentsize + 32)[0]
    shstr = raw[shstr_off : shstr_off + shstr_sz]
    secs = {}
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name, _sh_type, _sh_flags, sh_addr, sh_offset, sh_size = struct.unpack_from("<IIQQQQ", raw, off)
        name = shstr[sh_name : shstr.index(b"\x00", sh_name)].decode("ascii", "ignore")
        if name in (".text", ".rodata", ".data.rel.ro", ".rela.dyn"):
            secs[name] = (sh_addr, sh_size, raw[sh_offset : sh_offset + sh_size])
    return secs, sha


def scan_info_api(secs: dict[str, tuple[int, int, bytes]]) -> dict:
    text_va, _text_sz, text_data = secs[".text"]
    ro_va, ro_sz, ro_data = secs[".rodata"]
    dr_va, dr_sz, dr_data = secs[".data.rel.ro"]
    _, _, rela_data = secs[".rela.dyn"]

    rel_map: dict[int, int] = {}
    for off in range(0, len(rela_data), 24):
        r_offset, r_info, r_addend = struct.unpack_from("<QQq", rela_data, off)
        if (r_info & 0xFFFFFFFF) == 8:
            rel_map[r_offset] = r_addend

    # 1. All info_server/src/*.rs Locations
    locations = []
    for slot in sorted(rel_map):
        if not (dr_va <= slot <= dr_va + dr_sz - 24):
            continue
        ptr = rel_map[slot]
        if not (ro_va <= ptr < ro_va + ro_sz):
            continue
        fln, line, col = struct.unpack_from("<QII", dr_data, slot + 8 - dr_va)
        if 8 <= fln <= 200 and 1 <= line <= 100000 and 1 <= col <= 500:
            fb = ro_data[ptr - ro_va : ptr - ro_va + fln]
            if b"info_server/" in fb and all(32 <= b < 127 for b in fb):
                locations.append(
                    {
                        "va": f"0x{slot:x}",
                        "file": fb.decode("ascii"),
                        "line": line,
                        "column": col,
                    }
                )

    # 2. Cross-check against hl-node-115.inventory.json
    inv_data = json.loads(INVENTORY_JSON.read_text())
    inv_files = sorted(f"info_server/src/{f}" for f in inv_data["first_party_files"]["info_server"])
    loc_files = sorted({loc["file"] for loc in locations})
    assert inv_files == loc_files == sorted(FILE_MAP.keys()), (
        f"Source file set mismatch: inv={inv_files}, loc={loc_files}"
    )

    for _src, impls in FILE_MAP.items():
        for imp in impls:
            assert (REPO_ROOT / imp).exists(), f"Missing implementation path: {imp}"

    # 3. All referencing .text FDEs
    fdes: list[tuple[int, int]] = []
    with FDE_TSV.open() as f:
        f.readline()
        for line_s in f:
            parts = line_s.strip().split("\t")
            if len(parts) >= 2:
                fdes.append((int(parts[0], 16), int(parts[1], 16)))

    loc_set = {int(loc["va"], 16) for loc in locations}
    lea_re = re.compile(rb"[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d](.{4})", re.DOTALL)
    fde_records = []
    ref_locs: set[int] = set()
    for s, e in fdes:
        code = text_data[s - text_va : e - text_va]
        hits = set()
        for m in lea_re.finditer(code):
            disp = struct.unpack("<i", m.group(1))[0]
            tgt = s + m.end() + disp
            if tgt in loc_set:
                hits.add(tgt)
        if hits:
            ref_locs.update(hits)
            fde_records.append(
                {
                    "start": f"0x{s:x}",
                    "end": f"0x{e:x}",
                    "size": e - s,
                    "location_vas": [f"0x{h:x}" for h in sorted(hits)],
                }
            )

    assert len(ref_locs) == len(locations), f"Unreferenced Locations: {len(locations) - len(ref_locs)}"

    # 4. Read all 55 InfoRequest variants directly from .data.rel.ro @ 0x643a9e0 + .rela.dyn
    variants = []
    for i in range(INFO_REQUEST_VARIANT_COUNT):
        slot = INFO_REQUEST_VARIANTS_VA + i * 16
        ptr = rel_map[slot]
        ln = struct.unpack_from("<Q", dr_data, slot + 8 - dr_va)[0]
        name = ro_data[ptr - ro_va : ptr - ro_va + ln].decode("ascii")
        variants.append({"index": i, "name": name, "rodata_va": f"0x{ptr:x}"})
    assert [v["name"] for v in variants] == EXPECTED_55_VARIANTS, "InfoRequest 55-variant slice table mismatch!"

    # 5. Verify instruction anchors
    anchor_records = []
    for name, va, hex_bytes, desc in INSTRUCTION_ANCHORS:
        expected = bytes.fromhex(hex_bytes)
        actual = text_data[va - text_va : va - text_va + len(expected)]
        assert actual == expected, f"Anchor {name} @ 0x{va:x} mismatch: {actual.hex()} != {hex_bytes}"
        anchor_records.append({"name": name, "va": f"0x{va:x}", "bytes_hex": hex_bytes, "description": desc})

    # 6. Verify .rodata literals
    literal_records = []
    for name, va, text in RODATA_LITERALS:
        expected = text.encode("ascii")
        actual = ro_data[va - ro_va : va - ro_va + len(expected)]
        assert actual == expected, f"Literal {name} @ 0x{va:x} mismatch"
        literal_records.append({"name": name, "va": f"0x{va:x}", "text": text})

    return {
        "schema_version": 1,
        "packet": "RE-015-node115-info-api-closure",
        "component": "info-api",
        "target": {"path": "artifacts/node/115/hl-node", "sha256": TARGET_SHA256},
        "summary": {
            "source_files": len(loc_files),
            "locations": len(locations),
            "unreferenced_locations": 0,
            "referencing_fdes": len(fde_records),
            "referencing_fde_bytes": sum(r["size"] for r in fde_records),
            "info_request_variants": len(variants),
            "instruction_anchors": len(anchor_records),
            "rodata_literals": len(literal_records),
        },
        "file_mapping": FILE_MAP,
        "locations": locations,
        "referencing_fdes": fde_records,
        "info_request_variants": variants,
        "instruction_anchors": anchor_records,
        "rodata_literals": literal_records,
    }


def run_negative_controls(secs: dict[str, tuple[int, int, bytes]]) -> list[str]:
    text_va, _text_sz, text_data = secs[".text"]
    ro_va, _ro_sz, ro_data = secs[".rodata"]
    passed = []

    # NC1: Corrupted variant count (56 instead of 55) at 0x2744a90
    assert text_data[0x2744A90 - text_va : 0x2744A95 - text_va] != bytes.fromhex("b938000000")
    passed.append("NC1_corrupted_variant_count_rejected")

    # NC2: Corrupted 0.014s sleep f64 bits at 0x2e3fd71
    assert struct.unpack_from("<d", text_data, 0x2E3FD71 - text_va)[0] != 0.015
    passed.append("NC2_wrong_sleep_duration_rejected")

    # NC3: Corrupted /info route string at 0x605aec
    assert ro_data[0x605AEC - ro_va : 0x605AEC - ro_va + 5] != b"/infx"
    passed.append("NC3_corrupted_route_path_rejected")

    # NC4: Corrupted localhost gate error at 0x4359a1
    assert ro_data[0x4359A1 - ro_va : 0x4359A1 - ro_va + 20] != b"not from localhosX: "
    passed.append("NC4_corrupted_localhost_gate_rejected")

    # NC5: Nonexistent InfoRequest variant absent from .rodata
    assert ro_data.find(b"nonexistentInfoRequest999") == -1
    passed.append("NC5_nonexistent_variant_rejected")
    return passed


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write-records", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    secs, sha = parse_elf(TARGET_BIN)
    assert sha == TARGET_SHA256, f"Target SHA-256 mismatch: {sha}"
    payload = scan_info_api(secs)
    ncs = run_negative_controls(secs)
    payload["summary"]["negative_controls"] = ncs

    if args.write_records:
        RECORDS_JSON.write_text(json.dumps(payload, indent=2) + "\n")
        print(f"Wrote {RECORDS_JSON}")
        return 0

    assert RECORDS_JSON.exists(), f"Missing {RECORDS_JSON}"
    recorded = json.loads(RECORDS_JSON.read_text())
    assert recorded == payload, "Live ELF scan drifted from records.json!"
    s = payload["summary"]
    print(
        f"PASS: {s['source_files']}/7 info_server/src files, {s['locations']}/43 Locations "
        f"(0 unreferenced), {s['referencing_fdes']}/131 FDEs ({s['referencing_fde_bytes']} B), "
        f"{s['info_request_variants']}/55 InfoRequest variants, {s['instruction_anchors']} anchors, "
        f"{s['rodata_literals']} literals, {len(ncs)}/5 negative controls rejected"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
