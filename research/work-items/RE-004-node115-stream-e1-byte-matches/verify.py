#!/usr/bin/env python3
"""Compile lib.rs with rustc +1.95.0 and verify Stream E1 (assets/fees/orderbook) FDE byte matches against node #115."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

PACKET_DIR = Path(__file__).resolve().parent
REPO_ROOT = PACKET_DIR.parents[2]
BINARY_PATH = REPO_ROOT / "artifacts" / "node" / "115" / "hl-node"
FDE_TSV = REPO_ROOT / "work" / "index" / "node-115-fde.tsv"
BYTE_WINDOWS_JSON = REPO_ROOT / "research" / "byte-windows.json"
SOURCE_PATH = PACKET_DIR / "lib.rs"
RECORDS_PATH = PACKET_DIR / "records.json"

EXPECTED_BINARY_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
)
EXPECTED_BINARY_SIZE = 105_896_032
TEXT_VA = 0x1419300
TEXT_OFF = 0x1418300
RODATA_VA = 0x430400
RODATA_OFF = 0x430400
RODATA_SZ = 0x76E640

# 8 real PerpMeta / SpotMeta / TokenSpec business-logic FDEs (1,016 B)
BUSINESS_LOGIC_WINDOWS = [
    ("assets", "assets_checked_sz_to_wei", 0x3C4B1A0, 0x3C4B274, "l1/spot_meta checked_sz_to_wei (0x3c4b1a0)"),
    ("assets", "assets_perp_px_to_f64", 0x50BEA90, 0x50BEB2F, "l1/perp_meta px_to_f64 (0x50bea90)"),
    ("assets", "assets_token_wei_per_sz", 0x3C4B280, 0x3C4B30C, "l1/spot_meta TokenSpec::wei_per_sz (0x3c4b280)"),
    ("assets", "assets_perp_sz_to_f64", 0x50BEB30, 0x50BEBBA, "l1/perp_meta sz_to_f64 (0x50beb30)"),
    ("assets", "assets_spot_for_quote", 0x3C47AE0, 0x3C47B59, "l1/spot_meta spot_for_quote (0x3c47ae0)"),
    ("assets", "assets_perp_px_decimals", 0x3D19800, 0x3D19868, "l1/perp_meta px_decimals (0x3d19800)"),
    ("assets", "assets_quote_name_pair", 0x3D1A2C0, 0x3D1A314, "l1/spot_meta quote_name_pair (0x3d1a2c0)"),
    ("assets", "assets_first_spot_for_token", 0x3C47660, 0x3C4769A, "l1/spot_meta first_spot_for_token (0x3c47660)"),
]

# Pure Stream E1 Visitor::expecting strings -> (component, symbol_name, literal)
EXPECTING_SPECS = [
    # assets (23 types)
    ("assets", "assets_expecting_side", "enum Side"),
    ("assets", "assets_expecting_perp_asset_info", "struct PerpAssetInfo"),
    ("assets", "assets_expecting_perp_meta", "struct PerpMeta"),
    ("assets", "assets_expecting_spot_info", "struct SpotInfo"),
    ("assets", "assets_expecting_spot_meta", "struct SpotMeta"),
    ("assets", "assets_expecting_token_info", "struct TokenInfo"),
    ("assets", "assets_expecting_token_spec", "struct TokenSpec"),
    ("assets", "assets_expecting_aqav2_token_info", "struct Aqav2TokenInfo"),
    ("assets", "assets_expecting_token_infos", "tuple struct TokenInfos"),
    ("assets", "assets_expecting_pdi", "tuple struct Pdi"),
    ("assets", "assets_expecting_px", "tuple struct Px"),
    ("assets", "assets_expecting_sz", "tuple struct Sz"),
    ("assets", "assets_expecting_szi", "tuple struct Szi"),
    ("assets", "assets_expecting_ntl", "tuple struct Ntl"),
    ("assets", "assets_expecting_ntli", "tuple struct Ntli"),
    ("assets", "assets_expecting_wei", "tuple struct Wei"),
    ("assets", "assets_expecting_side_map", "tuple struct SideMap"),
    ("assets", "assets_expecting_usdc_px", "tuple struct UsdcPx"),
    ("assets", "assets_expecting_usdc_ntl", "tuple struct UsdcNtl"),
    ("assets", "assets_expecting_usdc_ntli", "tuple struct UsdcNtli"),
    ("assets", "assets_expecting_usdc_big_spot_ntl", "tuple struct UsdcBigSpotNtl"),
    ("assets", "assets_expecting_usdc_ntl_scale_serde", "tuple struct UsdcNtlScaleSerde"),
    ("assets", "assets_expecting_usdc_rough_ntli", "tuple struct UsdcRoughNtli"),
    # fees (20 types)
    ("fees", "fees_expecting_fee_schedule", "struct FeeSchedule"),
    ("fees", "fees_expecting_new_fee_schedule", "struct NewFeeSchedule"),
    ("fees", "fees_expecting_fee_tiers", "struct FeeTiers"),
    ("fees", "fees_expecting_fee_tracker", "struct FeeTracker"),
    ("fees", "fees_expecting_fee_trial", "struct FeeTrial"),
    ("fees", "fees_expecting_vip_fees", "struct VipFees"),
    ("fees", "fees_expecting_mm_fees", "struct MmFees"),
    ("fees", "fees_expecting_user_fee_state", "struct UserFeeState"),
    ("fees", "fees_expecting_referral_state", "struct ReferralState"),
    ("fees", "fees_expecting_referrer_state", "struct ReferrerState"),
    ("fees", "fees_expecting_stake_discount", "struct StakeDiscount"),
    ("fees", "fees_expecting_stake_discount_tiers", "struct StakeDiscountTiers"),
    ("fees", "fees_expecting_collected_builder_fees", "tuple struct CollectedBuilderFees"),
    ("fees", "fees_expecting_unvalidated_hip3_deployer_fee", "struct UnvalidatedHip3DeployerFee"),
    ("fees", "fees_expecting_add_cross_scaled_vlm", "struct AddCrossScaledVlm"),
    ("fees", "fees_expecting_scaled_and_raw_vlm", "struct ScaledAndRawVlm"),
    ("fees", "fees_expecting_daily_scaled_vlms", "tuple struct DailyScaledVlms"),
    ("fees", "fees_expecting_fee_rate_map_serde", "tuple struct FeeRateMapSerde"),
    ("fees", "fees_expecting_raw_vlm", "tuple struct RawVlm"),
    ("fees", "fees_expecting_scaled_vlm", "tuple struct ScaledVlm"),
    # orderbook (36 types)
    ("orderbook", "orderbook_expecting_tpsl", "enum Tpsl"),
    ("orderbook", "orderbook_expecting_order_description", "enum OrderDescription"),
    ("orderbook", "orderbook_expecting_untriggered_order", "enum UntriggeredOrder"),
    ("orderbook", "orderbook_expecting_book", "struct Book"),
    ("orderbook", "orderbook_expecting_book_order", "struct BookOrder"),
    ("orderbook", "orderbook_expecting_book_order_key", "tuple struct BookOrderKey"),
    ("orderbook", "orderbook_expecting_book_orders", "tuple struct BookOrders"),
    ("orderbook", "orderbook_expecting_books", "tuple struct Books"),
    ("orderbook", "orderbook_expecting_level", "struct Level"),
    ("orderbook", "orderbook_expecting_level_summary", "struct LevelSummary"),
    ("orderbook", "orderbook_expecting_slab", "struct Slab"),
    ("orderbook", "orderbook_expecting_order_core", "struct OrderCore"),
    ("orderbook", "orderbook_expecting_order_wire_serde", "struct OrderWireSerde"),
    ("orderbook", "orderbook_expecting_order_builder_info", "struct OrderBuilderInfo"),
    ("orderbook", "orderbook_expecting_open_order_tracker", "struct OpenOrderTracker"),
    ("orderbook", "orderbook_expecting_cancel", "struct Cancel"),
    ("orderbook", "orderbook_expecting_cancel_by_cloid", "struct CancelByCloid"),
    ("orderbook", "orderbook_expecting_cloid", "tuple struct Cloid"),
    ("orderbook", "orderbook_expecting_cloid_tracker", "struct CloidTracker"),
    ("orderbook", "orderbook_expecting_user_cloid_tracker", "struct UserCloidTracker"),
    ("orderbook", "orderbook_expecting_modify_wire", "struct ModifyWire"),
    ("orderbook", "orderbook_expecting_scheduled_cancel", "struct ScheduledCancel"),
    ("orderbook", "orderbook_expecting_trigger", "struct Trigger"),
    ("orderbook", "orderbook_expecting_trigger_order", "struct TriggerOrder"),
    ("orderbook", "orderbook_expecting_trigger_wire_serde", "struct TriggerWireSerde"),
    ("orderbook", "orderbook_expecting_trailing_stop_order", "struct TrailingStopOrder"),
    ("orderbook", "orderbook_expecting_twap_id", "tuple struct TwapId"),
    ("orderbook", "orderbook_expecting_twap_details_wire", "struct TwapDetailsWire"),
    ("orderbook", "orderbook_expecting_twap_heap_key", "struct TwapHeapKey"),
    ("orderbook", "orderbook_expecting_twap_schedule", "struct TwapSchedule"),
    ("orderbook", "orderbook_expecting_twap_state", "struct TwapState"),
    ("orderbook", "orderbook_expecting_twap_tracker", "struct TwapTracker"),
    ("orderbook", "orderbook_expecting_twap_trigger", "struct TwapTrigger"),
    ("orderbook", "orderbook_expecting_twap_trigger_wire", "struct TwapTriggerWire"),
    ("orderbook", "orderbook_expecting_twap_wire_serde", "struct TwapWireSerde"),
    ("orderbook", "orderbook_expecting_waiting_twap", "struct WaitingTwap"),
]


def parse_elf_sections(blob: bytes) -> list[tuple[int, str, int, int, int, int, int, int]]:
    e_shoff = struct.unpack_from("<Q", blob, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", blob, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", blob, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", blob, 0x3E)[0]
    shstr_off = struct.unpack_from("<Q", blob, e_shoff + e_shstrndx * e_shentsize + 24)[0]
    out = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name, sh_type, _sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info = (
            struct.unpack_from("<IIQQQQII", blob, off)
        )
        end = blob.find(b"\0", shstr_off + sh_name)
        name = blob[shstr_off + sh_name : end].decode("latin1")
        out.append((i, name, sh_type, sh_addr, sh_offset, sh_size, sh_link, sh_info))
    return out


def load_fde_map() -> dict[int, int]:
    fdes: dict[int, int] = {}
    with FDE_TSV.open("r", encoding="utf-8") as fh:
        fh.readline()
        for line in fh:
            parts = line.strip().split("\t")
            if len(parts) >= 2:
                s = int(parts[0], 16) if parts[0].startswith("0x") else int(parts[0])
                e = int(parts[1], 16) if parts[1].startswith("0x") else int(parts[1])
                fdes[s] = e
    return fdes


def compile_object() -> tuple[bytes, str]:
    ver = subprocess.check_output(["rustc", "+1.95.0", "--version"], text=True).strip()
    with tempfile.TemporaryDirectory(prefix="re004-e1-byte-match-") as tmpdir:
        obj_path = Path(tmpdir) / "stream_e1_bytes.o"
        subprocess.run(
            [
                "rustc",
                "+1.95.0",
                "--edition=2021",
                "--crate-type=rlib",
                "--crate-name=stream_e1_byte_matches",
                "-C",
                "opt-level=3",
                "-C",
                "overflow-checks=yes",
                "--emit=obj",
                "-o",
                str(obj_path),
                str(SOURCE_PATH),
            ],
            check=True,
        )
        return obj_path.read_bytes(), ver


def extract_compiled_symbols(obj: bytes) -> dict[str, tuple[bytes, list[int]]]:
    secs = parse_elf_sections(obj)
    symtab = [s for s in secs if s[2] == 2][0]
    strtab = secs[symtab[6]]
    relas_by_sec: dict[int, list[int]] = {}
    for s in secs:
        if s[2] == 4:
            relas_by_sec[s[7]] = [
                struct.unpack_from("<Q", obj, o)[0]
                for o in range(s[4], s[4] + s[5], 24)
            ]
    out: dict[str, tuple[bytes, list[int]]] = {}
    for o in range(symtab[4], symtab[4] + symtab[5], 24):
        st_name, st_info, _st_other, st_shndx, st_value, st_size = struct.unpack_from(
            "<IBBHQQ", obj, o
        )
        if (st_info & 0xF) != 2 or st_size == 0 or st_shndx == 0 or st_shndx >= len(secs):
            continue
        end = obj.find(b"\0", strtab[4] + st_name)
        sym = obj[strtab[4] + st_name : end].decode("latin1")
        sec = secs[st_shndx]
        body = obj[sec[4] + st_value : sec[4] + st_value + st_size]
        rels = sorted(r - st_value for r in relas_by_sec.get(st_shndx, []) if st_value <= r < st_value + st_size)
        out[sym] = (body, rels)
    return out


def find_symbol(compiled: dict[str, tuple[bytes, list[int]]], short_name: str) -> tuple[bytes, list[int]]:
    token = f"{len(short_name)}{short_name}"
    matches = [(k, v) for k, v in compiled.items() if token in k and "inner" not in k]
    if len(matches) != 1:
        raise RuntimeError(f"Expected 1 symbol for {short_name}, found {len(matches)}: {[m[0] for m in matches]}")
    return matches[0][1]


def discover_windows(binary: bytes, fdes: dict[int, int]) -> list[tuple[str, str, int, int, str]]:
    windows: list[tuple[str, str, int, int, str]] = list(BUSINESS_LOGIC_WINDOWS)
    by_msg = {msg: (comp, fn_name) for comp, fn_name, msg in EXPECTING_SPECS}
    for s, e in sorted(fdes.items()):
        if e - s != 25:
            continue
        b = binary[TEXT_OFF + (s - TEXT_VA) : TEXT_OFF + (e - TEXT_VA)]
        if b[:14] != b"\x48\x8b\x3e\x48\x8b\x46\x08\x48\x8b\x40\x18\x48\x8d\x35":
            continue
        if b[18] != 0xBA or b[23:25] != b"\xff\xe0":
            continue
        disp = struct.unpack_from("<i", b, 14)[0]
        ln = struct.unpack_from("<I", b, 19)[0]
        tgt = s + 18 + disp
        if not (RODATA_VA <= tgt < RODATA_VA + RODATA_SZ) or not (4 <= ln <= 80):
            continue
        txt = binary[RODATA_OFF + (tgt - RODATA_VA) : RODATA_OFF + (tgt - RODATA_VA) + ln].decode("ascii", "ignore")
        if txt in by_msg:
            comp, fn_name = by_msg[txt]
            windows.append((comp, fn_name, s, e, f"{comp} {txt} expecting (0x{s:x})"))
    return windows


def build_records() -> dict:
    binary = BINARY_PATH.read_bytes()
    actual_sha = hashlib.sha256(binary).hexdigest()
    if actual_sha != EXPECTED_BINARY_SHA256 or len(binary) != EXPECTED_BINARY_SIZE:
        raise RuntimeError(f"Target binary mismatch: {actual_sha} ({len(binary)} B)")
    fdes = load_fde_map()
    obj, compiler_ver = compile_object()
    compiled = extract_compiled_symbols(obj)

    windows = discover_windows(binary, fdes)
    records = []
    by_comp: dict[str, dict[str, int]] = {}
    for comp, fn_name, start, end, label in windows:
        if fdes.get(start) != end:
            raise RuntimeError(f"FDE mismatch for 0x{start:x}: expected 0x{end:x}, got {fdes.get(start)}")
        cbytes, rels = find_symbol(compiled, fn_name)
        size = end - start
        if len(cbytes) != size:
            raise RuntimeError(f"Size mismatch for {fn_name} (0x{start:x}): compiled={len(cbytes)} target={size}")
        tbytes = binary[TEXT_OFF + (start - TEXT_VA) : TEXT_OFF + (end - TEXT_VA)]
        masked = set()
        for roff in rels:
            for k in range(4):
                masked.add(roff + k)
        mismatches = [i for i in range(size) if i not in masked and cbytes[i] != tbytes[i]]
        if mismatches:
            raise RuntimeError(f"Non-relocation mismatch for {fn_name} (0x{start:x}): offsets {mismatches[:5]}")
        raw_eq = sum(1 for a, b in zip(cbytes, tbytes) if a == b)
        records.append(
            {
                "component": comp,
                "symbol": fn_name,
                "label": label,
                "start": f"0x{start:x}",
                "end": f"0x{end:x}",
                "size": size,
                "relocation_offsets": rels,
                "raw_equal_bytes": raw_eq,
                "target_sha256": hashlib.sha256(tbytes).hexdigest(),
                "compiled_sha256": hashlib.sha256(cbytes).hexdigest(),
            }
        )
        st = by_comp.setdefault(comp, {"windows": 0, "bytes": 0, "raw_equal_bytes": 0})
        st["windows"] += 1
        st["bytes"] += size
        st["raw_equal_bytes"] += raw_eq

    return {
        "work_item": "RE-004-node115-stream-e1-byte-matches",
        "target_binary": "artifacts/node/115/hl-node",
        "target_sha256": EXPECTED_BINARY_SHA256,
        "compiler": compiler_ver,
        "source_sha256": hashlib.sha256(SOURCE_PATH.read_bytes()).hexdigest(),
        "summary": {
            "total_windows": len(records),
            "total_bytes": sum(r["size"] for r in records),
            "total_raw_equal_bytes": sum(r["raw_equal_bytes"] for r in records),
            "relocation_qualified_windows": len(records),
            "by_component": by_comp,
        },
        "windows": records,
    }


def verify_records(expected: dict, *, allow_corrupt_check: bool = False) -> None:
    actual = build_records()
    if actual != expected:
        raise RuntimeError("Rebuilt compiled-byte records do not match committed records.json")

    # Ensure zero overlap with dependency windows, zero partial overlap with first-party
    # byte-windows.json entries (allowing exact (s, e) == (es, ee) first-party consolidation),
    # and zero overlap with sibling byte-match packets.
    bw = json.loads(BYTE_WINDOWS_JSON.read_text(encoding="utf-8"))
    bw_entries: list[tuple[int, int, bool]] = [
        (int(w["start"]), int(w["end"]), "dependency" in w) for w in bw["windows"]
    ]

    sibling_entries: list[tuple[int, int, str]] = []
    for sibling_rel in (
        "research/work-items/RE-007-node115-stream-e2-byte-matches/records.json",
        "research/work-items/RE-009-node115-storage-abci-byte-matches/records.json",
    ):
        sib_path = REPO_ROOT / sibling_rel
        if sib_path.exists():
            sib = json.loads(sib_path.read_text(encoding="utf-8"))
            for w in sib.get("windows", sib.get("records", [])):
                sv = w.get("start_va", w.get("start"))
                ev = w.get("end_va", w.get("end"))
                if sv is None or ev is None:
                    continue
                si = int(sv, 16) if isinstance(sv, str) else int(sv)
                ei = int(ev, 16) if isinstance(ev, str) else int(ev)
                sibling_entries.append((si, ei, sibling_rel))

    seen = set()
    for r in expected["windows"]:
        s, e = int(r["start"], 16), int(r["end"], 16)
        if s in seen:
            raise RuntimeError(f"Duplicate start VA 0x{s:x}")
        seen.add(s)
        for es, ee, is_dep in bw_entries:
            if s < ee and es < e:
                if is_dep:
                    raise RuntimeError(
                        f"Window 0x{s:x}..0x{e:x} overlaps dependency window 0x{es:x}..0x{ee:x}"
                    )
                if (s, e) != (es, ee):
                    raise RuntimeError(
                        f"Window 0x{s:x}..0x{e:x} partially overlaps first-party window 0x{es:x}..0x{ee:x}"
                    )
        for es, ee, src_name in sibling_entries:
            if s < ee and es < e:
                raise RuntimeError(
                    f"Window 0x{s:x}..0x{e:x} overlaps {src_name} 0x{es:x}..0x{ee:x}"
                )

    if allow_corrupt_check:
        # 4 negative controls
        bad1 = copy.deepcopy(expected)
        bad1["target_sha256"] = "0" * 64
        if bad1 == actual:
            raise RuntimeError("Negative control 1 failed")

        bad2 = copy.deepcopy(expected)
        bad2["windows"][0]["target_sha256"] = "f" * 64
        if bad2 == actual:
            raise RuntimeError("Negative control 2 failed")

        bad3 = copy.deepcopy(expected)
        bad3["windows"][0]["size"] += 1
        if bad3 == actual:
            raise RuntimeError("Negative control 3 failed")

        bad4 = copy.deepcopy(expected)
        bad4["source_sha256"] = "a" * 64
        if bad4 == actual:
            raise RuntimeError("Negative control 4 failed")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--generate", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.generate:
        recs = build_records()
        RECORDS_PATH.write_text(json.dumps(recs, indent=2) + "\n", encoding="utf-8")
        s = recs["summary"]
        print(
            f"GENERATED: {s['total_windows']} windows, {s['total_bytes']} B, "
            f"{s['total_raw_equal_bytes']} raw-equal, by_component={s['by_component']}"
        )
        return 0

    expected = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))
    verify_records(expected, allow_corrupt_check=args.self_test)
    s = expected["summary"]
    print(
        f"PASS: {s['relocation_qualified_windows']}/{s['total_windows']} relocation-qualified, "
        f"{s['total_bytes']} B ({s['total_raw_equal_bytes']} raw-equal), "
        f"by_component={s['by_component']}"
        + (" (4/4 negative controls rejected)" if args.self_test else "")
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
