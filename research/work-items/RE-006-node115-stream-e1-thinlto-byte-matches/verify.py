#!/usr/bin/env python3
"""Compile main.rs with rustc +1.95.0 (-C lto=thin) and verify 78 Stream E1 (orderbook/assets/fees) FDE byte matches against node #115."""

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
SOURCE_PATH = PACKET_DIR / "main.rs"
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
POW10_VAS = (0x91B7C0, 0x60D448)
POW10_PREFIX = struct.pack("<4d", 1.0, 10.0, 100.0, 1000.0)

# 78 strictly disjoint first-party Stream E1 FDEs (30,364 B):
# (component, label, start_va, size, required_rodata_anchor_str_or_None_for_pow10)
TARGET_WINDOWS: list[tuple[str, str, int, int, str | None]] = [
    # orderbook: OrderCore::fmt (12 x 636 B = 7,632 B)
    ("orderbook", "OrderCore::fmt", 0x232A420, 636, "OrderCore"),
    ("orderbook", "OrderCore::fmt", 0x232A6A0, 636, "OrderCore"),
    ("orderbook", "OrderCore::fmt", 0x24546F0, 636, "OrderCore"),
    ("orderbook", "OrderCore::fmt", 0x2454970, 636, "OrderCore"),
    ("orderbook", "OrderCore::fmt", 0x25FF3A0, 636, "OrderCore"),
    ("orderbook", "OrderCore::fmt", 0x25FF620, 636, "OrderCore"),
    ("orderbook", "OrderCore::fmt", 0x2E338E0, 636, "OrderCore"),
    ("orderbook", "OrderCore::fmt", 0x2E33B60, 636, "OrderCore"),
    ("orderbook", "OrderCore::fmt", 0x5102100, 636, "OrderCore"),
    ("orderbook", "OrderCore::fmt", 0x5102380, 636, "OrderCore"),
    ("orderbook", "OrderCore::fmt", 0x51F8B60, 636, "OrderCore"),
    ("orderbook", "OrderCore::fmt", 0x51F8DE0, 636, "OrderCore"),
    # orderbook: BookOrder::fmt (4 x 693 B = 2,772 B) & &&BookOrder::fmt (4 x 699 B = 2,796 B)
    ("orderbook", "BookOrder::fmt", 0x2329EA0, 693, "BookOrder"),
    ("orderbook", "BookOrder::fmt", 0x232A160, 693, "BookOrder"),
    ("orderbook", "BookOrder::fmt", 0x5101B80, 693, "BookOrder"),
    ("orderbook", "BookOrder::fmt", 0x5101E40, 693, "BookOrder"),
    ("orderbook", "&&BookOrder::fmt", 0x25EAE10, 699, "BookOrder"),
    ("orderbook", "&&BookOrder::fmt", 0x25EB0D0, 699, "BookOrder"),
    ("orderbook", "&&BookOrder::fmt", 0x51AC880, 699, "BookOrder"),
    ("orderbook", "&&BookOrder::fmt", 0x51ACDF0, 699, "BookOrder"),
    # orderbook: OrderDescription::fmt (7 x 582 B = 4,074 B)
    ("orderbook", "OrderDescription::fmt", 0x2329C50, 582, "TwapSlice"),
    ("orderbook", "OrderDescription::fmt", 0x2454380, 582, "TwapSlice"),
    ("orderbook", "OrderDescription::fmt", 0x25FF150, 582, "TwapSlice"),
    ("orderbook", "OrderDescription::fmt", 0x2E33480, 582, "TwapSlice"),
    ("orderbook", "OrderDescription::fmt", 0x51010B0, 582, "TwapSlice"),
    ("orderbook", "OrderDescription::fmt", 0x51F7F40, 582, "TwapSlice"),
    ("orderbook", "OrderDescription::fmt", 0x5AA9090, 582, "TwapSlice"),
    # orderbook: &Level::fmt (4 x 452 B = 1,808 B)
    ("orderbook", "&Level::fmt", 0x241F210, 452, "priority_key_to_order_key"),
    ("orderbook", "&Level::fmt", 0x241FB10, 452, "priority_key_to_order_key"),
    ("orderbook", "&Level::fmt", 0x51AC6B0, 452, "priority_key_to_order_key"),
    ("orderbook", "&Level::fmt", 0x51ACB40, 452, "priority_key_to_order_key"),
    # orderbook: Relationships::fmt (6 x 253 B = 1,518 B)
    ("orderbook", "Relationships::fmt", 0x2323D60, 253, "Relationships"),
    ("orderbook", "Relationships::fmt", 0x2454280, 253, "Relationships"),
    ("orderbook", "Relationships::fmt", 0x25FF050, 253, "Relationships"),
    ("orderbook", "Relationships::fmt", 0x2E32D60, 253, "Relationships"),
    ("orderbook", "Relationships::fmt", 0x51009E0, 253, "Relationships"),
    ("orderbook", "Relationships::fmt", 0x51F7A30, 253, "Relationships"),
    # orderbook: &LevelSummary::fmt (4 x 221 B = 884 B)
    ("orderbook", "&LevelSummary::fmt", 0x241E9B0, 221, "LevelSummary"),
    ("orderbook", "&LevelSummary::fmt", 0x241F410, 221, "LevelSummary"),
    ("orderbook", "&LevelSummary::fmt", 0x51AC4F0, 221, "LevelSummary"),
    ("orderbook", "&LevelSummary::fmt", 0x51AC5D0, 221, "LevelSummary"),
    # orderbook: Half::fmt (4 x 177 B = 708 B)
    ("orderbook", "Half::fmt", 0x2323BE0, 177, "Half"),
    ("orderbook", "Half::fmt", 0x2323CA0, 177, "Half"),
    ("orderbook", "Half::fmt", 0x5100860, 177, "Half"),
    ("orderbook", "Half::fmt", 0x5100920, 177, "Half"),
    # orderbook: &Trigger::fmt (2 x 253 B = 506 B)
    ("orderbook", "&Trigger::fmt", 0x241E3B0, 253, "Trigger"),
    ("orderbook", "&Trigger::fmt", 0x241EE70, 253, "Trigger"),
    # orderbook: &UserState::fmt (2 x 253 B = 506 B)
    ("orderbook", "&UserState::fmt", 0x241F4F0, 253, "book_order_keys"),
    ("orderbook", "&UserState::fmt", 0x241F5F0, 253, "book_order_keys"),
    # orderbook: &TriggerOrder::fmt (2 x 224 B = 448 B)
    ("orderbook", "&TriggerOrder::fmt", 0x241EF70, 224, "TriggerOrder"),
    ("orderbook", "&TriggerOrder::fmt", 0x241F6F0, 224, "TriggerOrder"),
    # orderbook: &&UserCloidTracker::fmt (2 x 224 B = 448 B)
    ("orderbook", "&&UserCloidTracker::fmt", 0x27725C0, 224, "UserCloidTracker"),
    ("orderbook", "&&UserCloidTracker::fmt", 0x4D99FA0, 224, "UserCloidTracker"),
    # orderbook: &PriorityDequeEntry::fmt (2 x 221 B = 442 B)
    ("orderbook", "&PriorityDequeEntry::fmt", 0x241E8D0, 221, "PriorityDequeEntry"),
    ("orderbook", "&PriorityDequeEntry::fmt", 0x51ACD10, 221, "PriorityDequeEntry"),
    # orderbook: &PriorityKey::fmt (2 x 221 B = 442 B)
    ("orderbook", "&PriorityKey::fmt", 0x241FF40, 221, "PriorityKey"),
    ("orderbook", "&PriorityKey::fmt", 0x51AD0B0, 221, "PriorityKey"),
    # orderbook: &CloidTracker::fmt (2 x 180 B = 360 B)
    ("orderbook", "&CloidTracker::fmt", 0x2772BC0, 180, "CloidTracker"),
    ("orderbook", "&CloidTracker::fmt", 0x4D9AFE0, 180, "CloidTracker"),
    # orderbook: Cloid / Oid / TwapId DebugTuple (2,081 B)
    ("orderbook", "&Cloid::fmt", 0x26A0770, 296, "Cloid"),
    ("orderbook", "&Cloid::fmt", 0x53D4BB0, 296, "Cloid"),
    ("orderbook", "&&Cloid::fmt", 0x26A0640, 299, "Cloid"),
    ("orderbook", "&&Cloid::fmt", 0x53D5360, 299, "Cloid"),
    ("orderbook", "&Oid::fmt", 0x241ED40, 296, "Oid"),
    ("orderbook", "&&Oid::fmt", 0x241E670, 299, "Oid"),
    ("orderbook", "&TwapId::fmt", 0x2D49350, 296, "TwapId"),
    # fees: OrderBuilderInfo & SubBuilder (474 B)
    ("fees", "&OrderBuilderInfo::fmt", 0x2D48450, 253, "OrderBuilderInfo"),
    ("fees", "&SubBuilder::fmt", 0x2D48B00, 221, "SubBuilder"),
    # assets: Perp / Spot / Token DebugTuple (2,066 B)
    ("assets", "Perp::fmt", 0x4545530, 293, "Perp"),
    ("assets", "&Perp::fmt", 0x241E280, 296, "Perp"),
    ("assets", "&Perp::fmt", 0x38DB4D0, 296, "Perp"),
    ("assets", "&Perp::fmt", 0x53D5490, 296, "Perp"),
    ("assets", "Spot::fmt", 0x2CC9BC0, 293, "Spot"),
    ("assets", "&Spot::fmt", 0x2D48BF0, 296, "Spot"),
    ("assets", "&Token::fmt", 0x4228AC0, 296, "Token"),
    # assets: SpotMeta::sz_to_f64_zero_fast (3 x 133 B = 399 B)
    ("assets", "SpotMeta::sz_to_f64_zero_fast", 0x269D6A0, 133, None),
    ("assets", "SpotMeta::sz_to_f64_zero_fast", 0x50BEBC0, 133, None),
    ("assets", "SpotMeta::sz_to_f64_zero_fast", 0x57CDAE0, 133, None),
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


def compile_thinlto_objects() -> tuple[list[tuple[str, bytes, list[int]]], str]:
    ver = subprocess.check_output(["rustc", "+1.95.0", "--version"], text=True).strip()
    compiled: list[tuple[str, bytes, list[int]]] = []
    with tempfile.TemporaryDirectory(prefix="re006-e1-thinlto-") as tmpdir:
        tmp = Path(tmpdir)
        outbin = tmp / "stream_e1_thinlto"
        subprocess.run(
            [
                "rustc",
                "+1.95.0",
                "--edition=2021",
                "--crate-name=stream_e1_thinlto",
                "-C",
                "opt-level=3",
                "-C",
                "overflow-checks=yes",
                "-C",
                "lto=thin",
                "-C",
                "save-temps",
                "-o",
                str(outbin),
                str(SOURCE_PATH),
            ],
            cwd=str(tmp),
            check=True,
        )
        for obj_path in sorted(tmp.glob("*.rcgu.o")):
            obj = obj_path.read_bytes()
            secs = parse_elf_sections(obj)
            relas_by_sec: dict[int, list[int]] = {}
            for s in secs:
                if s[2] == 4:  # SHT_RELA
                    relas_by_sec[s[7]] = sorted(
                        struct.unpack_from("<Q", obj, o)[0]
                        for o in range(s[4], s[4] + s[5], 24)
                    )
            for idx, name, _sh_type, _sh_addr, sh_offset, sh_size, _sh_link, _sh_info in secs:
                if not name.startswith(".text.") or sh_size == 0:
                    continue
                if "Debug" not in name and "e1_spot_sz_to_f64_zero_fast" not in name:
                    continue
                body = obj[sh_offset : sh_offset + sh_size]
                rels = [r for r in relas_by_sec.get(idx, []) if 0 <= r < sh_size]
                compiled.append((name, body, rels))
    return compiled, ver


def verify_rodata_anchor(binary: bytes, start: int, size: int, anchor: str | None) -> None:
    """Confirm the target node #115 FDE itself references the claimed type string (or POW10 table)."""
    tbytes = binary[TEXT_OFF + (start - TEXT_VA) : TEXT_OFF + (start - TEXT_VA) + size]
    if anchor is None:
        # Must reference a POW10 f64 table ([1.0, 10.0, 100.0, 1000.0, ...]) via `lea rcx, [rip + disp32]`
        pos = 0
        while True:
            idx = tbytes.find(b"\x48\x8d\x0d", pos)
            if idx == -1 or idx + 7 > len(tbytes):
                break
            disp = struct.unpack_from("<i", tbytes, idx + 3)[0]
            tgt = (start + idx + 7) + disp
            if tgt in POW10_VAS:
                ro_off = RODATA_OFF + (tgt - RODATA_VA)
                if binary[ro_off : ro_off + len(POW10_PREFIX)] == POW10_PREFIX:
                    return
            pos = idx + 1
        raise RuntimeError(f"POW10 anchor not found in 0x{start:x}")

    needle = anchor.encode("ascii")
    pos = 0
    while True:
        idx = tbytes.find(b"\x48\x8d\x35", pos)
        if idx == -1 or idx + 7 > len(tbytes):
            break
        disp = struct.unpack_from("<i", tbytes, idx + 3)[0]
        tgt = (start + idx + 7) + disp
        if RODATA_VA <= tgt < RODATA_VA + RODATA_SZ:
            ro_off = RODATA_OFF + (tgt - RODATA_VA)
            if binary[ro_off : ro_off + len(needle)] == needle:
                return
        pos = idx + 1
    raise RuntimeError(f"RODATA anchor {anchor!r} not found in 0x{start:x}")


def build_records() -> dict:
    binary = BINARY_PATH.read_bytes()
    actual_sha = hashlib.sha256(binary).hexdigest()
    if actual_sha != EXPECTED_BINARY_SHA256 or len(binary) != EXPECTED_BINARY_SIZE:
        raise RuntimeError(f"Target binary mismatch: {actual_sha} ({len(binary)} B)")

    fdes = load_fde_map()
    compiled, compiler_ver = compile_thinlto_objects()

    records = []
    by_comp: dict[str, dict[str, int]] = {}
    for comp, label, start, size, anchor in TARGET_WINDOWS:
        end = start + size
        if fdes.get(start) != end:
            raise RuntimeError(
                f"FDE mismatch for {label} 0x{start:x}: expected 0x{end:x}, got {fdes.get(start)}"
            )
        verify_rodata_anchor(binary, start, size, anchor)
        tbytes = binary[TEXT_OFF + (start - TEXT_VA) : TEXT_OFF + (end - TEXT_VA)]

        matched = None
        for sec_name, cbytes, rels in compiled:
            if len(cbytes) != size:
                continue
            masked = set()
            for roff in rels:
                for k in range(4):
                    masked.add(roff + k)
            if all(i in masked or cbytes[i] == tbytes[i] for i in range(size)):
                raw_eq = sum(1 for a, b in zip(cbytes, tbytes) if a == b)
                if matched is None or raw_eq > matched[3]:
                    matched = (sec_name, cbytes, rels, raw_eq)

        if matched is None:
            raise RuntimeError(
                f"No 100% relocation-qualified compiled match for {label} 0x{start:x} ({size} B)"
            )
        sec_name, cbytes, rels, raw_eq = matched
        records.append(
            {
                "component": comp,
                "label": label,
                "compiled_section": sec_name,
                "rodata_anchor": anchor if anchor is not None else "POW10_f64_table",
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
        "work_item": "RE-006-node115-stream-e1-thinlto-byte-matches",
        "target_binary": "artifacts/node/115/hl-node",
        "target_sha256": EXPECTED_BINARY_SHA256,
        "compiler": compiler_ver,
        "compiler_flags": [
            "+1.95.0",
            "--edition=2021",
            "-C",
            "opt-level=3",
            "-C",
            "overflow-checks=yes",
            "-C",
            "lto=thin",
            "-C",
            "save-temps",
        ],
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


def _parse_addr(val: str | int) -> int:
    return int(val, 16) if isinstance(val, str) else int(val)


def verify_records(expected: dict, *, allow_corrupt_check: bool = False) -> None:
    actual = build_records()
    if actual != expected:
        raise RuntimeError("Rebuilt compiled-byte records do not match committed records.json")

    bw = json.loads(BYTE_WINDOWS_JSON.read_text(encoding="utf-8"))
    bw_entries: list[tuple[int, int, bool]] = [
        (_parse_addr(w["start"]), _parse_addr(w["end"]), "dependency" in w)
        for w in bw["windows"]
    ]

    # Reject any overlap with ALL other work-item byte-match packets
    sibling_entries: list[tuple[int, int, str]] = []
    for p in sorted((REPO_ROOT / "research" / "work-items").glob("RE-*")):
        if p.resolve() == PACKET_DIR.resolve():
            continue
        for fn in ("records.json", "windows.json"):
            fp = p / fn
            if not fp.exists():
                continue
            sib = json.loads(fp.read_text(encoding="utf-8"))
            items = sib if isinstance(sib, list) else sib.get("windows", sib.get("records", []))
            if not isinstance(items, list):
                continue
            for w in items:
                if not isinstance(w, dict):
                    continue
                sv = w.get("start_va", w.get("start"))
                ev = w.get("end_va", w.get("end"))
                szv = w.get("size", w.get("len"))
                if sv is None or (ev is None and szv is None):
                    continue
                si = _parse_addr(sv)
                ei = _parse_addr(ev) if ev is not None else si + int(szv)
                sibling_entries.append((si, ei, f"{p.name}/{fn}"))

    seen: set[int] = set()
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
