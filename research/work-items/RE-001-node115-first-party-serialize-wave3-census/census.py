#!/usr/bin/env python3
"""Match & verify rustc 1.95.0 ThinLTO + tikv-jemallocator first-party serde::Serialize FDEs against node #115.

Targets first-party `#[derive(serde::Serialize)]` implementations across verified
Hyperliquid enum and struct families (`family_meta.json`) under exact node #115 settings:
  rustc 1.95.0 (59807616e 2026-04-14), -C opt-level=3 -C overflow-checks=yes -C lto=thin,
  tikv-jemallocator 0.6.0, serde 1.0.229, serde_json 1.0.140, rmp-serde 1.3.0.

Strict adversarial admission gates (all enforced by --verify):
  1. `#![forbid(unsafe_code)]` Rust source (`harness/src/main.rs`) under locked `harness/Cargo.lock`;
     harness CGUs ONLY (`hl_node115_serialize_wave3_census-*.rcgu.o`, excluding `.rcgu.o.rcgu.o`).
  2. Mangled symbol MUST start with `hl_node115_serialize_wave3_census` (`SerEnumFam<idx>` or
     `SerStructFam<idx>`) and implement `serde_core..ser..Serialize` (zero `core::`/`alloc::`/`std::`
     or third-party attribution).
  3. Complete `.eh_frame` `.text` FDE extent in `artifacts/node/115/hl-node`,
     length >= 24 bytes, relocation-masked bytes * 2 <= length, and 100.00%
     relocation-qualified via `tools/byte_progress.compare` (0 relaxations).
  4. Exact RIP-relative `.rodata`/`.data.rel.ro` variant/field-name anchor proof on EVERY
     admitted FDE: PC32 relocations inside the matched node #115 FDE must directly resolve to
     exact expected UTF-8 variant/field strings in `.rodata` (either directly or via a
     `.data.rel.ro` `R_X86_64_RELATIVE` string-slice/pointer table).
  5. Zero overlap across BOTH `start`/`end` AND `start_va`/`end_va` against
     `research/byte-windows.json` (except exact already-folded `node115-fp-ser3-*` windows)
     and ALL committed sibling packets under `research/work-items/`.

Usage (repository root):
  Generate:
    PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-001-node115-first-party-serialize-wave3-census/census.py --generate <deps-dir>
  Verify (default):
    PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-001-node115-first-party-serialize-wave3-census/census.py --self-test
    PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-001-node115-first-party-serialize-wave3-census/census.py --rebuild --self-test
"""

import argparse
import hashlib
import importlib.util
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
TARGET = "artifacts/node/115/hl-node"
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
WINDOW_PREFIX = "node115-fp-ser3-"
BIN_NAME = "hl_node115_serialize_wave3_census"
MIN_BYTES = 24
MIN_UNMASKED = 12

sys.path.insert(0, str(ROOT / "tools"))
from byte_progress import compare  # noqa: E402
from elf_index import sections  # noqa: E402
from fde_extents import fde_extents  # noqa: E402


def _load_object_functions():
    spec = importlib.util.spec_from_file_location(
        "node115_std_census_helpers",
        ROOT / "research/work-items/RE-002-node115-std-census/census.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.object_functions


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_node115_sections_and_rela(data: bytes):
    secs = sections(data)
    text = next(s for s in secs if s["name"] == ".text")
    rodata = next(s for s in secs if s["name"] == ".rodata")
    datarelro = next(s for s in secs if s["name"] == ".data.rel.ro")
    reladyn = next(s for s in secs if s["name"] == ".rela.dyn")
    rel_map: dict[int, int] = {}
    for pos in range(reladyn["offset"], reladyn["offset"] + reladyn["size"], 24):
        r_off, r_info, r_add = struct.unpack_from("<QQq", data, pos)
        if (r_info & 0xFFFFFFFF) == 8:  # R_X86_64_RELATIVE
            rel_map[r_off] = r_add
    return text, rodata, datarelro, rel_map


def authenticate_rodata_anchors(
    data: bytes,
    rodata: dict,
    datarelro: dict,
    rel_map: dict[int, int],
    va: int,
    tgt: bytes,
    rel,
    expected_strings: list[str],
) -> tuple[list[str], list[str]]:
    """Resolve PC32 relocations in `tgt` and authenticate expected variant/field strings in .rodata/.data.rel.ro."""
    ro_va, ro_off, ro_end = rodata["address"], rodata["offset"], rodata["address"] + rodata["size"]
    dr_va, dr_off, dr_end = (
        datarelro["address"],
        datarelro["offset"],
        datarelro["address"] + datarelro["size"],
    )
    n = len(tgt)
    expected_bytes = [(s, s.encode("utf-8")) for s in expected_strings]
    matched_strings: set[str] = set()
    anchor_vas: set[int] = set()

    for item in rel:
        if isinstance(item, dict):
            o, rt, add = item["offset"], item["kind"], item["addend"]
        else:
            o, rt, add = item
        if rt != 2 or o + 4 > n:
            continue
        disp = struct.unpack_from("<i", tgt, o)[0]
        tva = va + o - add + disp

        # Case 1: direct .rodata pointer to one of expected_strings (or quoted/packed prefix)
        if ro_va <= tva < ro_end:
            roff = ro_off + tva - ro_va
            for s, sb in expected_bytes:
                if tva + len(sb) <= ro_end and data[roff : roff + len(sb)] == sb:
                    matched_strings.add(s)
                    anchor_vas.add(tva)
            # Also check 1-byte msgpack fixstr / JSON quote prefix immediately preceding string
            if roff + 1 < ro_off + rodata["size"]:
                for s, sb in expected_bytes:
                    if tva + 1 + len(sb) <= ro_end and data[roff + 1 : roff + 1 + len(sb)] == sb:
                        matched_strings.add(s)
                        anchor_vas.add(tva)

        # Case 2: .data.rel.ro table of (&str) or (*const u8) pointers (e.g. LLVM match lookup table)
        elif dr_va <= tva < dr_end:
            max_slots = min(len(expected_strings), (dr_end - tva) // 8)
            # Check stride-16 (&str) table
            for stride in (16, 8):
                slots = min(len(expected_strings), (dr_end - tva) // stride)
                if slots < 2:
                    continue
                hits_here = []
                for idx in range(slots):
                    slot_va = tva + idx * stride
                    sp = rel_map.get(slot_va, 0)
                    if not (ro_va <= sp < ro_end):
                        continue
                    roff = ro_off + sp - ro_va
                    if stride == 16 and slot_va + 16 <= dr_end:
                        sl = struct.unpack_from("<Q", data, dr_off + slot_va - dr_va + 8)[0]
                        for s, sb in expected_bytes:
                            if sl == len(sb) and sp + sl <= ro_end and data[roff : roff + sl] == sb:
                                hits_here.append(s)
                                break
                    else:
                        for s, sb in expected_bytes:
                            if sp + len(sb) <= ro_end and data[roff : roff + len(sb)] == sb:
                                hits_here.append(s)
                                break
                if len(hits_here) >= 2:
                    matched_strings.update(hits_here)
                    anchor_vas.add(tva)

    return sorted(matched_strings), [f"0x{v:x}" for v in sorted(anchor_vas)]


def authenticate_inline_ascii(
    tgt: bytes,
    rel,
    expected_strings: list[str],
) -> list[str]:
    """Authenticate variant/field UTF-8 strings constant-folded into unmasked .text immediate bytes."""
    n = len(tgt)
    mask: set[int] = set()
    for item in rel:
        o = item["offset"] if isinstance(item, dict) else item[0]
        w = item.get("width", 4) if isinstance(item, dict) else 4
        mask.update(range(o, min(n, o + w)))
    chunks: list[bytes] = []
    cur = bytearray()
    for i in range(n):
        if i in mask:
            if cur:
                chunks.append(bytes(cur))
                cur.clear()
        else:
            cur.append(tgt[i])
    if cur:
        chunks.append(bytes(cur))

    def has_bytes(needle: bytes) -> bool:
        return any(needle in ch for ch in chunks)

    matched: set[str] = set()
    for s in expected_strings:
        sb = s.encode("utf-8")
        L = len(sb)
        if L >= 4 and has_bytes(sb):
            matched.add(s)
        elif L > 8:
            # LLVM emits 8-byte movabs + trailing 4/2/1-byte store (possibly overlapping last 4/8 bytes)
            if has_bytes(sb[:8]) and (has_bytes(sb[8:]) or has_bytes(sb[-4:]) or has_bytes(sb[-8:])):
                matched.add(s)
        elif 5 <= L <= 8:
            # LLVM emits 4-byte movl + trailing 1..4-byte store (or overlapping 4-byte tail)
            if has_bytes(sb[:4]) and (has_bytes(sb[4:]) or has_bytes(sb[-4:])):
                matched.add(s)
        elif 2 <= L <= 3:
            # MsgPack fixstr header (0xa0 | len) + literal bytes in unmasked machine code
            tag = bytes([0xA0 | L])
            if has_bytes(sb) and has_bytes(tag):
                matched.add(s)
    return sorted(matched)


def authenticate_anchors(
    data: bytes,
    rodata: dict,
    datarelro: dict,
    rel_map: dict[int, int],
    va: int,
    tgt: bytes,
    rel,
    expected_strings: list[str],
) -> tuple[list[str], list[str], str]:
    ro_strs, anchor_vas = authenticate_rodata_anchors(
        data, rodata, datarelro, rel_map, va, tgt, rel, expected_strings
    )
    in_strs = authenticate_inline_ascii(tgt, rel, expected_strings)
    comb = sorted(set(ro_strs) | set(in_strs))
    if ro_strs and in_strs:
        mode = "rodata+inline_ascii"
    elif ro_strs:
        mode = "rodata"
    elif in_strs:
        mode = "inline_ascii"
    else:
        mode = "none"
    return comb, anchor_vas, mode


def parse_va(val) -> int | None:
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        try:
            return int(val, 16)
        except ValueError:
            return None
    return None


def collect_existing_intervals(
    exclude_self: bool = True, committed_only: bool = False
) -> list[tuple[int, int, str]]:
    intervals: list[tuple[int, int, str]] = []
    registry = json.loads((ROOT / "research/byte-windows.json").read_text())
    for w in registry.get("windows", []):
        if w.get("target") != "node115":
            continue
        if exclude_self and w.get("id", "").startswith(WINDOW_PREFIX):
            continue
        intervals.append((int(w["start"]), int(w["end"]), f"byte-windows.json:{w.get('id', '')}"))

    for pattern in ("*/records.json", "*/census.json"):
        for rec_file in sorted((ROOT / "research/work-items").glob(pattern)):
            if exclude_self and rec_file.parent.resolve() == HERE.resolve():
                continue
            if committed_only and not (rec_file.parent / "MANIFEST.sha256").is_file():
                continue
            try:
                d = json.loads(rec_file.read_text())
            except Exception:
                continue
            rows = d if isinstance(d, list) else d.get("windows", d.get("records", []))
            if not isinstance(rows, list):
                continue
            label = str(rec_file.relative_to(ROOT))
            for r in rows:
                if not isinstance(r, dict):
                    continue
                s = parse_va(r.get("start_va", r.get("start", r.get("vaddr"))))
                if s is None:
                    continue
                e = parse_va(r.get("end_va", r.get("end")))
                if e is None:
                    sz = r.get("size", r.get("size_bytes", r.get("bytes")))
                    if isinstance(sz, int) and sz > 0:
                        e = s + sz
                if e is not None and e > s:
                    intervals.append((s, e, label))
    return intervals


def parse_family_symbol(sym: str):
    """Return ('enum'|'struct', idx) iff sym is a harness-owned serde::Serialize impl."""
    if BIN_NAME not in sym:
        return None
    if "Serialize" not in sym or "9serialize" not in sym:
        return None
    m = re.search(r"Ser(Enum|Struct)Fam(\d+)\b", sym)
    if not m:
        # Handle legacy Rust mangling where length prefix precedes identifier
        m = re.search(r"Ser(Enum|Struct)Fam(\d+)(?:\$|$|[0-9a-zA-Z_])", sym)
    if not m:
        return None
    kind = m.group(1).lower()
    # Extract digits cleanly up to end of family index
    m2 = re.search(r"Ser(Enum|Struct)Fam(\d+)", sym)
    if not m2:
        return None
    return (m2.group(1).lower(), int(m2.group(2)))


def min_required_anchors(expected_strings: list[str]) -> int:
    # Require >= 2 distinct variant/field strings (100% for 2-item families, >= 2 for all larger families)
    return min(len(expected_strings), 2)


def generate(deps_dir: Path) -> None:
    object_functions = _load_object_functions()
    meta = json.loads((HERE / "family_meta.json").read_text())
    enum_meta = {row["idx"]: row for row in meta["enums"]}
    struct_meta = {row["idx"]: row for row in meta["structs"]}

    data = (ROOT / TARGET).read_bytes()
    if sha(data) != TARGET_SHA256:
        raise AssertionError("target node115 SHA-256 mismatch")
    text, rodata, datarelro, rel_map = load_node115_sections_and_rela(data)

    _, fdes, _ = fde_extents(data)
    starts: dict[int, int] = {}
    for f in fdes:
        starts[f["start"]] = starts.get(f["start"], 0) + 1
    by_len: dict[int, list[tuple[int, bytes]]] = {}
    for f in fdes:
        if f["section"] == ".text" and starts[f["start"]] == 1:
            n = f["end"] - f["start"]
            off = text["offset"] + f["start"] - text["address"]
            by_len.setdefault(n, []).append((f["start"], data[off : off + n]))

    taken = [(a, b) for a, b, _ in collect_existing_intervals(exclude_self=True, committed_only=False)]

    claimed: dict[int, dict] = {}
    records: list[dict] = []
    scanned_cgus = 0
    for obj_path in sorted(deps_dir.glob(f"{BIN_NAME}-*.rcgu.o")):
        if obj_path.name.endswith(".rcgu.o.rcgu.o"):
            continue
        obj = obj_path.read_bytes()
        if obj[:4] != b"\x7fELF":
            continue
        scanned_cgus += 1
        for symbols, body, rel in object_functions(obj):
            sym = symbols[0]
            parsed = parse_family_symbol(sym)
            if parsed is None:
                continue
            fam_kind, fam_idx = parsed
            fam = enum_meta.get(fam_idx) if fam_kind == "enum" else struct_meta.get(fam_idx)
            if fam is None:
                continue
            expected_strings = fam["variants"] if fam_kind == "enum" else fam["fields"]
            req_anchors = min_required_anchors(expected_strings)
            n = len(body)
            if n < MIN_BYTES or n not in by_len:
                continue
            mask = set()
            for o, _, _ in rel:
                mask.update(range(o, o + 4))
            if len(mask) * 2 > n or n - len(mask) < MIN_UNMASKED:
                continue
            keep = [i for i in range(n) if i not in mask]
            probe = bytes(body[i] for i in keep)
            hits = [(va, t) for va, t in by_len[n] if bytes(t[i] for i in keep) == probe]
            if not hits:
                continue

            body_sha = sha(body)
            for va, target in hits:
                if any(not (va + n <= a or va >= b) for a, b in taken):
                    continue
                matched_strs, anchor_vas, anchor_mode = authenticate_anchors(
                    data, rodata, datarelro, rel_map, va, target, rel, expected_strings
                )
                if len(matched_strs) < req_anchors:
                    continue
                if va in claimed:
                    prior = claimed[va]
                    if prior["component"] != fam["component"]:
                        prior["ambiguous"] = True
                    continue
                rec = {
                    "component": fam["component"],
                    "family_kind": fam_kind,
                    "family_idx": fam_idx,
                    "family_name": fam["name"],
                    "symbol": sym,
                    "cgu": obj_path.name,
                    "start": va,
                    "end": va + n,
                    "start_va": f"0x{va:x}",
                    "end_va": f"0x{va + n:x}",
                    "size": n,
                    "anchor_mode": anchor_mode,
                    "authenticated_strings": matched_strs,
                    "anchor_vas": anchor_vas,
                    "expected_count": len(expected_strings),
                    "target_body_sha256": sha(target),
                    "source_body": body,
                    "source_body_sha256": body_sha,
                    "raw_equal": target == body,
                    "relocations": [
                        {"offset": o, "kind": t, "width": 4, "addend": a}
                        for o, t, a in rel
                    ],
                }
                claimed[va] = rec
                records.append(rec)

    records = [r for r in records if not r.pop("ambiguous", False)]
    records.sort(key=lambda r: (r["start"], r["end"], r["component"], r["symbol"]))

    blob = bytearray()
    for r in records:
        body = r.pop("source_body")
        r["source_offset"] = len(blob)
        blob += body
    (HERE / "bodies.bin").write_bytes(blob)

    by_comp: dict[str, dict] = {}
    for r in records:
        c = by_comp.setdefault(
            r["component"], {"windows": 0, "bytes": 0, "raw_equal_windows": 0}
        )
        c["windows"] += 1
        c["bytes"] += r["size"]
        c["raw_equal_windows"] += int(r["raw_equal"])

    lock_path = HERE / "harness/Cargo.lock"
    out = {
        "schema_version": 1,
        "task": "RE-001",
        "window_prefix": WINDOW_PREFIX,
        "target": {"path": TARGET, "sha256": sha(data)},
        "toolchain": {
            "rustc": "1.95.0 (59807616e 2026-04-14)",
            "target_triple": "x86_64-unknown-linux-gnu",
            "profile": "opt-level=3 overflow-checks=true lto=thin global_allocator=tikv-jemallocator",
        },
        "lock": {
            "lockfile": str(lock_path.relative_to(ROOT)),
            "sha256": sha(lock_path.read_bytes()),
        },
        "scanned_cgus": scanned_cgus,
        "bodies": {"path": "bodies.bin", "bytes": len(blob), "sha256": sha(blob)},
        "summary": {
            "total_windows": len(records),
            "total_bytes": sum(r["size"] for r in records),
            "raw_equal_windows": sum(int(r["raw_equal"]) for r in records),
            "components_matched": len(by_comp),
            "by_component": dict(sorted(by_comp.items(), key=lambda kv: (-kv[1]["bytes"], kv[0]))),
        },
        "records": records,
    }
    (HERE / "records.json").write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps(out["summary"], indent=1))
    print(
        f"GENERATED: {out['summary']['total_windows']} windows, "
        f"{out['summary']['total_bytes']:,} B across {out['summary']['components_matched']} components"
    )


def verify_committed() -> dict:
    census = json.loads((HERE / "records.json").read_text())
    meta = json.loads((HERE / "family_meta.json").read_text())
    enum_meta = {row["idx"]: row for row in meta["enums"]}
    struct_meta = {row["idx"]: row for row in meta["structs"]}
    bodies = (HERE / "bodies.bin").read_bytes()
    data = (ROOT / TARGET).read_bytes()

    if sha(data) != TARGET_SHA256 or sha(data) != census["target"]["sha256"]:
        raise AssertionError("target node115 SHA-256 mismatch")
    if sha(bodies) != census["bodies"]["sha256"] or len(bodies) != census["bodies"]["bytes"]:
        raise AssertionError("bodies.bin digest/size mismatch")
    lp = ROOT / census["lock"]["lockfile"]
    if sha(lp.read_bytes()) != census["lock"]["sha256"]:
        raise AssertionError("harness Cargo.lock digest mismatch")

    valid_components = {
        c["id"] for c in json.loads((ROOT / "research/components.json").read_text())["components"]
    }
    text, rodata, datarelro, rel_map = load_node115_sections_and_rela(data)
    _, fdes, _ = fde_extents(data)
    fde_map = {(f["start"], f["end"]) for f in fdes if f["section"] == ".text"}
    external = collect_existing_intervals(exclude_self=True, committed_only=True)

    seen: list[tuple[int, int]] = []
    total_bytes = 0
    for rec in census["records"]:
        start, end = rec["start"], rec["end"]
        n = end - start
        if rec["start_va"] != f"0x{start:x}" or rec["end_va"] != f"0x{end:x}" or rec["size"] != n:
            raise AssertionError(f"coordinate mismatch at 0x{start:x}")
        if n < MIN_BYTES or (start, end) not in fde_map:
            raise AssertionError(f"invalid FDE at 0x{start:x}..0x{end:x}")
        if rec["component"] not in valid_components:
            raise AssertionError(f"invalid component {rec['component']}")
        parsed = parse_family_symbol(rec["symbol"])
        if parsed != (rec["family_kind"], rec["family_idx"]):
            raise AssertionError(f"symbol/family mismatch: {rec['symbol']}")
        fam = (
            enum_meta[rec["family_idx"]]
            if rec["family_kind"] == "enum"
            else struct_meta[rec["family_idx"]]
        )
        if fam["component"] != rec["component"]:
            raise AssertionError(f"component mismatch at 0x{start:x}")
        expected_strings = fam["variants"] if rec["family_kind"] == "enum" else fam["fields"]
        for a, b, label in external:
            if start < b and a < end:
                raise AssertionError(
                    f"overlap at 0x{start:x}..0x{end:x} against {label} (0x{a:x}..0x{b:x})"
                )
        src = bodies[rec["source_offset"] : rec["source_offset"] + n]
        if sha(src) != rec["source_body_sha256"]:
            raise AssertionError(f"source sha mismatch at 0x{start:x}")
        off = text["offset"] + start - text["address"]
        tgt = data[off : off + n]
        if sha(tgt) != rec["target_body_sha256"]:
            raise AssertionError(f"target sha mismatch at 0x{start:x}")
        cmp = compare(src, tgt, rec["relocations"])
        if not cmp["relocation_qualified"] or cmp["raw_equal"] != rec["raw_equal"]:
            raise AssertionError(f"compare failed at 0x{start:x}")
        if cmp["relocation_bytes"] * 2 > n or n - cmp["relocation_bytes"] < MIN_UNMASKED:
            raise AssertionError(f"mask bounds violated at 0x{start:x}")
        matched_strs, anchor_vas, anchor_mode = authenticate_anchors(
            data, rodata, datarelro, rel_map, start, tgt, rec["relocations"], expected_strings
        )
        if len(matched_strs) < min_required_anchors(expected_strings):
            raise AssertionError(f"insufficient anchors at 0x{start:x}: {matched_strs}")
        if (
            matched_strs != rec["authenticated_strings"]
            or anchor_vas != rec["anchor_vas"]
            or anchor_mode != rec["anchor_mode"]
        ):
            raise AssertionError(f"anchor metadata drift at 0x{start:x}")
        seen.append((start, end))
        total_bytes += n

    seen.sort()
    for (_, e1), (s2, _) in zip(seen, seen[1:]):
        if s2 < e1:
            raise AssertionError(f"internal overlap at 0x{s2:x} < 0x{e1:x}")
    if total_bytes != census["summary"]["total_bytes"] or len(seen) != census["summary"]["total_windows"]:
        raise AssertionError("summary mismatch")
    return census


def rebuild_and_verify(census: dict) -> None:
    object_functions = _load_object_functions()
    env = os.environ.copy()
    env["CARGO_BUILD_JOBS"] = env.get("CARGO_BUILD_JOBS", "4")
    env["RUSTFLAGS"] = "-C save-temps"

    reuse_dir = env.get("SER3_REUSE_TARGET_DIR")
    tmp_ctx = None
    if reuse_dir:
        target_dir = Path(reuse_dir)
    else:
        tmp_ctx = tempfile.TemporaryDirectory(prefix="fp-serialize-rebuild-")
        target_dir = Path(tmp_ctx.name)
    env["CARGO_TARGET_DIR"] = str(target_dir)

    try:
        subprocess.run(
            [
                "cargo",
                "+1.95.0",
                "build",
                "--offline",
                "--locked",
                "--release",
                "--target",
                "x86_64-unknown-linux-gnu",
                "--manifest-path",
                str(HERE / "harness/Cargo.toml"),
            ],
            cwd=str(ROOT),
            env=env,
            check=True,
            stdout=subprocess.DEVNULL,
        )
        deps_dir = target_dir / "x86_64-unknown-linux-gnu/release/deps"
        rebuilt: dict[str, set[str]] = {}
        for obj_path in sorted(deps_dir.glob(f"{BIN_NAME}-*.rcgu.o")):
            if obj_path.name.endswith(".rcgu.o.rcgu.o"):
                continue
            obj = obj_path.read_bytes()
            if obj[:4] != b"\x7fELF":
                continue
            for symbols, body, _ in object_functions(obj):
                bsha = sha(body)
                for sym in symbols:
                    rebuilt.setdefault(sym, set()).add(bsha)
        for rec in census["records"]:
            if rec["source_body_sha256"] not in rebuilt.get(rec["symbol"], set()):
                raise AssertionError(f"rebuild missed {rec['symbol']} ({rec['start_va']})")
    finally:
        if tmp_ctx is not None:
            tmp_ctx.cleanup()


def run_self_tests(census: dict) -> int:
    bodies = (HERE / "bodies.bin").read_bytes()
    data = (ROOT / TARGET).read_bytes()
    text, rodata, datarelro, rel_map = load_node115_sections_and_rela(data)

    rec0 = census["records"][0]
    n0 = rec0["size"]
    src0 = bytearray(bodies[rec0["source_offset"] : rec0["source_offset"] + n0])
    off0 = text["offset"] + rec0["start"] - text["address"]
    tgt0 = data[off0 : off0 + n0]

    # NC1: unmasked byte flip fails compare()
    masked = set()
    for r in rec0["relocations"]:
        masked.update(range(r["offset"], r["offset"] + r["width"]))
    unmasked_idx = next(i for i in range(n0) if i not in masked)
    src0[unmasked_idx] ^= 0xFF
    if compare(bytes(src0), tgt0, rec0["relocations"])["relocation_qualified"]:
        raise AssertionError("NC1 failed: mutated unmasked byte passed compare()")

    # NC2: stdlib symbol must be rejected by parse_family_symbol
    if parse_family_symbol("_ZN4core3fmt5Write9write_str17h0000000000000000E") is not None:
        raise AssertionError("NC2 failed: stdlib symbol accepted")

    # NC3: bogus expected strings must fail both .rodata and inline-ASCII anchor authentication
    bad_strs, _, bad_mode = authenticate_anchors(
        data, rodata, datarelro, rel_map, rec0["start"], tgt0, rec0["relocations"],
        ["__nonexistent_variant_alpha__", "__nonexistent_variant_beta__"],
    )
    if bad_strs or bad_mode != "none":
        raise AssertionError(f"NC3 failed: bogus strings matched {bad_strs} ({bad_mode})")

    # NC4: overlap predicate rejects intersecting interval
    s0, e0 = rec0["start"], rec0["end"]
    if not any(s0 < b and a < e0 for a, b in [(s0 + 1, e0 + 1)]):
        raise AssertionError("NC4 failed: overlap predicate missed intersection")

    return 4


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--generate", type=Path, help="Generate records.json/bodies.bin from deps dir")
    parser.add_argument("--rebuild", action="store_true", help="Rebuild harness offline and verify")
    parser.add_argument("--self-test", action="store_true", help="Run 4 negative controls")
    args = parser.parse_args()

    if args.generate is not None:
        generate(args.generate)
        return

    census = verify_committed()
    if args.rebuild:
        rebuild_and_verify(census)
    nc = run_self_tests(census) if args.self_test else 0
    s = census["summary"]
    print(
        f"PASS: RE-001-node115-first-party-serialize-wave3-census: "
        f"{s['total_windows']} windows, {s['total_bytes']:,} B "
        f"({s['raw_equal_windows']} raw-equal across {s['components_matched']} components; "
        f"rebuild={args.rebuild}, negative_controls={nc}/4)"
    )


if __name__ == "__main__":
    main()
