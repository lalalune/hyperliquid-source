#!/usr/bin/env python3
"""Live rustc +1.95.0 compiled-byte verifier for RE-008-node115-consensus-bincode-encode-byte-matches.

Verifies 23 strictly disjoint, zero-overlap, 100.00% relocation-qualified pure first-party
`consensus` `bincode-fork` `Encode` `.text` FDEs (6,916 B total; 6,330/6,916 = 91.53% raw-equal,
0 non-relocation byte differences, 0 external crates.io deps, `#![forbid(unsafe_code)]`) in
Linux x86-64 node #115 (`artifacts/node/115/hl-node`).
"""

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

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
RECORDS_PATH = HERE / "records.json"
SRC_PATH = HERE / "consensus_encode.rs"
FDE_TSV_PATH = REPO / "work" / "index" / "node-115-fde.tsv"
BYTE_WINDOWS_PATH = REPO / "research" / "byte-windows.json"
WORK_ITEMS_DIR = REPO / "research" / "work-items"

TARGET_REL = "artifacts/node/115/hl-node"
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET_SIZE = 105_896_032

RUSTC_FLAGS = [
    "--edition=2021",
    "--crate-type=rlib",
    "--crate-name",
    "cs_bincode_enc",
    "-C",
    "opt-level=3",
    "-C",
    "overflow-checks=yes",
    "-C",
    "relocation-model=pie",
    "-C",
    "lto=off",
    "--emit=obj",
]

# (component, label, wrapper_substr, start_va, expected_size, expected_call_targets)
SPECS: list[tuple[str, str, str, int, int, list[int]]] = [
    (
        "consensus",
        "<Qc as Encode>::encode<&mut SizeWriter>@0x5966770",
        "call_qc_refsize",
        0x5966770,
        339,
        [0x5822850, 0x5822460, 0x51FF410, 0x5827400],
    ),
    (
        "consensus",
        "<Qc as Encode>::encode<SizeWriter>@0x59668d0",
        "call_qc_size",
        0x59668D0,
        339,
        [0x5822B90, 0x5822370, 0x5201150, 0x58275B0],
    ),
    (
        "consensus",
        "<Qc as Encode>::encode<VecWriter>@0x5966a30",
        "call_qc_vec",
        0x5966A30,
        339,
        [0x5822910, 0x5822260, 0x51FFAA0, 0x58265D0],
    ),
    (
        "consensus",
        "<BlockHeader as Encode>::encode<VecWriter>@0x5966b90",
        "call_bh_vec",
        0x5966B90,
        305,
        [0x58221E0, 0x5822910, 0x5822260],
    ),
    (
        "consensus",
        "<BlockHeader as Encode>::encode<SizeWriter>@0x5966cd0",
        "call_bh_size",
        0x5966CD0,
        301,
        [0x58223A0, 0x5822B90, 0x5822370],
    ),
    (
        "consensus",
        "<Block as Encode>::encode<&mut SizeWriter>@0x5966e40",
        "call_blk_refsize",
        0x5966E40,
        532,
        [0x5822850, 0x5822460, 0x4ECAA90, 0x5822160, 0x5966770, 0x4DE6640, 0x4E05940],
    ),
    (
        "consensus",
        "<Block as Encode>::encode<VecWriter>@0x5967060",
        "call_blk_vec",
        0x5967060,
        558,
        [0x58221E0, 0x5822910, 0x5822260, 0x4ECABA0, 0x5821F30, 0x5966A30, 0x4DE66A0, 0x4E05700],
    ),
    (
        "consensus",
        "<Block as Encode>::encode<SizeWriter>@0x5967290",
        "call_blk_size",
        0x5967290,
        542,
        [0x58223A0, 0x5822B90, 0x5822370, 0x4ECACB0, 0x58220E0, 0x59668D0, 0x4DE6670, 0x4E05550],
    ),
    (
        "consensus",
        "<TcVote as Encode>::encode<VecWriter>@0x59676c0",
        "call_tcv_vec",
        0x59676C0,
        250,
        [0x58221E0, 0x5822910, 0x5966A30],
    ),
    (
        "consensus",
        "<TcVote as Encode>::encode<SizeWriter>@0x59677c0",
        "call_tcv_size",
        0x59677C0,
        243,
        [0x58223A0, 0x5822B90, 0x59668D0],
    ),
    (
        "consensus",
        "<Timeout as Encode>::encode<VecWriter>@0x5967d90",
        "call_to_vec",
        0x5967D90,
        229,
        [0x58221E0, 0x5822910],
    ),
    (
        "consensus",
        "<Timeout as Encode>::encode<SizeWriter>@0x5967e80",
        "call_to_size",
        0x5967E80,
        225,
        [0x58223A0, 0x5822B90],
    ),
    (
        "consensus",
        "<Signature as Encode>::encode<SizeWriter>@0x5967f70",
        "call_sig_size",
        0x5967F70,
        302,
        [0x5822B90],
    ),
    (
        "consensus",
        "<Signature as Encode>::encode<&mut SizeWriter>@0x59680a0",
        "call_sig_refsize",
        0x59680A0,
        299,
        [0x5822850],
    ),
    (
        "consensus",
        "<Option<(Block, Qc)> as Encode>::encode<SizeWriter>@0x4e05490",
        "call_opt_bq_size",
        0x4E05490,
        192,
        [0x58292C0, 0x59668D0],
    ),
    (
        "consensus",
        "<Option<Qc> as Encode>::encode<SizeWriter>@0x4e05550",
        "call_opt_qc_size",
        0x4E05550,
        127,
        [0x59668D0],
    ),
    (
        "consensus",
        "<Option<(Block, Qc)> as Encode>::encode<VecWriter>@0x4e055d0",
        "call_opt_bq_vec",
        0x4E055D0,
        291,
        [0x5829210, 0x5966A30, 0x5963A10],
    ),
    (
        "consensus",
        "<Option<Qc> as Encode>::encode<VecWriter>@0x4e05700",
        "call_opt_qc_vec",
        0x4E05700,
        220,
        [0x5966A30, 0x5963A10],
    ),
    (
        "consensus",
        "<Option<HorizonMapAndTail> as Encode>::encode<VecWriter>@0x4e057e0",
        "call_opt_hmt_vec",
        0x4E057E0,
        343,
        [0x51FF790, 0x5826DC0, 0x542D2C0, 0x5963A10],
    ),
    (
        "consensus",
        "<Option<Qc> as Encode>::encode<&mut SizeWriter>@0x4e05940",
        "call_opt_qc_refsize",
        0x4E05940,
        131,
        [0x5966770],
    ),
    (
        "consensus",
        "<Option<HorizonMapAndTail> as Encode>::encode<SizeWriter>@0x4e059d0",
        "call_opt_hmt_size",
        0x4E059D0,
        242,
        [0x5200190, 0x5826B20, 0x542D860],
    ),
    (
        "consensus",
        "<Option<HorizonState> as Encode>::encode<VecWriter>@0x4e05ad0",
        "call_opt_hs_vec",
        0x4E05AD0,
        317,
        [0x59CDF40, 0x51FF790, 0x5827E70, 0x5963A10],
    ),
    (
        "consensus",
        "<HorizonInner as Encode>::encode<VecWriter>@0x59cdf40",
        "call_hinner_vec",
        0x59CDF40,
        250,
        [0x4E057E0, 0x542D2C0, 0x5963A10],
    ),
]


def sha256_bytes(buf: bytes) -> str:
    return hashlib.sha256(buf).hexdigest()


def parse_elf_sections(data: bytes) -> dict[str, tuple[int, int, int]]:
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise ValueError("Expected little-endian ELF64")
    e_shoff = struct.unpack_from("<Q", data, 40)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)
    shs = [
        struct.unpack_from("<IIQQQQIIQQ", data, e_shoff + i * e_shentsize)
        for i in range(e_shnum)
    ]
    str_off = shs[e_shstrndx][4]
    out: dict[str, tuple[int, int, int]] = {}
    for sh in shs:
        end = data.index(b"\x00", str_off + sh[0])
        name = data[str_off + sh[0] : end].decode("utf-8", "replace")
        out[name] = (sh[3], sh[4], sh[5])
    return out


def parse_relocations(
    data: bytes, secs: dict[str, tuple[int, int, int]], rela_name: str
) -> list[dict[str, int]]:
    if rela_name not in secs:
        return []
    _, off, sz = secs[rela_name]
    out: list[dict[str, int]] = []
    for pos in range(off, off + sz, 24):
        r_offset, r_info, r_addend = struct.unpack_from("<QQq", data, pos)
        r_type = r_info & 0xFFFFFFFF
        width = 8 if r_type == 1 else 4
        out.append(
            {
                "offset": int(r_offset),
                "width": int(width),
                "type": int(r_type),
                "addend": int(r_addend),
            }
        )
    return out


def parse_symtab(data: bytes) -> list[str]:
    e_shoff = struct.unpack_from("<Q", data, 40)[0]
    e_shentsize, e_shnum = struct.unpack_from("<HH", data, 58)
    shs = [
        struct.unpack_from("<IIQQQQIIQQ", data, e_shoff + i * e_shentsize)
        for i in range(e_shnum)
    ]
    sym_sh = next(sh for sh in shs if sh[1] == 2)
    str_sh = shs[sym_sh[6]]
    names: list[str] = []
    for pos in range(sym_sh[4], sym_sh[4] + sym_sh[5], sym_sh[9]):
        st_name = struct.unpack_from("<I", data, pos)[0]
        end = data.index(b"\x00", str_sh[4] + st_name)
        names.append(data[str_sh[4] + st_name : end].decode("utf-8", "replace"))
    return names


def resolve_wrapper_encode_section(
    od: bytes,
    osecs: dict[str, tuple[int, int, int]],
    syms: list[str],
    wrapper_substr: str,
) -> str:
    wsecs = [n for n in osecs if n.startswith(".text.") and wrapper_substr in n]
    if len(wsecs) != 1:
        raise ValueError(f"Expected 1 wrapper section matching {wrapper_substr!r}, got {wsecs}")
    rname = ".rela" + wsecs[0]
    if rname not in osecs:
        raise ValueError(f"Missing relocation section {rname} for wrapper {wrapper_substr}")
    _, roff, rsz = osecs[rname]
    targets: list[str] = []
    for pos in range(roff, roff + rsz, 24):
        _, r_info, _ = struct.unpack_from("<QQq", od, pos)
        sname = syms[r_info >> 32]
        if "Encode" in sname:
            targets.append(".text." + sname)
    if len(targets) != 1:
        raise ValueError(f"Expected 1 Encode target in {wrapper_substr}, got {targets}")
    return targets[0]


def load_fde_index() -> dict[int, tuple[int, int]]:
    out: dict[int, tuple[int, int]] = {}
    for line in FDE_TSV_PATH.read_text(encoding="utf-8").splitlines()[1:]:
        parts = line.split("\t")
        s = int(parts[0], 0)
        e = int(parts[1], 0)
        sz = int(parts[2], 0)
        if e - s != sz:
            raise ValueError(f"Malformed FDE row: {line}")
        out[s] = (e, sz)
    return out


def check_call_anchors(
    fde_bytes: bytes,
    fde_va: int,
    relocs: list[dict[str, int]],
    expected_targets: list[int],
) -> None:
    if not expected_targets:
        return
    observed: set[int] = set()
    for r in relocs:
        off = r["offset"]
        if off >= 1 and off + 4 <= len(fde_bytes) and fde_bytes[off - 1] == 0xE8:
            disp = struct.unpack_from("<i", fde_bytes, off)[0]
            observed.add(fde_va + off + 4 + disp)
    missing = [hex(t) for t in expected_targets if t not in observed]
    if missing:
        raise ValueError(
            f"Missing .text call-target anchors {missing} in FDE {hex(fde_va)} "
            f"(observed: {[hex(x) for x in sorted(observed)]})"
        )


def _parse_int(v: object) -> int:
    return int(v, 0) if isinstance(v, str) else int(v)


def _extract_span(row: object) -> tuple[int, int] | None:
    if not isinstance(row, dict):
        return None
    sk = next((k for k in ("start_va", "start", "va", "addr") if k in row), None)
    if sk is None:
        return None
    s = _parse_int(row[sk])
    if "end_va" in row:
        e = _parse_int(row["end_va"])
    elif "end" in row:
        e = _parse_int(row["end"])
    elif "size_bytes" in row:
        e = s + _parse_int(row["size_bytes"])
    elif "size" in row:
        e = s + _parse_int(row["size"])
    else:
        return None
    if e <= s:
        return None
    return (s, e)


def check_disjointness(
    windows: list[tuple[int, int, str]],
    byte_windows_data: dict | None = None,
) -> None:
    # 1. Internal disjointness
    ordered = sorted(windows, key=lambda x: (x[0], x[1]))
    for i in range(len(ordered) - 1):
        s1, e1, l1 = ordered[i]
        s2, e2, l2 = ordered[i + 1]
        if s2 < e1:
            raise ValueError(
                f"Internal overlap: {l1} ({hex(s1)}..{hex(e1)}) vs {l2} ({hex(s2)}..{hex(e2)})"
            )

    # 2. research/byte-windows.json check (Wave-7+ consolidation-safe):
    #    - Forbid ANY overlap with dependency windows.
    #    - Forbid ANY partial overlap with first-party windows; allow ONLY exact (s, e) == (es, ee)
    #      if a later consolidation wave merges this exact packet into byte-windows.json.
    bw = (
        byte_windows_data
        if byte_windows_data is not None
        else json.loads(BYTE_WINDOWS_PATH.read_text(encoding="utf-8"))
    )
    for row in bw.get("windows", []):
        sp = _extract_span(row)
        if sp is None:
            continue
        es, ee = sp
        src_kind = row.get("source_kind", "")
        is_dep = src_kind == "dependency" or row.get("component") in (
            "native-libraries",
            "dependencies",
        )
        for s, e, lbl in ordered:
            if s < ee and es < e:
                if is_dep:
                    raise ValueError(
                        f"Overlap with dependency window {hex(es)}..{hex(ee)} for {lbl} ({hex(s)}..{hex(e)})"
                    )
                if (s, e) != (es, ee):
                    raise ValueError(
                        f"Partial overlap with byte-windows.json {hex(es)}..{hex(ee)} for {lbl} ({hex(s)}..{hex(e)})"
                    )

    # 3. Sibling compiled-byte match / census / thinlto / wave / identity / gate-closure packets:
    #    forbid ANY overlap against claimed windows/records/matched_fdes.
    for p in sorted(WORK_ITEMS_DIR.glob("*/*")):
        if p.name not in ("records.json", "census.json"):
            continue
        parent_name = p.parent.name
        if parent_name == HERE.name:
            continue
        if "consolidation" in parent_name:
            continue
        if not any(
            k in parent_name
            for k in ("byte-match", "census", "gate-closure", "thinlto", "wave", "identity")
        ):
            continue
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(doc, dict):
            continue
        for key in ("windows", "records", "matched_fdes"):
            items = doc.get(key)
            if not isinstance(items, list):
                continue
            for row in items:
                sp = _extract_span(row)
                if sp is None:
                    continue
                es, ee = sp
                for s, e, lbl in ordered:
                    if s < ee and es < e:
                        raise ValueError(
                            f"Overlap with sibling packet {parent_name} ({hex(es)}..{hex(ee)}) for {lbl} ({hex(s)}..{hex(e)})"
                        )


def compile_unit(
    tmp_dir: Path,
) -> tuple[str, bytes, dict[str, tuple[int, int, int]], list[str]]:
    ver = subprocess.check_output(["rustc", "+1.95.0", "--version"], text=True).strip()
    if "1.95.0" not in ver:
        raise RuntimeError(f"Expected rustc 1.95.0, got: {ver}")
    out_o = tmp_dir / "consensus_encode.o"
    cmd = ["rustc", "+1.95.0"] + RUSTC_FLAGS + ["-o", str(out_o), str(SRC_PATH)]
    subprocess.run(cmd, check=True)
    od = out_o.read_bytes()
    return ver, od, parse_elf_sections(od), parse_symtab(od)


def build_records() -> tuple[dict, list[tuple[bytes, bytes, list[dict[str, int]]]]]:
    sys.path.insert(0, str(REPO / "tools"))
    import byte_progress as bp

    bin_path = REPO / TARGET_REL
    bin_data = bin_path.read_bytes()
    if len(bin_data) != TARGET_SIZE:
        raise ValueError(f"Unexpected binary size: {len(bin_data)} != {TARGET_SIZE}")
    actual_sha = sha256_bytes(bin_data)
    if actual_sha != TARGET_SHA256:
        raise ValueError(f"Unexpected binary SHA-256: {actual_sha}")

    secs = parse_elf_sections(bin_data)
    t_va, t_off, _ = secs[".text"]
    fdes = load_fde_index()

    with tempfile.TemporaryDirectory() as td:
        rustc_ver, od, osecs, syms = compile_unit(Path(td))

    windows_out: list[dict] = []
    raw_pairs: list[tuple[bytes, bytes, list[dict[str, int]]]] = []
    span_list: list[tuple[int, int, str]] = []

    for comp, label, wsub, start_va, exp_sz, call_anchors in SPECS:
        if start_va not in fdes:
            raise ValueError(f"FDE start {hex(start_va)} not found in node-115-fde.tsv")
        end_va, fde_sz = fdes[start_va]
        if fde_sz != exp_sz:
            raise ValueError(f"FDE size mismatch for {label}: {fde_sz} != {exp_sz}")
        tgt_bytes = bin_data[
            t_off + (start_va - t_va) : t_off + (start_va - t_va) + fde_sz
        ]

        sname = resolve_wrapper_encode_section(od, osecs, syms, wsub)
        _, soff, ssz = osecs[sname]
        comp_bytes = od[soff : soff + ssz]
        relocs = parse_relocations(od, osecs, ".rela" + sname)
        if len(comp_bytes) != fde_sz:
            raise ValueError(
                f"Compiled size mismatch for {label}: {len(comp_bytes)} != {fde_sz}"
            )
        cmp_res = bp.compare(tgt_bytes, comp_bytes, relocs)
        if not cmp_res["relocation_qualified"] or cmp_res["non_relocation_difference_offsets"]:
            raise ValueError(f"Byte comparison failed for {label}: {cmp_res}")

        check_call_anchors(tgt_bytes, start_va, relocs, call_anchors)

        rel_offsets = sorted(
            {r["offset"] + k for r in relocs for k in range(r["width"])}
        )
        windows_out.append(
            {
                "component": comp,
                "label": label,
                "source_unit": "consensus_encode.rs",
                "wrapper_symbol": wsub,
                "compile_flags": RUSTC_FLAGS,
                "start_va": hex(start_va),
                "end_va": hex(end_va),
                "size": fde_sz,
                "target_sha256": sha256_bytes(tgt_bytes),
                "compiled_section": sname,
                "compiled_sha256": sha256_bytes(comp_bytes),
                "compiled_bytes_hex": comp_bytes.hex(),
                "relocations": relocs,
                "relocation_offsets": rel_offsets,
                "raw_equal_bytes": cmp_res["raw_equal_bytes"],
                "relocation_bytes": cmp_res["relocation_bytes"],
                "non_relocation_bytes": cmp_res["non_relocation_bytes"],
                "equal_non_relocation_bytes": cmp_res["equal_non_relocation_bytes"],
                "relocation_qualified": True,
                "call_target_anchors": [hex(t) for t in call_anchors],
            }
        )
        raw_pairs.append((tgt_bytes, comp_bytes, relocs))
        span_list.append((start_va, end_va, label))

    check_disjointness(span_list)

    rec = {
        "schema_version": 1,
        "work_item": HERE.name,
        "target_binary": {
            "path": TARGET_REL,
            "size": TARGET_SIZE,
            "sha256": TARGET_SHA256,
        },
        "rustc_version": rustc_ver,
        "source_files": {
            "consensus_encode.rs": sha256_bytes(SRC_PATH.read_bytes()),
        },
        "summary": {
            "windows": len(windows_out),
            "total_bytes": sum(w["size"] for w in windows_out),
            "raw_equal_bytes": sum(w["raw_equal_bytes"] for w in windows_out),
            "consensus_windows": len(windows_out),
            "consensus_bytes": sum(w["size"] for w in windows_out),
        },
        "windows": windows_out,
    }
    return rec, raw_pairs


def run_negative_controls(
    rec: dict, raw_pairs: list[tuple[bytes, bytes, list[dict[str, int]]]]
) -> int:
    sys.path.insert(0, str(REPO / "tools"))
    import byte_progress as bp

    rejected = 0

    # Control 1: flip 1 non-relocation byte -> must fail bp.compare
    tgt0, comp0, rel0 = raw_pairs[0]
    rel_set = {r["offset"] + k for r in rel0 for k in range(r["width"])}
    flip_idx = next(i for i in range(len(comp0)) if i not in rel_set)
    mut = bytearray(comp0)
    mut[flip_idx] ^= 0xFF
    res = bp.compare(tgt0, bytes(mut), rel0)
    if res["relocation_qualified"]:
        raise AssertionError("Negative control 1 failed: flipped byte still qualified")
    rejected += 1

    # Control 2: shifted FDE start_va + 1 -> must not match node-115-fde.tsv
    fdes = load_fde_index()
    if (int(rec["windows"][0]["start_va"], 16) + 1) in fdes:
        raise AssertionError("Negative control 2 failed: start_va+1 unexpectedly in FDE index")
    rejected += 1

    # Control 3: bogus .text call-target anchor -> must fail check_call_anchors
    s0 = int(rec["windows"][0]["start_va"], 16)
    try:
        check_call_anchors(tgt0, s0, rel0, [0x1419300])
    except ValueError:
        rejected += 1
    else:
        raise AssertionError("Negative control 3 failed: bogus call-target anchor accepted")

    # Control 4: synthetic overlap against dependency window -> must fail check_disjointness
    bw_mut = copy.deepcopy(json.loads(BYTE_WINDOWS_PATH.read_text(encoding="utf-8")))
    e0 = int(rec["windows"][0]["end_va"], 16)
    bw_mut["windows"].append(
        {
            "component": "dependencies",
            "source_kind": "dependency",
            "start": hex(s0),
            "end": hex(e0),
        }
    )
    try:
        check_disjointness([(s0, e0, "synthetic")], byte_windows_data=bw_mut)
    except ValueError:
        rejected += 1
    else:
        raise AssertionError("Negative control 4 failed: dependency overlap accepted")

    return rejected


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true", help="Write records.json")
    ap.add_argument("--self-test", action="store_true", help="Run adversarial negative controls")
    args = ap.parse_args()

    rec, raw_pairs = build_records()
    if args.write:
        RECORDS_PATH.write_text(json.dumps(rec, indent=2) + "\n", encoding="utf-8")
    else:
        pinned = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))
        if pinned != rec:
            raise ValueError("Live compiled records do not match pinned records.json")

    neg_msg = ""
    if args.self_test:
        n_rej = run_negative_controls(rec, raw_pairs)
        neg_msg = f", {n_rej}/4 negative controls rejected"

    s = rec["summary"]
    pct = 100.0 * s["raw_equal_bytes"] / s["total_bytes"]
    print(
        f"PASS: {s['windows']}/{s['windows']} relocation-qualified "
        f"(consensus {s['consensus_windows']}w/{s['consensus_bytes']} B; "
        f"total {s['total_bytes']} B, {s['raw_equal_bytes']}/{s['total_bytes']} = {pct:.2f}% raw-equal, "
        f"0 overlaps{neg_msg})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
